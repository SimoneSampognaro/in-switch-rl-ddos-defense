#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import Ether, IP, UDP
import random
import math

# -------------------------
# Configuration
# -------------------------

VICTIM_IP = "10.0.2.21"
DNS_PORT = 53
NTP_PORT = 123

# MTU handling
ETH_MTU = 1500
IP_HEADER_SIZE = 20
UDP_HEADER_SIZE = 8
MAX_UDP_PAYLOAD = ETH_MTU - IP_HEADER_SIZE - UDP_HEADER_SIZE  # 1472 bytes

# TOS value used to mark attack packets
TOS_ATTACK = 0x80

# -------------------------
# DNS NORMAL distribution (IMC 2019)
# Probabilities + average DNS payload sizes [bytes]
# -------------------------

DNS_NORMAL_DIST = [
    ("A",     0.64, 121),
    ("AAAA",  0.22, 114),
    ("PTR",   0.064, 129),
    ("TXT",   0.014, 118),
    ("MX",    0.012, 113),
    ("SRV",   0.011, 137),
    ("CNAME", 0.010, 131),
    ("SOA",   0.005, 128),
]

def sample_dns_payload():
    r = random.random()
    cumulative = 0.0
    for qtype, prob, size in DNS_NORMAL_DIST:
        cumulative += prob
        if r <= cumulative:
            return qtype, size
    return DNS_NORMAL_DIST[-1][0], DNS_NORMAL_DIST[-1][2]

# -------------------------
# BAF distributions (NDSS 2014 inspired)
# -------------------------

DNS_BAF_DIST = [
    (28.7, 0.6),
    (41.2, 0.3),
    (64.1, 0.1),
]

# NTP PAF distribution (NDSS 2014 inspired)
NTP_PAF_DIST = [
    (2, 0.6),
    (3, 0.3),
    (5, 0.1),
]

# NTP constants
NTP_MONLIST_RESPONSE_PAYLOAD = 440

def sample_baf(dist):
    r = random.random()
    cumulative = 0.0
    for baf, prob in dist:
        cumulative += prob
        if r <= cumulative:
            return baf
    return dist[-1][0]

# -------------------------
# Classification helpers
# -------------------------

def is_attack(pkt):
    return pkt[IP].tos == TOS_ATTACK

def get_protocol(pkt):
    dport = pkt[UDP].dport
    if dport == DNS_PORT:
        return "DNS"
    elif dport == NTP_PORT:
        return "NTP"
    else:
        return None

# -------------------------
# Handlers
# -------------------------

def get_if():
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def handle_normal(pkt, proto):
    print(f"[NORMAL] {proto} packet received")

    # -------------------------
    # DNS NORMAL behavior
    # -------------------------
    if proto == "DNS":
        qtype, payload_size = sample_dns_payload()
        payload = b"D" * payload_size

        print(
            f"  -> DNS normal response: "
            f"QTYPE={qtype}, payload_size={payload_size} bytes"
        )

    # -------------------------
    # NTP NORMAL behavior
    # -------------------------
    elif proto == "NTP":
        req_len = len(bytes(pkt[UDP].payload))
        print(f"NTP={req_len})")
        payload = b"B" * req_len
    else:
        payload = b"OK"

    response = (
        Ether(src=SERVER_MAC, dst='ff:ff:ff:ff:ff:ff') /
        IP(src=SERVER_IP, dst=VICTIM_IP) /
        UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
        payload
    )

    sendp(Ether(bytes(response)), verbose=False)

def handle_attack(pkt, proto):
    print(f"[ATTACK] {proto} amplification behavior")

    # -------------------------
    # DNS amplification
    # -------------------------
    if proto == "DNS":
        req_len = max(len(bytes(pkt[UDP].payload)), 1)

        baf = sample_baf(DNS_BAF_DIST)
        baf_rounded = int(round(baf))

        total_resp_len = min(int(round(req_len * baf)), 65000)
        num_packets = math.ceil(total_resp_len / MAX_UDP_PAYLOAD)

        print(
            f"  -> DNS BAF={baf:.1f} (rounded={baf_rounded}), "
            f"request_size={req_len}, "
            f"total_response_size={total_resp_len} bytes, "
            f"packets_sent={num_packets}"
        )

        remaining = total_resp_len

        for _ in range(num_packets):
            chunk_size = min(remaining, MAX_UDP_PAYLOAD)
            remaining -= chunk_size

            payload = b"A" * chunk_size

            response = (
                Ether(src=SERVER_MAC, dst='ff:ff:ff:ff:ff:ff') /
                IP(src=SERVER_IP, dst=VICTIM_IP) /
                UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                payload
            )

            sendp(Ether(bytes(response)), verbose=False)

    # -------------------------
    # NTP amplification
    # -------------------------
    elif proto == "NTP":
        # Sample Packet Amplification Factor (PAF)
        paf = sample_baf(NTP_PAF_DIST)

        num_packets = int(round(paf))  # PAF = number of packets

        payload_size = NTP_MONLIST_RESPONSE_PAYLOAD
        payload = b"A" * payload_size

        print(
            f"  -> NTP PAF={paf}, "
            f"packets_sent={num_packets}, "
            f"payload_size={payload_size} bytes"
        )

        payload = b"A" * NTP_MONLIST_RESPONSE_PAYLOAD

        for _ in range(num_packets):
            response = (
                Ether(src=SERVER_MAC, dst='ff:ff:ff:ff:ff:ff') /
                IP(src=SERVER_IP, dst=VICTIM_IP) /
                UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                payload
            )

            sendp(Ether(bytes(response)), verbose=False)

# -------------------------
# Packet processing
# -------------------------

def process_request(pkt):
    global packet_counter
    if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
        return
    packet_counter += 1

    print(f"\n[RECEIVED PACKET #{packet_counter}]")
    print(pkt.summary())

    proto = get_protocol(pkt)
    if proto is None:
        return

    if is_attack(pkt):
        handle_attack(pkt, proto)
    else:
        handle_normal(pkt, proto)

def main():
    global SERVER_IP, SERVER_MAC
    global packet_counter

    packet_counter = 0

    iface = get_if()
    SERVER_MAC = get_if_hwaddr(iface)
    SERVER_IP = get_if_addr(iface)

    print(f"[INFO] Listening on interface: {iface}")
    print(f"[INFO] Interface MAC address: {SERVER_MAC}")
    print(f"[INFO] Interface IP address:  {SERVER_IP}")

    sniff(
        filter=f"udp and not icmp and src host {VICTIM_IP} and (dst port 53 or dst port 123)",
        prn=process_request,
        store=False
    )

if __name__ == '__main__':
    main()