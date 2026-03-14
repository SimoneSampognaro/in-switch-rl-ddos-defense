#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Reason-GPL: import-scapy

import sys
import time
import random
from itertools import cycle

from scapy.all import (
    Ether,
    IP,
    UDP,
    sendp,
    get_if_list,
    get_if_hwaddr,
    get_if_addr
)

# ===================== CONFIG =====================

WINDOW_DURATION = 10

TRAIN_WINDOWS = 2500
TEST_WINDOWS = 500
TOTAL_WINDOWS = TRAIN_WINDOWS + TEST_WINDOWS

DNS_SERVERS = "10.0.1.11"
NTP_SERVERS = "10.0.1.12"

DNS_PORT = 53
NTP_PORT = 123

# -------- State-based traffic model --------
STATES = {
    "LOW": {
        "packets": 10,
        "duration": (2, 3),
        "weight": 0.3,
    },
    "MEDIUM": {
        "packets": 30,
        "duration": (2, 6),
        "weight": 0.4,
    },
    "HIGH": {
        "packets": 50,
        "duration": (2, 4),
        "weight": 0.3,
    },
}

# ==================================================

def get_if():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    print("Cannot find eth0 interface")
    sys.exit(1)


def build_packet(iface, dst_ip, dport, payload):
    return (
        Ether(
            src=VICTIM_MAC,
            dst="ff:ff:ff:ff:ff:ff"
        )
        / IP(src=VICTIM_IP, dst=dst_ip)
        / UDP(sport=12345, dport=dport)
        / payload
    )


# -------------------------
# RANDOM PROFILE (original)
# -------------------------
def generate_window_profile(num_windows, seed):
    rng = random.Random(seed)

    windows = []
    states = list(STATES.keys())
    weights = [STATES[s]["weight"] for s in states]

    while len(windows) < num_windows:
        state = rng.choices(states, weights=weights)[0]
        packets = STATES[state]["packets"]
        dmin, dmax = STATES[state]["duration"]
        duration = rng.randint(dmin, dmax)

        windows.extend([(state, packets)] * duration)

    return windows[:num_windows]

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("dns", "ntp"):
        print("Usage: ./send_victim.py [dns|ntp]")
        sys.exit(1)

    mode = sys.argv[1]
    global VICTIM_IP, VICTIM_MAC

    iface = get_if()
    VICTIM_MAC = get_if_hwaddr(iface)
    VICTIM_IP  = get_if_addr(iface)

    if mode in ("dns"):
        server = DNS_SERVERS
        dport = DNS_PORT

        def generate_payload():
            return b"\x00" * 100

    elif mode in ("ntp"):
        server = NTP_SERVERS
        dport = NTP_PORT

        def generate_payload():
            return b"\x00" * 48

    print(f"[+] Mode: {mode.upper()}")
    print(f"[+] Interface: {iface}")
    print(f"[+] Interface MAC address: {VICTIM_MAC}")
    print(f"[+] Interface IP address:  {VICTIM_IP}")
    print(f"[+] Window size: {WINDOW_DURATION}s\n")

    print("[+] Generating TRAIN windows with seed 16")
    train_profile = generate_window_profile(TRAIN_WINDOWS, seed=16)

    print("[+] Generating TEST windows with seed 42")
    test_profile = generate_window_profile(TEST_WINDOWS, seed=42)

    window_profile = train_profile + test_profile

    print("[+] Traffic profile (packets per window):")
    for i, p in enumerate(window_profile):
        print(f"    Window {i:02d}: {p}")
    print()

    for window_idx, (state, packets_to_send) in enumerate(window_profile):

        print(
            f"[+] Window {window_idx:02d} | "
            f"{state} | sending {packets_to_send} packets"
        )

        window_start = time.time()

        if packets_to_send > 0:

            ACTIVE_PHASE = WINDOW_DURATION / 2
            interval = ACTIVE_PHASE / packets_to_send

            for _ in range(packets_to_send):

                payload = generate_payload()
                pkt = build_packet(iface, server, dport, payload)
                sendp(pkt, verbose=False)

                time.sleep(interval)

        elapsed_since_window = time.time() - window_start
        remaining = max(0, WINDOW_DURATION - elapsed_since_window + 2)
        time.sleep(remaining)

    print("\n[+] Traffic generation finished")

if __name__ == "__main__":
    main()
