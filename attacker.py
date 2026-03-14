#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Reason-GPL: import-scapy

import sys
import time
import random

from scapy.all import (
    Ether,
    IP,
    UDP,
    sendp,
    get_if_list,
    get_if_hwaddr,
)

# ===================== CONFIG =====================

WINDOW_DURATION = 10

TRAIN_WINDOWS = 2500
TEST_WINDOWS = 500
TOTAL_WINDOWS = TRAIN_WINDOWS + TEST_WINDOWS

TOS_ATTACK = 0x80

DNS_SERVERS = "10.0.1.11"
NTP_SERVERS = "10.0.1.12"

DNS_PORT = 53
NTP_PORT = 123

STATES = {
    "SILENT": {
        "packets": 0,
        "duration": (2, 4)
    },
    "LOW": {
        "packets": 10,
        "duration": (1, 2)
    },
    "MEDIUM": {
        "packets": 30,
        "duration": (3, 5)
    },
    "HIGH": {
        "packets": 75,
        "duration": (3, 6)
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
            src=ATTACKER_MAC,
            dst="ff:ff:ff:ff:ff:ff"
        )
        / IP(
            src=VICTIM_IP,
            dst=dst_ip,
            tos=TOS_ATTACK
        )
        / UDP(sport=12345, dport=dport)
        / payload
    )


# ================= RANDOM PROFILE (UNCHANGED) =================
def generate_window_profile(num_windows, seed):
    """
    Profile with two attack types:
    - CYCLIC (ramp-up / ramp-down)
    - BURST (sudden HIGH or MEDIUM)
    Alternated with short SILENT phases.
    """

    rng = random.Random(seed)
    windows = []

    while len(windows) < num_windows:

        # =============
        # SILENT PHASE
        # =============
        silent_duration = rng.randint(3, 5)
        for _ in range(silent_duration):
            if len(windows) >= num_windows:
                break
            windows.append(("SILENT", STATES["SILENT"]["packets"]))

        if len(windows) >= num_windows:
            break

        # ----------------------------
        # Choose attack type
        # ----------------------------
        attack_type = rng.choices(
            ["CYCLIC", "BURST"],
            weights=[0.6, 0.4]
        )[0]

        # ==============
        # CYCLIC ATTACK
        # ==============
        if attack_type == "CYCLIC":

            # ramp up
            ramp_up = ["LOW", "MEDIUM"]
            for state in ramp_up:
                duration = rng.randint(1, 2)
                for _ in range(duration):
                    if len(windows) >= num_windows:
                        break
                    windows.append((state, STATES[state]["packets"]))

            # high plateau
            plateau_duration = rng.randint(3, 4)
            for _ in range(plateau_duration):
                if len(windows) >= num_windows:
                    break
                windows.append(("HIGH", STATES["HIGH"]["packets"]))

            # ramp down
            ramp_down = ["MEDIUM", "LOW"]
            for state in ramp_down:
                duration = rng.randint(1, 2)
                for _ in range(duration):
                    if len(windows) >= num_windows:
                        break
                    windows.append((state, STATES[state]["packets"]))

        # ==============
        # BURST ATTACK
        # ==============
        else:
            burst_state = rng.choices(
                ["MEDIUM", "HIGH"],
                weights=[0.3, 0.7]
            )[0]

            burst_duration = rng.randint(4, 6)

            for _ in range(burst_duration):
                if len(windows) >= num_windows:
                    break
                windows.append((burst_state, STATES[burst_state]["packets"]))

    return windows[:num_windows]

# ================= MAIN =================

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("dns", "ntp"):
        print("Usage: ./send_attack.py [dns|ntp]")
        sys.exit(1)

    mode = sys.argv[1]
    global VICTIM_IP, ATTACKER_MAC

    iface = get_if()
    ATTACKER_MAC = get_if_hwaddr(iface)
    VICTIM_IP = "10.0.2.21"
    payload = b"\x00" * 20

    # Server selection
    if mode in ("dns"):
        server = DNS_SERVERS
        dport = DNS_PORT
    elif mode in ("ntp"):
        server = NTP_SERVERS
        dport = NTP_PORT

    print(f"[+] Mode: {mode.upper()}")
    print(f"[+] Interface: {iface}")
    print(f"[+] Interface MAC address: {ATTACKER_MAC}")
    print(f"[+] Interface IP address:  {VICTIM_IP}")
    print(f"[+] Window size: {WINDOW_DURATION}s\n")


    print("[+] Generating TRAIN windows with seed 16")
    train_profile = generate_window_profile(TRAIN_WINDOWS, seed=16)

    print("[+] Generating TEST windows with seed 42")
    test_profile = generate_window_profile(TEST_WINDOWS, seed=42)

    window_profile = train_profile + test_profile

    print("[+] Traffic profile:")
    for i, (state, packets) in enumerate(window_profile):
        print(f"    Window {i:02d}: {state} | {packets} packets")
    print()

    # ================= TRAFFIC GENERATION =================

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
                pkt = build_packet(iface, server, dport, payload)
                sendp(pkt, verbose=False)
                time.sleep(interval)

        elapsed_since_window = time.time() - window_start
        remaining = max(0, WINDOW_DURATION - elapsed_since_window + 2)
        time.sleep(remaining)

    print("\n[+] Traffic generation finished")


if __name__ == "__main__":
    main()
