#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import os
import sys
import grpc
import json
import math

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections

# =========================
# CONFIGURATION CONSTANTS
# =========================

BINS = 8
ALPHA = 0.1  # Learning rate
GAMMA = 0.9  # Discount factor
DROP = 1
ALLOW = 0
QVALUE = 255
PKT_COUNT_BITS = 16
BYTE_COUNT_BITS = 32
K = 5
VICTIM = "10.0.2.21"
SERVICE_WEIGHTS = {   # (w_b, w_p) 
    53:  (0.6, 0.4),  # DNS
    123: (0.4, 0.6),  # NTP
}

AI_BIN_MIN = 0
AI_BIN_MAX = 20

BETA_L_BIN = 7            # 35-40
BETA_M_MINUS_BIN = 9      # 45-49
BETA_M_PLUS_BIN = 11      # 55-59
BETA_H_BIN = 13           # 65-69

SERVDEGR_THRESHOLD = 8
SERVDEGR_MAX = 10

# =========================
# RL TABLE GENERATORS
# =========================

def generate_amp_factor_cfg(n_bins: int):
    """
    Generate a list of (bin_in, bin_out, amp_factor) tuples
    where amp_factor = ceil(((bin_out - bin_in)/(n_bins - 1) + 1) * 10),
    producing integer values in [0, 20] for all combinations of bin_in
    and bin_out in [0, n_bins-1].
    """
    cfg = []
    scale = 1 / (n_bins - 1)
    for bin_in in range(n_bins):
        for bin_out in range(n_bins):
            delta = bin_in - bin_out
            normalized = delta * scale         # in [-1, +1]
            amp_factor = (normalized + 1) * 10  # in [0, 20]
            amp_factor_rounded = math.ceil(amp_factor)
            cfg.append((bin_in, bin_out, amp_factor_rounded))
    return cfg

def generate_ai_cfg(unique_af, w_b, w_p, k):
    """
    Returns list of (AF_b, AF_p, AI)
    AI = 50 * ( 1 + w_b*(AF_b/10 - 1) + w_p*(AF_p/10 - 1) )
    AI in [0,100]
    """
    ai_list = []
    for af_b in unique_af:
        for af_p in unique_af:
            norm_b = af_b / 10.0 - 1.0
            norm_p = af_p / 10.0 - 1.0
            ai = 50.0 * (1.0 + w_b * norm_b + w_p * norm_p)
            ai = math.ceil(ai)
            ai_list.append((af_b, af_p, ai))
    return ai_list


# =========================
# HELPER FUNCTIONS
# =========================

def make_default_entry(table, action_name):
    """
    Create a default-action entry for a given table.
    :param table: P4 table name
    :param action_name: P4 action to install as default
    :return: dict representing a default TableEntry
    """
    return {
        "table": table,
        "default_action": True,
        "action_name": action_name,
        "action_params": {}
    }

def make_lpm_entry(table, field, prefix, prefix_len, action_name, action_params):
    return {
        "table": table,
        "match": { field: [prefix, prefix_len] },
        "action_name": action_name,
        "action_params": action_params
    }

def make_exact_entries(table, field, values, action_name):
    """
    Create exact-match entries for a list of values.
    :param table: P4 table name
    :param field: header or metadata field to match on
    :param values: list of exact match values (int or str)
    :param action_name: action to invoke for each match
    :return: list of dicts, one per value
    """
    return [
        {
            "table": table,
            "match": { field: v },
            "action_name": action_name,
            "action_params": {}
        }
        for v in values
    ]

def make_range_entries(table, field, ranges, action_name, param_name, priority=None):
    """
    Create range-match entries.
    :param table: P4 table name
    :param field: header or metadata field to match on
    :param ranges: list of tuples (low, high, param_value)
    :param action_name: action to invoke
    :param param_name: name of the action parameter to set
    :param priority: optional priority for the entry
    :return: list of dicts, one per range
    """
    entries = []
    for low, high, param in ranges:
        entry = {
            "table": table,
            "match": { field: [low, high] },
            "action_name": action_name,
            "action_params": { param_name: param }
        }
        if priority is not None:
            entry["priority"] = priority
        entries.append(entry)
    return entries

# =========================
# BUILD ALL TABLE ENTRIES
# =========================

def build_all_entries():
    """
    Build the complete list of table entries programmatically.
    Modify this function to add or adjust any combinations.
    :return: list of entry dicts ready for loading
    """
    all_entries = []

    # 1) Ingress IPv4 LPM
    all_entries.append(make_default_entry(
        "MyIngress.ipv4_lpm",
        "MyIngress.drop"
    ))

    ipv4_routes = [
        ("10.0.1.11", 32, "08:00:00:00:01:11", 1),
        ("10.0.1.12", 32, "08:00:00:00:01:22", 2),
        ("10.0.1.13", 32, "08:00:00:00:01:33", 3),
        ("10.0.2.14", 32, "08:00:00:00:02:11", 4),
        ("10.0.2.21", 32, "08:00:00:00:02:22", 5),
        ("10.0.2.22", 32, "08:00:00:00:02:33", 6),
    ]

    for ip, plen, mac, port in ipv4_routes:
        all_entries.append(
            make_lpm_entry(
                table="MyIngress.ipv4_lpm",
                field="hdr.ipv4.dstAddr",
                prefix=ip,
                prefix_len=plen,
                action_name="MyIngress.ipv4_forward",
                action_params={
                    "dstAddr": mac,
                    "port": port
                }
            )
        )

    # 2) Packet direction: single exact LPM match
    all_entries.append({
        "table": "MyIngress.packet_direction",
        "match": { "hdr.ipv4.dstAddr": [VICTIM, 32] },
        "action_name": "MyIngress.get_flow_id_in",
        "action_params": {}
    })
    SERVERS_NET = "10.0.1.0"
    all_entries.append({
        "table": "MyIngress.packet_direction",
        "match": { "hdr.ipv4.dstAddr": [SERVERS_NET, 24] },
        "action_name": "MyIngress.get_flow_id_out",
        "action_params": {}
    })
    "MyIngress.get_flow_id_out"
    all_entries.append(make_default_entry(
        "MyIngress.packet_direction",
        "MyIngress.drop"
    ))

    # 3) Amplification service check: ports 53 and 123
    all_entries += make_exact_entries(
        table="MyIngress.check_amplification_service",
        field="meta.port_to_check",
        values=[53, 123],
        action_name="MyIngress.amplifiable_service"
    )
    all_entries.append(make_default_entry(
        "MyIngress.check_amplification_service",
        "MyIngress.not_amplifiable_service"
    ))

    # Egress – Binning
    # Packet count ranges per time window
    pkt_ranges = [
        (0, 9, 0),        # Bin 0
        (10, 20, 1),       # Bin 1
        (21, 40, 2),       # Bin 2
        (41, 80, 3),      # Bin 3
        (81, 160, 4),     # Bin 4
        (161, 320, 5),     # Bin 5
        (321, 640, 6),    # Bin 6
        (641, (pow(2,PKT_COUNT_BITS)-1), 7)  # Bin 7
    ]
    all_entries += make_range_entries(
        table="MyEgress.in_pkt_count_bin",
        field="meta.in_pkt_count",
        ranges=pkt_ranges,
        action_name="MyEgress.set_bin",
        param_name="bin",
        priority=1
    )
    all_entries += make_range_entries(
        table="MyEgress.out_pkt_count_bin",
        field="meta.out_pkt_count",
        ranges=pkt_ranges,
        action_name="MyEgress.set_bin",
        param_name="bin",
        priority=1
    )

    # Total byte ranges per time window
    byte_ranges = [
        (0, 512, 0),         # Bin 0
        (513, 1024, 1),      # Bin 1
        (1025, 2048, 2),      # Bin 2
        (2049, 4096, 3),      # Bin 3
        (4097, 8192, 4),     # Bin 4
        (8193, 16384, 5),    # Bin 5
        (16385, 32768, 6),    # Bin 6
        (32769, (pow(2,BYTE_COUNT_BITS)-1), 7)    # Bin 7
    ]
    all_entries += make_range_entries(
        table="MyEgress.in_byte_count_bin",
        field="meta.in_byte_count",
        ranges=byte_ranges,
        action_name="MyEgress.set_bin",
        param_name="bin",
        priority=1
    )
    all_entries += make_range_entries(
        table="MyEgress.out_byte_count_bin",
        field="meta.out_byte_count",
        ranges=byte_ranges,
        action_name="MyEgress.set_bin",
        param_name="bin",
        priority=1
    )

    # 6) Amplification factors (byte/packet)
    amp_factor_cfg = generate_amp_factor_cfg(8)

    for f2, f3, amp in amp_factor_cfg:
        all_entries.append({
            "table": "MyEgress.amplification_factor_byte",
            "match": { "meta.f2": f2, "meta.f3": f3 },
            "action_name": "MyEgress.set_amplification_factor_byte",
            "action_params": { "amp_byte": amp }
        })

    for f0, f1, amp in amp_factor_cfg:
        all_entries.append({
            "table": "MyEgress.amplification_factor_pkt",
            "match": { "meta.f0": f0, "meta.f1": f1 },
            "action_name": "MyEgress.set_amplification_factor_pkt",
            "action_params": { "amp_pkt": amp }
        })

    # Extract unique amp_byte values
    unique_amp_values = sorted({amp for _, _, amp in amp_factor_cfg})

    # 7) Asymmetry index
    for port, (w_b, w_p) in SERVICE_WEIGHTS.items():
        ai_cfg = generate_ai_cfg(unique_amp_values, w_b, w_p, K)

        for af_b, af_p, ai in ai_cfg:
            ai_bin = ai // 5  # bin of 5 units (0–20)

            all_entries.append({
                "table": "MyEgress.asymmetry_index",
                "match": {
                    "meta.amplification_factor_byte": af_b,
                    "meta.amplification_factor_pkt": af_p,
                    "meta.port_to_check": port
                },
                "action_name": "MyEgress.set_asymmetry_index",
                "action_params": {
                    "ai": ai,
                    "ai_bin": ai_bin
                }
            })

    # Extract unique AI values
    unique_ai_values = sorted({ai for _, _, ai in ai_cfg})

    # 5. Reward table generation
    #    Based on:
    #    - AI_{t-1} bin
    #    - AI_{t-2} bin
    #    - a_{t-1}
    #    - ServDegr_t
    rt_cfg = []

    for ai_prev in range(AI_BIN_MIN, AI_BIN_MAX + 1):
        for ai_prev2 in range(AI_BIN_MIN, AI_BIN_MAX + 1):
            for a_prev in (ALLOW, DROP):
                for serv_degr in range(0, SERVDEGR_MAX + 1):

                    # -----------------------------
                    # r_t^AI component
                    # -----------------------------
                    r_ai = 0

                    # BENIGN STATE
                    if (BETA_M_MINUS_BIN <= ai_prev < BETA_M_PLUS_BIN
                            and a_prev == ALLOW):

                        if ai_prev2 >= BETA_H_BIN:
                            r_ai = 0
                        else:
                            r_ai = 1

                    # OVERREACTION STATE
                    elif (ai_prev < BETA_L_BIN
                            and a_prev == DROP):

                        if ai_prev2 >= BETA_H_BIN:
                            r_ai = 0
                        else:
                            r_ai = -1

                    # UNDERREACTION STATE
                    elif (ai_prev >= BETA_H_BIN
                            and a_prev == ALLOW):

                        if ai_prev2 < BETA_M_PLUS_BIN:
                            r_ai = 0
                        else:
                            r_ai = -1

                    # -----------------------------
                    # Service degradation override
                    # -----------------------------
                    if serv_degr > SERVDEGR_THRESHOLD and r_ai != 1:
                        r_t = -1
                    elif serv_degr > SERVDEGR_THRESHOLD and r_ai == 1:
                        r_t = 0
                    else:
                        r_t = r_ai

                    reward_abs = abs(r_t)
                    negative = 1 if r_t < 0 else 0

                    rt_cfg.append((
                        ai_prev,
                        ai_prev2,
                        a_prev,
                        serv_degr,
                        reward_abs,
                        negative
                    ))

    # Install entries in P4 table
    for ai_prev, ai_prev2, a_prev, serv_degr, r_t, neg in rt_cfg:
        all_entries.append({
            "table": "MyEgress.reward",
            "match": {
                "meta.curr_asymmetry_index_bin":  ai_prev,
                "meta.curr_action":   a_prev,
                "meta.prev_asymmetry_index_bin":  ai_prev2,
                "meta.service_degradation":   serv_degr
            },
            "action_name": "MyEgress.set_reward",
            "action_params": {
                "reward": r_t,
                "negative": neg
            }
        })


    # 9) Discount table entries
    discounted_q_list = [
    (
        q_raw,
        math.ceil(abs((q_raw - 128)) * GAMMA),
        1 if (q_raw - 128) < 0 else 0
    )
    for q_raw in range(QVALUE + 1)
    ]

    for max_q, qv, neg in discounted_q_list:
        all_entries.append({
            "table": "MyEgress.discount_table",
            "match": { "max_next_q": max_q },
            "action_name": "MyEgress.applyDiscount",
            "action_params": { "q_value": qv, "negative": neg}
        })

    # 10) Learning rate table entries
    scaled_list = [(v, math.ceil(v * ALPHA)) for v in range(0, QVALUE + 1)]
    for td, qv in scaled_list:
        all_entries.append({
            "table": "MyEgress.learning_rate_table",
            "match": { "td_error_reg": td },
            "action_name": "MyEgress.applyLearningRate",
            "action_params": { "q_value": qv }
        })

    return all_entries

def load_and_write_table_entries(entries, p4info_helper, sw):
    """
    Load a list of entry-dicts into the switch.
    :param entries: list of TableEntry dicts (as built above)
    :param p4info_helper: initialized P4InfoHelper
    :param sw: Bmv2SwitchConnection instance
    """
    for entry in entries:
        table_name   = entry["table"]
        action_name  = entry["action_name"]
        action_params= entry.get("action_params", {})
        default_act  = entry.get("default_action", False)
        priority     = entry.get("priority", None)
        match_fields = {}

        # Convert JSON match spec to P4Runtime format
        for field, val in entry.get("match", {}).items():
            if isinstance(val, list) and isinstance(val[0], str):
                match_fields[field] = (val[0], val[1])
            elif isinstance(val, list) and all(isinstance(x, int) for x in val):
                match_fields[field] = (val[0], val[1])
            else:
                match_fields[field] = val

        # Build and write the TableEntry
        te = p4info_helper.buildTableEntry(
            table_name     = table_name,
            match_fields   = match_fields if match_fields else None,
            action_name    = action_name,
            action_params  = action_params,
            default_action = default_act,
            priority       = priority
        )
        sw.WriteTableEntry(te)

        # Log installation
        if default_act:
            print(f"[INFO] Installed DEFAULT action for {table_name}")
        else:
            if table_name == "MyEgress.asymmetry_index" or table_name == "MyEgress.reward":
                print(f"[INFO] Installed entry: {table_name} {match_fields} → {action_name}({action_params})")

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")

        # Build and load all entries
        entries = build_all_entries()
        load_and_write_table_entries(entries, p4info_helper, s1)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/proto.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/proto.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
