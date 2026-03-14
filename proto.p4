// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//---------------------------------------------------------------------------
// Constant definitions for EtherType, protocols, timing, and RL parameters
//---------------------------------------------------------------------------
const bit<16> TYPE_IPV4           = 0x800;          // IPv4 EtherType
const bit<8>  TYPE_UDP            = 17;             // UDP protocol number
const bit<8>  TYPE_TCP            = 6;              // TCP protocol number
const bit<48> time_window         = 10_000_000;     // seconds in microseconds
const bit<8>  EPSILON             = 26;             // ε-greedy threshold (~0.1)

// Flow hashing and direction constants
#define MAX_FLOWS                  4
#define PORT_TO_ATTACKER           6
#define INCOMING                   0   // Server -> Host
#define OUTGOING                   1   // Host -> Server

// Action identifiers for RL decisions
#define ALLOW                      0
#define DROP                       1
#define NOT_ACTIVE                 0
#define ACTIVE                     1

// Q-table sizing and bit indices
#define QTABLE_SIZE                131072           // 16 bits used for state index
#define RIGHT_IDX_Q2               8
#define LEFT_IDX_Q2                15
#define LEFT_IDX_Q1                7
#define SHIFT_OFFSET               8
#define QVALUE_BITS                16
#define QVALUE_BITS_PER_ACTION     8
#define PKT_COUNT_BITS             16
#define BYTE_COUNT_BITS            32
#define LAST_ACTIONS_TAKEN_BITS     2
#define TRAINING_WINDOWS           2500
#define SERVDEGR_MAX               10

const bit<QVALUE_BITS_PER_ACTION> Q_OFFSET = 128;     // offset for signed encoding
const int<QVALUE_BITS_PER_ACTION> Q_MIN = -128;
const bit<QVALUE_BITS_PER_ACTION> Q_MAX = 127;

//---------------------------------------------------------------------------
// Header type definitions
//---------------------------------------------------------------------------
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

//---------------------------------------------------------------------------
// Metadata structure for per-flow and RL state
//---------------------------------------------------------------------------
struct metadata {
    bit<32> flow_id;                  // Unique per-flow identifier
    bit<16> port_to_check;            // UDP port to inspect for amplification
    bit<1>  direction;                // INCOMING or OUTGOING
    bit<1>  is_amplifiable_service;   // Flag for known amplification services
    bit<PKT_COUNT_BITS> in_pkt_count;             // Packet count incoming
    bit<PKT_COUNT_BITS> out_pkt_count;            // Packet count outgoing
    bit<BYTE_COUNT_BITS> in_byte_count;            // Byte count incoming
    bit<BYTE_COUNT_BITS> out_byte_count;           // Byte count outgoing
    bit<3>  bin;                      // Discretized feature index
    bit<1>  agent_trigger;            // Flag to activate RL decision
    bit<3>  f0; 
    bit<3>  f1;                       // Binned features
    bit<3>  f2;                       // for RL-related computations
    bit<3>  f3;           
    bit<16> amplification_factor_byte;// Amplification factor (bytes)
    bit<16> amplification_factor_pkt; // Amplification factor (packets)
    bit<8>  asymmetry_index;          // Asymmetry index for RL reward
    int<8>  reward;                   // Temporal reward signal
    bit<1>  last_action_taken;        // Last RL action: ALLOW or DROP
    bit<4>  service_degradation;
    bit<1>  prev_action;
    bit<5>  prev_asymmetry_index_bin;
    bit<1>  curr_action;
    bit<5>  curr_asymmetry_index_bin;
};

struct headers {
    ethernet_t                  ethernet;
    ipv4_t                      ipv4;
    udp_t                       udp;
}


error { IPHeaderTooShort }

//---------------------------------------------------------------------------
// Parser: extract Ethernet, IPv4, UDP headers
//---------------------------------------------------------------------------

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept; 
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}

//---------------------------------------------------------------------------
// Checksum verification
//---------------------------------------------------------------------------

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


//---------------------------------------------------------------------------
// Ingress processing: routing, flow ID, amplification detection,
// windowing, counting, and triggering RL decision
//---------------------------------------------------------------------------

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    // Temporary variables
    bit<16> tmp16;
    bit<32> tmp32;
    bit<48> tmp48;
    bit<1>  tmp1;

    // Per-flow registers for packet/byte counting and timestamps
    register<bit<PKT_COUNT_BITS>>(MAX_FLOWS) in_pkt_count_reg;
    register<bit<PKT_COUNT_BITS>>(MAX_FLOWS) out_pkt_count_reg;
    register<bit<BYTE_COUNT_BITS>>(MAX_FLOWS) in_byte_count_reg;
    register<bit<BYTE_COUNT_BITS>>(MAX_FLOWS) out_byte_count_reg;
    register<bit<48>>(MAX_FLOWS) first_ts;  // Timestamp of first packet in window

    // Actions for routing and flow-ID computation

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action get_flow_id_in() {
        meta.direction = INCOMING;
        hash(meta.flow_id, HashAlgorithm.crc32, (bit<32>)0,
             {hdr.ipv4.srcAddr, hdr.ipv4.protocol, hdr.udp.srcPort},
             (bit<32>)MAX_FLOWS);
    }
    action get_flow_id_out() {
        meta.direction = OUTGOING;
        hash(meta.flow_id, HashAlgorithm.crc32, (bit<32>)0,
             {hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.udp.dstPort},
             (bit<32>)MAX_FLOWS);
    }

    action amplifiable_service() {
        meta.is_amplifiable_service = 1;
    }

    action not_amplifiable_service() {
        meta.is_amplifiable_service = 0;
    }

    // Single action to read all registers at index `idx`, populate the metadata,
    // then clear the registers back to 0.
    action read_and_clear(bit<32> idx) {
        in_pkt_count_reg.read(meta.in_pkt_count, idx);
        in_pkt_count_reg.write(idx, (bit<16>)0);

        out_pkt_count_reg.read(meta.out_pkt_count, idx);
        out_pkt_count_reg.write(idx, (bit<16>)0);

        in_byte_count_reg.read(meta.in_byte_count, idx);
        in_byte_count_reg.write(idx, (bit<32>)0);

        out_byte_count_reg.read(meta.out_byte_count, idx);
        out_byte_count_reg.write(idx, (bit<32>)0);
    }

    // Tables for LPM routing and flow-direction identification

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 10;
        default_action = drop();
    }

    table packet_direction {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            get_flow_id_in;
            get_flow_id_out;
            drop;
        }
        size = 4;
        default_action = drop();
    }

    table check_amplification_service {
        key = {
            meta.port_to_check: exact;
        }
        actions = {
            amplifiable_service;
            not_amplifiable_service;
        }
        size = 2;
        default_action = not_amplifiable_service();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            if (hdr.udp.isValid()) {
                // If packet comes from the attacker, avoid any processing and just forward
                if (standard_metadata.ingress_port != PORT_TO_ATTACKER) {
                    // Determine port to check based on packet direction
                    packet_direction.apply();

                    // If packet is incoming (from network ➔ our host), look at the UDP source port,
                    // because that tells us which fixed server port this response came from.
                    // If packet is outgoing (our host ➔ network), look at the UDP destination port,
                    // since our host’s source port can be an ephemeral/random port and not useful
                    // for identifying the service.
                    if (meta.direction == INCOMING) {
                        meta.port_to_check = hdr.udp.srcPort;
                    } else {
                        meta.port_to_check = hdr.udp.dstPort;
                    }

                    // Detect amplifiable service
                    check_amplification_service.apply();

                    if(meta.is_amplifiable_service == 1){
                        // Read the stored timestamp for this flow (first packet in the current window)
                        first_ts.read(tmp48, (bit<32>)meta.flow_id);

                        // If we already have a timestamp (i.e., not zero)…
                        if (tmp48 > 0) {
                            // If the elapsed time since the first packet exceeds the time window…
                            if (standard_metadata.ingress_global_timestamp - tmp48 > time_window) {
                                // Trigger read_and_clear to process the accumulated flow state
                                read_and_clear(meta.flow_id);
                                
                                // Start a new time window by recording this packet’s timestamp
                                first_ts.write((bit<32>)meta.flow_id,
                                            standard_metadata.ingress_global_timestamp);
                                
                                // Signal that the agent should select a new action for this flow
                                meta.agent_trigger = ACTIVE;
                            }
                        }
                        else{
                            // Otherwise (no timestamp yet), record the current packet’s timestamp
                            // as the first packet in this time window
                            first_ts.write((bit<32>)meta.flow_id, standard_metadata.ingress_global_timestamp);
                        }

                        // Update packet/byte counters per direction
                        if(meta.direction == INCOMING ){
                            in_pkt_count_reg.read(tmp16, (bit<32>)meta.flow_id);
                            tmp16 = tmp16 + 1;
                            in_pkt_count_reg.write((bit<32>)meta.flow_id, tmp16);
                            tmp16 = 0;

                            in_byte_count_reg.read(tmp32, (bit<32>)meta.flow_id);
                            tmp32 = tmp32 + standard_metadata.packet_length;
                            in_byte_count_reg.write((bit<32>)meta.flow_id, tmp32);
                            tmp32 = 0;
                        }
                        else{ // meta.direction == OUTGOING
                            out_pkt_count_reg.read(tmp16, (bit<32>)meta.flow_id);
                            tmp16 = tmp16 + 1;
                            out_pkt_count_reg.write((bit<32>)meta.flow_id, tmp16);
                            tmp16 = 0;

                            out_byte_count_reg.read(tmp32, (bit<32>)meta.flow_id);
                            tmp32 = tmp32 + standard_metadata.packet_length;
                            out_byte_count_reg.write((bit<32>)meta.flow_id, tmp32);
                            tmp32 = 0;
                        }
                    }
                }
            }
        }
    }
}

//---------------------------------------------------------------------------
// Egress Processing: RL Decision, Reward Computation, and Q-table Updates
//---------------------------------------------------------------------------

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    // Registers for Q-table and RL state
    register<bit<QVALUE_BITS>>(QTABLE_SIZE) qtable;                // Packed Q1/Q2 values
    register<bit<32>>(MAX_FLOWS)    prev_qvalue_idx_reg;                 // Last Q-table index per flow
    register<bit<LAST_ACTIONS_TAKEN_BITS>>(MAX_FLOWS)     last_actions_taken_reg;                // Last action taken per flow
    register<bit<8>>(1)             rand_byte_reg;                 // Random byte for ε-greedy
    register<bit<32>>(MAX_FLOWS)    time_windows_reg;
    register<bit<1>>(MAX_FLOWS)     action_to_take_reg;
    register<bit<4>>(MAX_FLOWS)     service_degradation_reg       
    register<bit<5>>(MAX_FLOWS)     prev_asymmetry_index_bin_reg;
 
    // Local variables
    bit<QVALUE_BITS>            q;       // Raw QVALUE_BITS-bit entry containing two QVALUE_BITS_PER_ACTION-bit Q-values
    bit<32>                    prev_qvalue_idx;     // Index into the Q-table
    bit<QVALUE_BITS_PER_ACTION> q1;         // Decoded QVALUE_BITS_PER_ACTION-bit Q-values
    bit<QVALUE_BITS_PER_ACTION> q2;
    bit<1>                      action_to_take; // Decision: ALLOW or DROP
    bit<8>                      rand_byte;      // Random number for exploration
    bit<1>                      is_negative;
    bit<32>                     time_windows;
    bit<LAST_ACTIONS_TAKEN_BITS> last_actions_taken;

    // max Q(s',a'): highest next-state Q-value over all actions
    bit<QVALUE_BITS_PER_ACTION> max_next_q;

    // γ · max Q(s',a'): discounted estimate of future reward
    int<QVALUE_BITS_PER_ACTION> discounted_q;

    // δ = R + γ·max Q(s',a') − Q(s,a): the temporal-difference error
    int<QVALUE_BITS_PER_ACTION> td_error_reg;

    // Q(s,a) ← Q(s,a) + α·δ: updated Q-value after applying the learning rate
    int<QVALUE_BITS_PER_ACTION> learned_q;

    action set_bin(bit<3> bin){
        meta.bin = bin;
    }

    action set_amplification_factor_byte(bit <16> amp_byte){
        meta.amplification_factor_byte = amp_byte;
    }

    action set_amplification_factor_pkt(bit <16> amp_pkt){
        meta.amplification_factor_pkt = amp_pkt;
    }

    action set_asymmetry_index(bit<8> ai, bit<5> ai_bin){
        meta.asymmetry_index = ai;
        meta.curr_asymmetry_index_bin = ai_bin;
    }

    action set_reward(int<8> reward, bit<1> negative){
        meta.reward = reward;
        is_negative = (negative == 1) ? 1w1 : 1w0;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action applyDiscount(int<QVALUE_BITS_PER_ACTION> q_value, bit<1> negative) {
        discounted_q = q_value;
        //is_negative = (negative == 1) ? 1w1 : 1w0;
        if(negative == (bit<1>)1){
            is_negative = (bit<1>)1;
        }
        else{
            is_negative = (bit<1>)0;
        }
    }

    action applyLearningRate(int<QVALUE_BITS_PER_ACTION> q_value) {
        learned_q = q_value;
    }

    table in_pkt_count_bin {
        key = {
            meta.in_pkt_count: range;
        }
        actions = {
            set_bin;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table out_pkt_count_bin {
        key = {
            meta.out_pkt_count: range;
        }
        actions = {
            set_bin;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table in_byte_count_bin {
        key = {
            meta.in_byte_count: range;
        }
        actions = {
            set_bin;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table out_byte_count_bin {
        key = {
            meta.out_byte_count: range;
        }
        actions = {
            set_bin;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table amplification_factor_byte {
        key = {
            meta.f2: exact;
            meta.f3: exact;
        }
        actions = {
            set_amplification_factor_byte;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table amplification_factor_pkt {
        key = {
            meta.f0: exact;
            meta.f1: exact;
        }
        actions = {
            set_amplification_factor_pkt;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table asymmetry_index {
        key = {
            meta.amplification_factor_byte: exact;
            meta.amplification_factor_pkt: exact;
            meta.port_to_check: exact;
        }
        actions = {
            set_asymmetry_index;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    //-------------------------------------------------------------------------------
    // Reward computation:
    // Looks up the reward δₜ based on (last_action_taken, traffic_asymmetry, service_degradation)
    // and writes it via set_reward().
    //-------------------------------------------------------------------------------
    table reward {
        key = {
            meta.curr_asymmetry_index_bin:  exact;  // AI_{t-1}
            meta.curr_action:   exact;              // a_{t-1}
            meta.prev_asymmetry_index_bin:  exact;  // AI_{t-2}
            meta.service_degradation:   exact;      // ServDegr_{t}
        }
        actions = {
            set_reward;   // write meta.reward = R(s,a)
            NoAction;     // leave reward unchanged if no match
        }
        size           = 32768;
        default_action = NoAction();
    }

    //-------------------------------------------------------------------------------
    // Discount lookup:
    // Maps raw max Q(s',a') → γ · max Q(s',a') to produce discounted_q.
    // Using a table offloads the multiply/divide into the match/action pipeline.
    //-------------------------------------------------------------------------------
    table discount_table {
        key = {
            max_next_q: exact;      // highest Q-value from the next state
        }
        actions = {
            applyDiscount;          // compute and write meta.discounted_q
            NoAction;               // leave discounted_q = 0 if no match
        }
        size           = 1024;
        default_action = NoAction();
    }

    //-------------------------------------------------------------------------------
    // Learning‐rate adaptation:
    // Chooses α based on the magnitude (or sign) of the TD error δ,
    // then writes the scaled update into learned_q.
    //-------------------------------------------------------------------------------
    table learning_rate_table {
        key = {
            td_error_reg: exact;     // the temporal‐difference error δ
        }
        actions = {
            applyLearningRate;       // compute and write meta.learned_q
            NoAction;                // no update if out of range
        }
        size           = 1024;
        default_action = NoAction();
    }

    apply { 
        // Read the current pseudo-random byte from the register.
        // This byte will later be used in the MyEgress block to implement ε-greedy behavior,
        // i.e., to probabilistically choose between exploitation (greedy action) and exploration (random action).
        rand_byte_reg.read(rand_byte, 0);

        // Update the pseudo-random byte by XOR-ing it with the lower 8 bits of the current packet's ingress timestamp.
        // This ensures that the value changes over time in a deterministic but varying way, 
        // providing entropy for decision-making in the absence of true randomness in P4.
        rand_byte = rand_byte ^ standard_metadata.ingress_global_timestamp[7:0];
        rand_byte_reg.write(0, rand_byte);

        if(meta.is_amplifiable_service == 1){
            action_to_take_reg.read(action_to_take, meta.flow_id);
        }

        // Only trigger RL decision when flagged by MyIngress
        if(meta.agent_trigger == ACTIVE){
            
            // Read the number of completed time windows for this flow
            time_windows_reg.read(time_windows, meta.flow_id);

            // Reset Service Degradation for test phase
            if (time_windows > TRAINING_WINDOWS){
                service_degradation_reg.write(meta.flow_id, (bit<4>)0);
            }

            // ────────────────────────────────────────
            // 1) Feature binning: discretize counts
            // ────────────────────────────────────────
            in_pkt_count_bin.apply();   // Bin incoming packet count → meta.bin
            meta.f0 = meta.bin;         // Save as feature f0

            out_pkt_count_bin.apply();  // Bin outgoing packet count
            meta.f1 = meta.bin;         // Save as f1

            in_byte_count_bin.apply();  // Bin incoming byte count
            meta.f2 = meta.bin;         // Save as f2

            out_byte_count_bin.apply(); // Bin outgoing byte count
            meta.f3 = meta.bin;         // Save as f3

            // ───────────────────────────────────────────────────
            // 2) Compute Q‐table index from (AI_{t-1}, a_{t-1}, AI_{t-2}, a_{t-2}, ServDegr_{t})
            // ───────────────────────────────────────────────────

            // Compute byte‐level amplification factor
            amplification_factor_byte.apply();

            // Compute packet‐level amplification factor
            amplification_factor_pkt.apply();

            // Compute asymmetry index (formula set via control plane)
            asymmetry_index.apply();    // AI_{t-1}

            // Retrieve the last actions taken for this flow
            last_actions_taken_reg.read(last_actions_taken, meta.flow_id);

            // a_{t-1} = MSB
            meta.curr_action = (bit<1>)(last_actions_taken >> (LAST_ACTIONS_TAKEN_BITS - 1));

            // a_{t-2} = LSB
            meta.prev_action = (bit<1>) last_actions_taken;

            // ServDegr_{t}
            service_degradation_reg.read(meta.service_degradation, meta.flow_id);

            // AI_{t-2}
            prev_asymmetry_index_bin_reg.read(meta.prev_asymmetry_index_bin, meta.flow_id);

            bit<32> idx;

            idx = (bit<32>)meta.prev_asymmetry_index_bin;
            idx = (idx << 1) | (bit<32>)meta.prev_action;
            idx = (idx << 5) | (bit<32>)meta.curr_asymmetry_index_bin;
            idx = (idx << 1) | (bit<32>)meta.curr_action;
            idx = (idx << 4) | (bit<32>)meta.service_degradation;

            // ────────────────────────────────────────
            // 3) Read packed Q‐values (two 8‐bit values) at index `idx`
            // ────────────────────────────────────────

            // Read the QVALUE_BITS-bit Q-table entry at index `idx`.
            // The lower Q_VALUES_BITS_PER_ACTION bits represent Q-value for action 1 (Q1),
            // and the upper Q_VALUES_BITS_PER_ACTION bits represent Q-value for action 2 (Q2).
            qtable.read(q, idx);

            // Unpack Q1 (ALLOW) and Q2 (DROP), using bit slices
            // Extract Q1 and Q2 from the QVALUE_BITS-bit packed value.
            // Q-values are stored using offset encoding to support negative values.
            q1 = q[LEFT_IDX_Q1:0];              // ALLOW
            q2 = q[LEFT_IDX_Q2:RIGHT_IDX_Q2];   // DROP

            // Lazy initialization:
            // If both Q1 and Q2 are zero, assume the entry has never been initialized.
            // We initialize both Q-values to Q_OFFSET, which encodes Q = 0 in offset logic.
            // This avoids having to prepopulate the table externally.
            if (q1 == 0 && q2 == 0) {
                bit<QVALUE_BITS> init_val = ((bit<QVALUE_BITS>)Q_OFFSET << SHIFT_OFFSET) | (bit<QVALUE_BITS>)Q_OFFSET;
                qtable.write(idx, init_val);
                q1 = (bit<QVALUE_BITS_PER_ACTION>)Q_OFFSET;
                q2 = (bit<QVALUE_BITS_PER_ACTION>)Q_OFFSET;
            }
            
            // ────────────────────────────────────────
            // 4) ε‐greedy action selection
            // ────────────────────────────────────────
            // time_windows < LAST_ACTIONS_TAKEN_BIT : My state is still partial: I don't have a full action history yet.
            // I perform pure exploration and store the chosen action and qvalue index.
            if (time_windows < TRAINING_WINDOWS && (rand_byte < EPSILON || time_windows < LAST_ACTIONS_TAKEN_BITS) ) {
                // Exploration: choose action by LSB of rand_byte (0=ALLOW,1=DROP)
                action_to_take = (bit<1>) rand_byte;
            } else {
                // Exploitation: pick max‐valued action
                action_to_take = (q2 > q1) ? (bit<1>)DROP : (bit<1>)ALLOW;
            }
            
            // Track maximum next‐state Q for TD‐error & reward tables
            max_next_q = (q2 > q1) ? q2 : q1;

            // At this point, the state is complete: the action history is full.
            // I can now safely access the Q-table and perform Q-value updates,
            // if the training is not over yet
            if(time_windows < TRAINING_WINDOWS && time_windows >= LAST_ACTIONS_TAKEN_BITS){

                // Lookup reward based on the last action and asymmetry index
                reward.apply();

                bit<2> reward_encoded;

                if (is_negative == 1) {
                    reward_encoded = 2;
                    meta.reward = -meta.reward;
                } else {
                    reward_encoded = (meta.reward == 1) ? (bit<2>)1 : 0;
                }

                is_negative = 0;

                // 𝑄(𝑠,𝑎) ← 𝑄(𝑠,𝑎)+ 𝛼 [ r_t + 𝛾 〖𝑚𝑎𝑥〗_(𝑎^′ )  𝑄(𝑠^′,𝑎^′ ) − 𝑄(𝑠,𝑎)]

                // Read index of previous Q‐value and the packed Q‐entry
                prev_qvalue_idx_reg.read(prev_qvalue_idx, meta.flow_id);
                bit<QVALUE_BITS> prev_q;
                qtable.read(prev_q, prev_qvalue_idx);

                // Extract the Q‐value for the action actually taken last time
                bit<QVALUE_BITS_PER_ACTION> prev_q_for_last_action;
                if (meta.last_action_taken == ALLOW) {
                    // If the last action was “ALLOW”, grab the low-order bits
                    prev_q_for_last_action = prev_q[LEFT_IDX_Q1:0];
                } else {
                    // If it was “DROP”, grab the high-order bits
                    prev_q_for_last_action = prev_q[LEFT_IDX_Q2:RIGHT_IDX_Q2];
                }

                // Lookup discounted next‐state value: γ * max Q(s',a')
                discount_table.apply();

                if(is_negative == 1){
                    discounted_q = -discounted_q;
                }
                is_negative = 0;

                int<QVALUE_BITS_PER_ACTION> real_prev_q_for_last_action = (int<QVALUE_BITS_PER_ACTION>)prev_q_for_last_action - (int<QVALUE_BITS_PER_ACTION>)Q_OFFSET;

                // Compute TD‐error δ = r_t + γ·max Q(s',a') − Q(s,a)
                int<QVALUE_BITS> temp = (int<QVALUE_BITS>)meta.reward + (int<QVALUE_BITS>)discounted_q - (int<QVALUE_BITS>)real_prev_q_for_last_action;

                if (temp < (int<QVALUE_BITS>)Q_MIN) {
                    td_error_reg = (int<QVALUE_BITS_PER_ACTION>)Q_MIN;
                } 
                else if(temp > (int<QVALUE_BITS>)Q_MAX){
                    td_error_reg = (int<QVALUE_BITS_PER_ACTION>)Q_MAX;
                } 
                else {
                    td_error_reg = (int<QVALUE_BITS_PER_ACTION>)temp;
                }

                is_negative = 0;
                if(td_error_reg < 0){
                    td_error_reg = -td_error_reg;
                    is_negative = 1;
                }
                
                // Lookup learning rate α * TD-error
                learning_rate_table.apply();

                // Split packed previous Q into per‐action values
                bit<QVALUE_BITS_PER_ACTION> prev_q1 = prev_q[LEFT_IDX_Q1:0];
                bit<QVALUE_BITS_PER_ACTION> prev_q2 = prev_q[LEFT_IDX_Q2:RIGHT_IDX_Q2];

                // Update only the Q‐value corresponding to the last action taken
                if (meta.last_action_taken == ALLOW) {
                    if(is_negative == 1){  
                        // Intermediate step to have real_prev_q_for_last_action on bit<16>, then cast is to int<16>
                        bit<QVALUE_BITS> tmp3 = (bit<QVALUE_BITS>)prev_q_for_last_action;
                        temp = (int<QVALUE_BITS>)tmp3 - (int<QVALUE_BITS>)learned_q;

                        if (temp < 0) {
                                prev_q1 = (bit<QVALUE_BITS_PER_ACTION>)0;
                        } 
                        else if(temp > (int<QVALUE_BITS>)Q_OFFSET + (int<QVALUE_BITS>)Q_MAX){
                                prev_q1 = (bit<QVALUE_BITS_PER_ACTION>)Q_OFFSET + (bit<QVALUE_BITS_PER_ACTION>)Q_MAX;
                        } 
                        else {
                            // No overflow -> just save the difference
                            int<QVALUE_BITS_PER_ACTION> tmp2 = (int<QVALUE_BITS_PER_ACTION>)temp;
                            prev_q1 = (bit<QVALUE_BITS_PER_ACTION>)tmp2;
                        } 
                    }
                    else{
                        bit<QVALUE_BITS> tmp3 = (bit<QVALUE_BITS>)prev_q_for_last_action;
                        temp = (int<QVALUE_BITS>)tmp3 + (int<QVALUE_BITS>)learned_q;

                        if (temp < 0) {
                                prev_q1 = (bit<QVALUE_BITS_PER_ACTION>)0;
                        } 
                        else if(temp > (int<QVALUE_BITS>)Q_OFFSET + (int<QVALUE_BITS>)Q_MAX){
                                prev_q1 = (bit<QVALUE_BITS_PER_ACTION>)Q_OFFSET + (bit<QVALUE_BITS_PER_ACTION>)Q_MAX;
                        } 
                        else {
                            // No overflow
                            int<QVALUE_BITS_PER_ACTION> tmp2 = (int<QVALUE_BITS_PER_ACTION>)temp;
                            prev_q1 = (bit<QVALUE_BITS_PER_ACTION>)tmp2;
                        }
                    } 
                }    
                else {
                    if(is_negative == 1){  
                        // Intermediate step to have real_prev_q_for_last_action on bit<16>, then cast is to int<16>
                        bit<QVALUE_BITS> tmp3 = (bit<QVALUE_BITS>)prev_q_for_last_action;
                        temp = (int<QVALUE_BITS>)tmp3 - (int<QVALUE_BITS>)learned_q;

                        if (temp < 0) {
                                prev_q2 = (bit<QVALUE_BITS_PER_ACTION>)0;
                        } 
                        else if(temp > (int<QVALUE_BITS>)Q_OFFSET + (int<QVALUE_BITS>)Q_MAX){
                                prev_q2 = (bit<QVALUE_BITS_PER_ACTION>)Q_OFFSET + (bit<QVALUE_BITS_PER_ACTION>)Q_MAX;
                        } 
                        else {
                            // No overflow -> just save the difference
                            int<QVALUE_BITS_PER_ACTION> tmp2 = (int<QVALUE_BITS_PER_ACTION>)temp;
                            prev_q2 = (bit<QVALUE_BITS_PER_ACTION>)tmp2;
                        } 
                    }
                    else{
                        bit<QVALUE_BITS> tmp3 = (bit<QVALUE_BITS>)prev_q_for_last_action;
                        temp = (int<QVALUE_BITS>)tmp3 + (int<QVALUE_BITS>)learned_q;

                        if (temp < 0) {
                                prev_q2 = (bit<QVALUE_BITS_PER_ACTION>)0;
                        } 
                        else if(temp > (int<QVALUE_BITS>)Q_OFFSET + (int<QVALUE_BITS>)Q_MAX){
                                prev_q2 = (bit<QVALUE_BITS_PER_ACTION>)Q_OFFSET + (bit<QVALUE_BITS_PER_ACTION>)Q_MAX;
                        } 
                        else {
                            // No overflow
                            int<QVALUE_BITS_PER_ACTION> tmp2 = (int<QVALUE_BITS_PER_ACTION>)temp;
                            prev_q2 = (bit<QVALUE_BITS_PER_ACTION>)tmp2;
                        }
                    }
                }

                // Pack updated Q1/Q2 back and write to Q‐table
                prev_q = ((bit<QVALUE_BITS>)prev_q2 << SHIFT_OFFSET) | (bit<QVALUE_BITS>)prev_q1;
                qtable.write(prev_qvalue_idx, prev_q);
            }

            // Increase counter used to check if learning time is over
            time_windows = time_windows + 1;
            time_windows_reg.write(meta.flow_id, time_windows);
            
            // Record last action & Q‐index for next iteration
            prev_qvalue_idx_reg.write(meta.flow_id, idx);

            // Read old history
            bit<LAST_ACTIONS_TAKEN_BITS> old = last_actions_taken;

            // Shift right by one position to drop the oldest bit
            bit<LAST_ACTIONS_TAKEN_BITS> shifted = old >> 1;

            // Position the new action at the MSB:
            //    - First extend action_to_take to the full width
            //    - Then shift left by (N-1) to land in the MSB slot
            bit<LAST_ACTIONS_TAKEN_BITS> insert =  (bit<LAST_ACTIONS_TAKEN_BITS>)(action_to_take) << (LAST_ACTIONS_TAKEN_BITS - 1);

            // Combine shifted history and insert via bitwise OR
            last_actions_taken = shifted | insert;

            // Save the updated action history to the register
            last_actions_taken_reg.write(meta.flow_id, last_actions_taken);

            // Save the current asymmetry index to the register
            prev_asymmetry_index_bin_reg.write(meta.flow_id, meta.curr_asymmetry_index_bin);

            // Update Service Degradation accordingly to the action chosen
            if(action_to_take == DROP){
                if(meta.service_degradation < SERVDEGR_MAX){
                    meta.service_degradation = meta.service_degradation + 1 ;
                }
                service_degradation_reg.write(meta.flow_id, meta.service_degradation);
            }
            else{
                if(meta.service_degradation > 0){
                    meta.service_degradation = meta.service_degradation - 1 ;
                }
                service_degradation_reg.write(meta.flow_id, meta.service_degradation);
            }

            action_to_take_reg.write(meta.flow_id, action_to_take);
        }

        // If this is an amplifiable service and action=DROP, then drop packet
        if(meta.is_amplifiable_service & action_to_take == DROP ){
            drop();
        }
        // else (action_to_take == ALLOW ) we let the packet exit the pipeline...
    }
}    

//---------------------------------------------------------------------------
// Checksum computation for deparser
//---------------------------------------------------------------------------
control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

//---------------------------------------------------------------------------
// Deparser: emit headers
//---------------------------------------------------------------------------
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
    }
}

//---------------------------------------------------------------------------
// Top-level switch instantiation
//---------------------------------------------------------------------------
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
