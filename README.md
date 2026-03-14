# In-switch RL DDoS Defense

Prototype implementation of an **in-switch reinforcement learning system for mitigating amplification-based Distributed Denial of Service (DDoS) attacks** in programmable networks.

This project was developed during my Master's thesis research and led to the acceptance of the paper **“Adaptive Mitigation of Amplification-Based DDoS Attacks in Programmable Data Planes”** at **SecSoft 2026**.

**Author**  
Simone Sampognaro  
Polytechnic of Turin

**Supervisors**

- Prof. Riccardo Sisto — Polytechnic of Turin  
- Prof. Fulvio Valenza — Polytechnic of Turin  
- Prof. Paola Grosso — University of Amsterdam  
- Dr. Marios Avgeris — University of Amsterdam  
- Dr. Anestis Dalgkitsis — University of Amsterdam

The system demonstrates how **reinforcement learning can be embedded directly in the programmable data plane** to enable adaptive mitigation decisions at line rate.

---

# Overview

Amplification-based DDoS attacks exploit protocol asymmetries in services such as **DNS and NTP** to generate large traffic volumes toward a victim.

Traditional defenses often rely on:

- static filtering rules  
- control-plane analysis  
- offline machine learning models  

These approaches struggle to react quickly to dynamic attack patterns.

This project explores a different approach:

**performing reinforcement learning directly inside the programmable data plane.**

The programmable switch observes traffic patterns and learns mitigation policies online without external training.

---

# System Architecture

The experimental setup emulates an amplification attack scenario composed of:

- Attacker
- Victim
- Amplification Server
- Programmable Switch (P4)

The switch implements the RL agent that decides whether to:

- **ALLOW** traffic  
- **DROP** traffic  

based on observed traffic asymmetry.

```
Attacker ──► Amplifier Server ──► Victim
        │
        └────────► Programmable Switch (RL mitigation)
```

The learning process is performed **entirely inside the data plane**.

---

# Repository Structure

```
.
├── proto.p4        # P4 implementation of the RL mitigation system
├── controller.py   # Controller used to populate switch tables
├── attacker.py     # Amplification attack traffic generator
├── victim.py       # Legitimate victim traffic generator
├── server.py       # Amplification server emulator (DNS/NTP)
├── Makefile        # Builds and runs the P4 program in the BMv2 environment
└── README.md
```

---

# Traffic Generation

The repository includes Python scripts that generate realistic traffic patterns using **Scapy**.

## Attacker

`attacker.py` generates amplification attack traffic.

Features:

- window-based attack model
- cyclic attack phases
- burst attacks
- silent periods

Attack packets are marked using the IP **TOS field** to emulate reflection attacks.

Supported protocols:

- DNS amplification
- NTP amplification

Example:

```bash
python3 attacker.py dns
```

or

```bash
python3 attacker.py ntp
```

---

## Victim

`victim.py` generates legitimate traffic toward the amplification servers.

Traffic follows a **state-based model** with three intensity levels:

- LOW
- MEDIUM
- HIGH

Example:

```bash
python3 victim.py dns
```

or

```bash
python3 victim.py ntp
```

---

## Amplification Server

`server.py` emulates vulnerable amplification services.

Supported protocols:

### DNS

Responses are generated according to empirical DNS distributions with different query types and payload sizes.

### NTP

NTP responses simulate amplification behavior similar to historical **monlist attacks**.

The server distinguishes between:

- **normal requests**
- **attack traffic**

and generates amplified responses accordingly.

---

# Reinforcement Learning in the Data Plane

The programmable switch implements a **Q-learning agent** that learns mitigation policies online.

### State Representation

The state includes:

- previous asymmetry index
- current asymmetry index
- previous action
- current action
- service degradation level

### Actions

The agent chooses between:

- **ALLOW**
- **DROP**

### Learning Algorithm

A **tabular Q-learning algorithm** is implemented directly in the P4 data plane.

Policy selection follows an **ε-greedy strategy**:

- exploration with probability ε
- exploitation otherwise

The Q-table is stored inside switch registers.

---

# Building the P4 Program

The project is designed to run inside the **P4 tutorials / BMv2 environment**.

Compile and start the topology using:

```bash
make
```

This command:

- compiles the P4 program
- launches the BMv2 software switch
- starts the Mininet topology

---

# Switch Configuration

After the switch is running, the forwarding tables must be populated using the controller.

Run:

```bash
python3 controller.py
```

The controller configures the programmable switch by:

- installing forwarding rules
- initializing the RL state tables
- populating the required match-action tables

---

# Running the Experiment

Typical execution order:

### 1. Start the P4 switch

```bash
make
```

---

### 2. Populate switch tables

```bash
python3 controller.py
```

---

### 3. Start the amplification server

```bash
python3 server.py
```

---

### 4. Start legitimate victim traffic

```bash
python3 victim.py dns
```

---

### 5. Launch the attack

```bash
python3 attacker.py dns
```

---

# Experimental Setup

Experiments simulate amplification attacks against a victim using:

- DNS amplification
- NTP amplification

Traffic is generated in **time windows**.

Two phases are used:

| Phase | Windows |
|------|--------|
| Training | 2500 |
| Testing | 500 |

The RL agent learns mitigation policies during training and is evaluated during testing.

---

# Requirements

Python packages:

```
scapy
```

Install with:

```bash
pip install scapy
```

The system is intended to run inside the **P4 tutorial virtual machine**.

---

# License

This project is released for academic and research purposes.