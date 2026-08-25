# NetKnife 🔪

![Python](https://img.shields.io/badge/Python-2.x-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)
![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)
![Status](https://img.shields.io/badge/Status-Legacy-orange.svg)
![Security Research](https://img.shields.io/badge/Purpose-Security%20Research-red.svg)

> **A Python-based network security and intrusion-testing toolkit created to explore networking, packet manipulation, wireless security, reconnaissance, and defensive security concepts.**

NetKnife is a **legacy cybersecurity research project** built around Python, Scapy, raw networking concepts, and Linux.

The project was originally developed as a hands-on experiment to understand how networks operate at a lower level by **building networking and security capabilities rather than simply using existing tools**.

---

## 📖 Table of Contents

* [About](#-about)
* [Project History](#-project-history)
* [Features](#-features)
* [Toolset](#-toolset)
* [Architecture](#-architecture)
* [Technical Concepts](#-technical-concepts)
* [Technology Stack](#-technology-stack)
* [Requirements](#-requirements)
* [Installation](#-installation)
* [Usage](#-usage)
* [Project Structure](#-project-structure)
* [Legacy Status](#️-legacy-status)
* [Educational Purpose](#-educational-purpose)
* [Responsible Use](#-responsible-use)
* [Project Philosophy](#-project-philosophy)
* [From NetKnife to Cybersecurity Engineering](#-from-netknife-to-cybersecurity-engineering)
* [Author](#-author)
* [License](#-license)

---

# 📖 About

**NetKnife** is a network security and intrusion-testing toolkit originally developed as one of my early cybersecurity projects.

The project focuses on practical experimentation with:

* Network discovery
* ARP
* Packet capture
* Packet crafting
* Network reconnaissance
* Wireless networking
* Layer 2 security
* Traffic manipulation
* Denial-of-Service research
* Attack detection

The goal was not to create a production-ready penetration-testing framework.

Instead, NetKnife was built as a **learning laboratory for networking and cybersecurity**.

---

# 🕰️ Project History

NetKnife was developed during the early stages of my journey into cybersecurity.

At that time, the objective was simple:

> **Understand how networks actually work by implementing the concepts myself.**

Rather than relying exclusively on established security tools, the project explored networking concepts directly through code.

This included working with:

* Ethernet frames
* ARP
* TCP/IP
* Network interfaces
* MAC addresses
* Packet crafting
* Packet sniffing
* Wireless networking
* VLAN concepts
* Network reconnaissance
* Attack detection

The code is intentionally preserved as a representation of that learning process.

> **From experimenting with packets and ARP as a teenager to working professionally with SOC, SIEM, threat hunting, and security engineering — NetKnife represents one of the early steps of that journey.**

---

# ⚡ Features

NetKnife contains experimental capabilities across several areas of network security.

## 🔎 Network Discovery

* Live host discovery
* IP address discovery
* MAC address discovery
* ARP-based host discovery
* TCP port scanning
* Wireless device discovery
* Access Point detection

## 🌐 Network Analysis

* Network packet capture
* Interface-based traffic monitoring
* Packet inspection using Scapy
* IP/MAC analysis
* Network interface information
* Basic traffic observation

## 🛡️ Layer 2 Security Research

* ARP spoofing
* ARP cache poisoning
* MAC flooding
* VLAN double-tagging concepts
* Suspicious ARP activity detection

## 📡 Wireless Security Research

* Access Point detection
* Fake Access Point experimentation
* Hidden SSID discovery
* Wireless device discovery
* Wi-Fi deauthentication testing

## 💥 Traffic & DoS Research

The project also contains experimental implementations related to traffic-generation and denial-of-service concepts, including:

* TCP SYN flooding
* HTTP GET flooding

These capabilities are intended for **controlled laboratory environments only**.

## 🕵️ Defensive Capabilities

NetKnife is not exclusively offensive.

It also includes experimental defensive functionality such as:

* ARP spoofing detection
* ARP cache poisoning detection
* Suspicious ARP response identification

## 🔐 Utilities

Additional utilities include:

* Hash generation
* Network interface information
* MAC address retrieval
* Public IP rotation through Tor
* Miscellaneous networking helpers

---

# 🧰 Toolset

| Category           | Component                | Description                                   |
| ------------------ | ------------------------ | --------------------------------------------- |
| Network Discovery  | Live IP & Device Scanner | Discovers active hosts and MAC addresses      |
| Network Discovery  | TCP Port Scanner         | Performs TCP-based port discovery             |
| Network Discovery  | Wi-Fi/AP Detection       | Identifies wireless devices and Access Points |
| Network Analysis   | Packet Capture           | Captures traffic from a network interface     |
| Network Analysis   | Packet Inspection        | Inspects packets using Scapy                  |
| Layer 2 Security   | ARP Poisoning            | Demonstrates ARP cache manipulation           |
| Layer 2 Security   | MAC Flooder              | Demonstrates CAM/MAC table flooding concepts  |
| Layer 2 Security   | VLAN Hopping             | Demonstrates double-tagging concepts          |
| Wireless Security  | Fake AP                  | Creates a test wireless Access Point          |
| Wireless Security  | Hidden SSID Locator      | Attempts to identify hidden wireless networks |
| Wireless Security  | Wi-Fi Deauthentication   | Demonstrates wireless deauthentication        |
| DoS Research       | SYN Flooder              | Demonstrates TCP SYN flooding                 |
| DoS Research       | HTTP Flooder             | Demonstrates HTTP GET flooding                |
| Defensive Security | ARP Detector             | Detects suspicious ARP behavior               |
| Utility            | Hash Creator             | Generates hashes from plaintext               |
| Utility            | IP Changer               | Rotates public IP through Tor                 |

---

# 🏗️ Architecture

Conceptually, NetKnife can be divided into several functional areas:

```text
                              NetKnife
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
         Discovery             Analysis            Security
              │                   │                   │
       ┌──────┼──────┐      ┌─────┼─────┐      ┌─────┼────────┐
       │      │      │      │     │     │      │     │        │
      ARP    TCP    Wi-Fi  Capture Monitor  ARP   MAC      VLAN
    Scanner Scanner Devices         │      Poison Flooding Hopping
       │                            │
       └──────────────┐             │
                      │             │
                      ▼             ▼
                Packet / Network Analysis
                              │
                              ▼
                    Wireless Security
                              │
                    ┌─────────┼─────────┐
                    │         │         │
                  Fake AP  Hidden SSID  Deauth
                              │
                              ▼
                    Defensive Security
                              │
                     ┌────────┴────────┐
                     │                 │
                ARP Detection     Traffic Analysis
```

---

# 🧠 Technical Concepts

NetKnife was primarily a **hands-on networking laboratory**.

## ARP

The project explores how Address Resolution Protocol works and how manipulating ARP traffic can influence communication between network hosts.

Understanding ARP was particularly important because it provides a practical introduction to:

* IP-to-MAC resolution
* Broadcast communication
* ARP caches
* Man-in-the-middle concepts
* ARP spoofing detection

---

## Packet Crafting

NetKnife uses **Scapy** to construct and transmit custom network packets.

This provides an opportunity to work directly with protocols instead of treating networking as a black box.

Concepts include:

* Ethernet frames
* ARP packets
* IP packets
* TCP packets
* HTTP traffic
* Wireless frames

---

## Packet Capture

The project experiments with capturing packets directly from network interfaces.

This introduces concepts such as:

* Packet headers
* Source/destination addresses
* Protocol identification
* Interface-level traffic
* Packet inspection

---

## Network Discovery

Discovery functionality explores how hosts and services can be identified inside a network.

Examples include:

* Active host discovery
* MAC address discovery
* ARP-based discovery
* TCP port discovery
* Wireless device discovery

---

## Wireless Security

Wireless functionality explores concepts surrounding:

* Access Points
* SSIDs
* Hidden networks
* Wireless devices
* Management frames
* Deauthentication

---

## Layer 2 Security

NetKnife explores several Layer 2 concepts:

* ARP spoofing
* ARP poisoning
* MAC flooding
* CAM table behavior
* VLAN tagging
* VLAN hopping

These experiments provide a practical introduction to the security implications of Layer 2 networking.

---

## Denial-of-Service Research

The project contains experimental implementations for studying:

* TCP SYN flooding
* HTTP GET flooding

The purpose is to understand how abnormal traffic patterns can affect network services and how such behavior can potentially be detected.

---

## Attack Detection

NetKnife also includes basic defensive mechanisms.

One example is detecting suspicious ARP activity by observing unexpected relationships between:

* IP addresses
* MAC addresses
* ARP responses

This creates a bridge between offensive experimentation and defensive monitoring.

---

# 🛠️ Technology Stack

NetKnife was primarily built using:

| Technology       | Purpose                           |
| ---------------- | --------------------------------- |
| Python 2         | Core implementation               |
| Scapy            | Packet crafting and analysis      |
| nmap-python      | Network scanning                  |
| Socket           | Network communication             |
| hashlib          | Hash generation                   |
| getmac           | MAC address handling              |
| Tkinter          | GUI components                    |
| Linux networking | Interface and network interaction |

---

# 📋 Requirements

NetKnife was developed for an older Linux/Python environment.

### Original environment

```text
Python 2.x
pip2
Scapy
nmap-python
Linux
```

Some dependencies used by the original project are now deprecated, unavailable, or incompatible with current distributions.

Therefore, **the repository should not be expected to run out-of-the-box on modern systems**.

---

# 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/AmirHoseinTangsiriNET/NetKnife.git
cd NetKnife
```

The original project was designed around Python 2:

```bash
python NetKnife.py
```

Depending on the selected functionality, additional privileges and system dependencies may be required.

> ⚠️ **Important:** The original code targets Python 2 and is not expected to work correctly on a modern Python 3 environment without modification.

---

# ▶️ Usage

NetKnife contains multiple experimental components rather than a single modern command-line interface.

Typical workflow:

```text
Network Interface
       │
       ▼
Discovery
       │
       ├── Host Discovery
       ├── ARP Discovery
       ├── Port Scanning
       └── Wireless Discovery
       │
       ▼
Network Analysis
       │
       ├── Packet Capture
       └── Packet Inspection
       │
       ▼
Security Research
       │
       ├── ARP Security
       ├── Layer 2 Research
       ├── Wireless Research
       └── Traffic Research
       │
       ▼
Detection
       │
       └── Suspicious ARP Activity
```

Because the project is legacy software, individual scripts may require manual configuration depending on the Linux distribution, network interface, and installed dependencies.

---

# 📁 Project Structure

The original repository contains multiple scripts and experimental components rather than a modern modular framework.

A conceptual representation is:

```text
NetKnife/
│
├── Network Discovery
│   ├── Host Discovery
│   ├── ARP Scanner
│   ├── Port Scanner
│   └── Wireless Discovery
│
├── Network Analysis
│   ├── Packet Capture
│   └── Packet Inspection
│
├── Layer 2 Security
│   ├── ARP Spoofing
│   ├── ARP Poisoning
│   ├── MAC Flooding
│   └── VLAN Hopping
│
├── Wireless Security
│   ├── Fake AP
│   ├── Hidden SSID
│   └── Deauthentication
│
├── Traffic Research
│   ├── SYN Flood
│   └── HTTP Flood
│
├── Defensive Security
│   └── ARP Detection
│
└── Utilities
    ├── Hashing
    ├── MAC Information
    └── Network Utilities
```

The exact implementation structure may differ because the repository represents the original state of the project.

---

# ⚠️ Legacy Status

## This project is intentionally preserved as legacy software.

NetKnife is **not actively maintained** and should not be considered a modern penetration-testing framework.

The repository contains:

* Python 2 code
* Deprecated dependencies
* Legacy APIs
* Experimental implementations
* Components that may not work on modern Linux distributions
* Code created primarily for educational experimentation

The project is preserved because its historical and educational value is more important than maintaining compatibility with modern environments.

---

# 🎓 Educational Purpose

NetKnife was created to answer practical questions about computer networks.

Instead of only asking:

> "What does ARP spoofing do?"

the project attempted to answer:

> "How does ARP spoofing actually work at the packet level?"

The same approach was applied to other networking concepts.

```text
Networking
    │
    ├── Ethernet
    ├── ARP
    ├── IP
    ├── TCP
    ├── HTTP
    └── 802.11
    │
    ▼
Packet Manipulation
    │
    ▼
Security Testing
    │
    ▼
Detection & Analysis
```

This methodology helped turn theoretical networking concepts into practical engineering knowledge.

---

# 🔐 Responsible Use

NetKnife contains functionality capable of:

* Generating network traffic
* Crafting packets
* Manipulating network protocols
* Performing network reconnaissance
* Testing wireless behavior
* Demonstrating security vulnerabilities

**Use this project only in environments where you have explicit authorization to perform security testing.**

Do not use NetKnife against:

* Networks you do not own
* Systems you do not administer
* Wireless networks without permission
* Third-party infrastructure
* Public services
* Production environments without authorization

The author is not responsible for damage or misuse resulting from this software.

---

# 🧪 Recommended Lab Environment

For educational experimentation, use an isolated laboratory.

For example:

```text
                    Isolated Lab Network

                ┌──────────────────────┐
                │   Virtual Network    │
                └──────────┬───────────┘
                           │
             ┌─────────────┼─────────────┐
             │             │             │
             ▼             ▼             ▼
        ┌────────┐   ┌──────────┐   ┌──────────┐
        │NetKnife│   │ Test Host│   │ Test VM  │
        │  VM    │   │          │   │          │
        └────────┘   └──────────┘   └──────────┘
```

A controlled environment makes it possible to study network behavior without affecting systems belonging to other users.

---

# 💡 Project Philosophy

The most important lesson behind NetKnife was simple:

> **Understand the technology by building things yourself.**

Security tools are powerful, but using a tool is not the same as understanding the underlying technology.

Building even a small packet scanner, ARP monitor, or packet-crafting script forces you to understand:

* Protocols
* Headers
* Network addressing
* Interfaces
* Packets
* State
* Communication
* Failure modes
* Detection opportunities

That knowledge becomes valuable far beyond the original tool.

---

# 🧭 From NetKnife to Cybersecurity Engineering

NetKnife represents an early stage of my cybersecurity journey.

The project started with questions such as:

```text
How does ARP actually work?
How are packets constructed?
How can devices be discovered?
How does a network react to abnormal traffic?
How do wireless networks behave?
How can an attack be detected?
```

Those questions eventually led toward deeper areas of cybersecurity:

```text
Networking
    ↓
Offensive Security
    ↓
Security Monitoring
    ↓
SOC & Incident Response
    ↓
Threat Hunting
    ↓
SIEM Engineering
    ↓
Security Architecture
```

NetKnife is therefore preserved **not because it is a modern framework**, but because it documents where the journey started.

---

# 📈 What Could Be Improved Today?

If NetKnife were redesigned today, several areas would benefit from modernization:

* Python 3 support
* Modern Scapy APIs
* Modular architecture
* CLI framework
* Configuration management
* Structured logging
* Unit testing
* Better error handling
* Modern dependency management
* IPv6 support
* Improved packet analysis
* Detection-oriented capabilities
* MITRE ATT&CK mapping
* SIEM integration
* PCAP export and analysis
* Modern wireless tooling

However, these improvements are intentionally **outside the scope of the preserved legacy version**.

The purpose of this repository is to document the original project rather than rewrite its history.

---

# 📚 Learning Areas

NetKnife provides hands-on exposure to several cybersecurity domains:

| Domain             | Concepts                      |
| ------------------ | ----------------------------- |
| Networking         | Ethernet, IP, TCP, ARP        |
| Network Security   | Spoofing, poisoning, flooding |
| Wireless Security  | APs, SSIDs, management frames |
| Reconnaissance     | Host and port discovery       |
| Packet Analysis    | Capture and inspection        |
| Layer 2 Security   | CAM, VLAN, ARP                |
| Defensive Security | ARP anomaly detection         |
| Linux              | Interfaces and networking     |
| Python             | Network programming           |
| Security Research  | Controlled experimentation    |

---

# ⭐ Why This Repository Is Preserved

Most early projects eventually disappear.

This one remains because it represents an important part of my technical development.

NetKnife was never intended to be a commercial security product.

It was a hands-on experiment created to understand how networking and offensive-security concepts work at a lower level.

Looking back at the project today, some of the code is outdated and some implementations are incomplete.

That is intentional.

The repository is a **snapshot of the learning process**.

> **The code may be old. The curiosity isn't.**

---

# 👨‍💻 Author

**AmirHossein Tangsiri Nezhad**

Cybersecurity Engineer / Security Researcher

GitHub:

https://github.com/AmirHoseinTangsiriNET

---

# 📄 License

NetKnife is licensed under the **Apache License 2.0**.

See the [`LICENSE`](LICENSE) file for the full license text.

---

# ⭐ Final Note

> **NetKnife is a legacy project, but it is also a snapshot of the curiosity that started everything.**

Built with:

**Python · Scapy · Linux · Packets · Curiosity**

The project started by asking how networks work.

The journey continued into security monitoring, threat hunting, incident response, SIEM engineering, and security architecture.

And the original lesson still stands:

> **Learn the protocol.
> Understand the packet.
> Build the tool. 🔪**
