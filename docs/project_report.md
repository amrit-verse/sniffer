# Internship Project Report: Basic Network Sniffer

**Project Title:** BasicNetworkSniffer  
**Author:** Amritesh Mishra  
**Degree:** Bachelor of Engineering (Computer Science Engineering)  
**Role:** Cyber Security Intern  
**Date:** June 2026

---

## 1. Introduction
During my Cyber Security Internship, my task was to build a network packet sniffer from scratch. The goal was to understand how data moves across a network and how security tools intercept and interpret that data. This report outlines how I built a Python-based sniffer using the Scapy library to monitor and log network traffic.

## 2. Objectives
- Capture live network traffic on my local machine.
- Parse IP headers, TCP/UDP segments, and ICMP messages to find the Source IP, Destination IP, and Protocol.
- Display the captured data in an easy-to-read table format in the terminal.
- Save the captures to a CSV file for review and a PCAP file so the traffic can be opened in Wireshark.
- Ensure the script handles errors safely without crashing abruptly.

## 3. Tools Used
- **Language:** Python 3.12
- **Library:** Scapy (v2.5.0) - Used to interact with network sockets and parse packet layers.
- **Library:** Rich (v13.0+) - Used to make the command-line interface look clean and color-coded.
- **Environment:** Kali Linux / Debian 13 (Using `venv` for dependency management).

## 4. Methodology & Implementation Details

### 4.1 Packet Capture Loop
The core of the tool relies on the `scapy.all.sniff()` function. I used a callback function `process_packet` that gets triggered every time a packet is captured. I also added support for BPF (Berkeley Packet Filter) syntax so users can type `--protocol TCP` and have the operating system filter the packets before they even reach Python, which improves performance.

### 4.2 Payload Extraction
Extracting the payload was an interesting challenge. Not all packets contain readable text. If I tried to force `decode('utf-8')` on binary data, the script would crash. To fix this, I set up a try-except block that first tries to decode the data as ASCII, ignoring errors, and stripping out unprintable characters. If that fails completely, it falls back to displaying a hex preview.

### 4.3 Data Export
To make sure data is saved even if the user stops the script midway, I set the CSV writer to append mode (`a`). For saving to Wireshark's format, I used `scapy.PcapWriter(append=True, sync=True)`, which writes raw packets to the hard drive immediately rather than keeping thousands of packets in the computer's RAM.

## 5. Challenges Faced
1. **Linux Virtual Environments:** Recent versions of Debian and Kali Linux block global `pip install` commands (PEP 668) to protect system packages. I had to learn how to properly set up Python virtual environments (`venv`) and rewrite my setup instructions so that the script would work out-of-the-box for other users.
2. **Permission Issues:** Sniffing packets requires root access, which meant running the script with `sudo`. Since `sudo` changes the execution environment, I had to figure out how to point `sudo` to the Python executable inside my virtual environment (`sudo venv/bin/python`).

## 6. Results
The tool successfully captures and logs network traffic. It accurately identifies protocols, maps IP addresses, and handles bad data without crashing. 

*(Please refer to the `screenshots/` directory in the repository to see the terminal UI in action).*

## 7. Future Improvements
- **DNS Parsing:** Right now, the tool shows IPs but not hostnames. I would like to add a feature to inspect port 53 traffic to extract DNS queries.
- **Security Alerts:** It would be interesting to add basic rules to detect excessive failed connection attempts (like an Nmap scan) and print a warning to the console.

## 8. Conclusion
Building this network sniffer was a great learning experience. It helped me bridge the gap between theoretical OSI model concepts I learned in my Computer Science Engineering degree and practical cybersecurity applications. Understanding how packets are structured gives me a much better perspective on how network defense mechanisms operate.
