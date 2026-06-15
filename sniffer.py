#!/usr/bin/env python3
"""
CodeAlpha Basic Network Sniffer

A network packet sniffer built with Python and Scapy.
Captures live network traffic, extracts packet metadata,
logs output to CSV and PCAP formats, and displays real-time 
traffic in the terminal using the Rich library.

Author: Amritesh Mishra
Project: CodeAlpha Cyber Security Internship Project
"""

import argparse
import csv
import logging
import os
import sys
import time
from datetime import datetime
from collections import defaultdict

# Terminal styling
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

# Network manipulation
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Raw

# Initialize terminal console
console = Console()

class NetworkSniffer:
    """
    Core class for capturing, parsing, and logging network packets.
    """

    def __init__(self, interface=None, protocol_filter=None, output_dir="captures", pcap_export=False):
        self.interface = interface
        self.protocol_filter = protocol_filter.upper() if protocol_filter else None
        self.output_dir = output_dir
        self.pcap_export = pcap_export
        
        self.output_csv = os.path.join(self.output_dir, "captures.csv")
        self.log_file = os.path.join(self.output_dir, "sniffer.log")
        self.output_pcap = os.path.join(self.output_dir, "captures.pcap") if pcap_export else None

        # Basic statistics tracking
        self.packet_count = 0
        self.protocol_counts = defaultdict(int)
        self.start_time = None
        
        self._setup_directories()
        self._setup_logging()
        self._initialize_csv()
        
        self.pcap_writer = None
        if self.pcap_export:
            # PcapWriter allows us to append packets one by one
            self.pcap_writer = scapy.PcapWriter(self.output_pcap, append=True, sync=True)

    def _setup_directories(self):
        """Creates required directories for the project structure."""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            os.makedirs("screenshots", exist_ok=True)
            os.makedirs("docs", exist_ok=True)
        except Exception as e:
            console.print(f"[bold red][!] Error creating directories: {e}[/bold red]")
            sys.exit(1)

    def _setup_logging(self):
        """Configures logging to write events to a file."""
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - [%(levelname)s] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        logging.info("Network Sniffer initialized.")

    def _initialize_csv(self):
        """Creates the CSV file and writes headers if it does not exist."""
        try:
            file_exists = os.path.isfile(self.output_csv)
            with open(self.output_csv, mode='a', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                if not file_exists:
                    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Length", "Payload Preview"])
        except Exception as e:
            logging.error(f"Failed to initialize CSV: {e}")
            console.print(f"[bold red][!] Failed to write to CSV: {e}[/bold red]")

    def display_banner(self):
        """Displays an ASCII banner on startup."""
        banner_text = """
   ____          _         _       _             
  / ___|___   __| | ___   / \     | | _ __  _ __  
 | |   / _ \ / _` |/ _ \ / _ \    | || '_ \| '_ \ 
 | |__| (_) | (_| |  __// ___ \   | || |_) | | | |
  \____\___/ \__,_|\___/_/   \_\  |_|| .__/|_| |_|
                                     |_|          
        CodeAlpha Basic Network Sniffer
        """
        panel = Panel(
            Text(banner_text, style="bold cyan", justify="center"),
            title="[bold green]Amritesh Mishra - Cyber Security Internship[/bold green]",
            subtitle="[bold yellow]Ready to Capture[/bold yellow]",
            expand=False
        )
        console.print(panel)

    def print_interfaces(self):
        """Displays available network interfaces for user reference."""
        console.print("[bold yellow][*] Available Network Interfaces:[/bold yellow]")
        interfaces = scapy.get_if_list()
        for i, iface in enumerate(interfaces):
            console.print(f"  [cyan]{i+1}.[/cyan] {iface}")
        console.print("")

    def _get_payload_preview(self, packet) -> str:
        """Safely extracts a payload preview from a packet without crashing on bad data."""
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                # Attempt to decode as ASCII, ignoring bad characters
                decoded = raw_data.decode('ascii', errors='ignore')
                cleaned = ''.join(c if c.isprintable() else '.' for c in decoded)
                return cleaned[:50]
            except Exception:
                # Fallback to hexadecimal representation
                return raw_data.hex()[:50]
        return "None"

    def process_packet(self, packet):
        """Callback function executed for every intercepted packet."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src_ip = "N/A"
            dst_ip = "N/A"
            protocol = "Other"
            length = len(packet)

            # Determine protocol and IP addresses based on layers
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if packet.haslayer(TCP):
                    protocol = "TCP"
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                if packet.haslayer(TCP):
                    protocol = "TCP"
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                elif packet.haslayer(ICMP):
                    protocol = "ICMPv6"
            elif packet.haslayer(ARP):
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
                protocol = "ARP"

            # Apply application-level protocol filter 
            if self.protocol_filter and self.protocol_filter != protocol and not (self.protocol_filter == "OTHER" and protocol == "Other"):
                return

            payload_preview = self._get_payload_preview(packet)

            self.packet_count += 1
            self.protocol_counts[protocol] += 1

            # Save packet details to CSV
            with open(self.output_csv, mode='a', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow([timestamp, src_ip, dst_ip, protocol, length, payload_preview])
                
            # Save raw packet to PCAP
            if self.pcap_writer:
                self.pcap_writer.write(packet)

            # Log basic info to file
            logging.info(f"Captured {protocol} | {src_ip} -> {dst_ip} | Len: {length}")

            # Define row colors based on protocol type for terminal output
            color = "white"
            if protocol == "TCP":
                color = "green"
            elif protocol == "UDP":
                color = "blue"
            elif protocol == "ICMP" or protocol == "ICMPv6":
                color = "magenta"
            elif protocol == "ARP":
                color = "yellow"

            # Print to console (append-only view)
            console.print(
                f"[{color}]{timestamp:<20} │ {src_ip:<15} │ {dst_ip:<15} │ {protocol:<7} │ {length:<6} │ {payload_preview:<40}[/{color}]"
            )

        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            # Silently drop malformed packets rather than crashing

    def start(self):
        """Starts the packet sniffing loop."""
        self.display_banner()

        if self.interface and self.interface not in scapy.get_if_list():
            console.print(f"[bold red][!] Interface '{self.interface}' not found.[/bold red]")
            self.print_interfaces()
            sys.exit(1)

        console.print(f"[bold green][+] Initialization Complete[/bold green]")
        if self.interface:
            console.print(f"[bold cyan][*] Interface:[/bold cyan] {self.interface}")
        else:
            console.print(f"[bold cyan][*] Interface:[/bold cyan] Default")
            
        if self.protocol_filter:
            console.print(f"[bold cyan][*] Protocol Filter:[/bold cyan] {self.protocol_filter}")
            
        console.print(f"[bold cyan][*] Logging to:[/bold cyan] {self.log_file}")
        console.print(f"[bold cyan][*] Exporting CSV:[/bold cyan] {self.output_csv}")
        if self.pcap_export:
            console.print(f"[bold cyan][*] Exporting PCAP:[/bold cyan] {self.output_pcap}")
            
        console.print("\n[bold yellow]Press Ctrl+C to stop sniffing.[/bold yellow]\n")

        # Display table header
        header = f"[bold white]{'Timestamp':<20} │ {'Source IP':<15} │ {'Destination IP':<15} │ {'Protocol':<7} │ {'Length':<6} │ {'Payload Preview':<40}[/bold white]"
        console.print(header)
        console.print("[bold white]─[/bold white]" * 115)

        # Build Scapy BPF filter
        bpf_filter = ""
        if self.protocol_filter in ["TCP", "UDP", "ICMP", "ARP"]:
            bpf_filter = self.protocol_filter.lower()

        self.start_time = time.time()
        logging.info("Packet sniffing started.")

        try:
            if bpf_filter:
                scapy.sniff(iface=self.interface, prn=self.process_packet, store=False, filter=bpf_filter)
            else:
                scapy.sniff(iface=self.interface, prn=self.process_packet, store=False)
        except PermissionError:
            console.print("\n[bold red][!] Permission Denied.[/bold red]")
            console.print("[red]Raw socket access requires administrative privileges. Please run the script with 'sudo' (Linux) or as Administrator (Windows).[/red]")
            console.print("[red]Example: sudo venv/bin/python sniffer.py[/red]")
            logging.error("Permission denied. Ensure script is run with elevated privileges.")
            self.stop(error=True)
        except OSError as e:
            if "No such device" in str(e):
                console.print(f"\n[bold red][!] Device not found.[/bold red]")
                self.print_interfaces()
            else:
                console.print(f"\n[bold red][!] An OS error occurred: {e}[/bold red]")
            logging.error(f"OS error: {e}")
            self.stop(error=True)
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            console.print(f"\n[bold red][!] An unexpected error occurred: {e}[/bold red]")
            logging.error(f"Unexpected sniffer error: {e}")
            self.stop(error=True)

    def stop(self, error=False):
        """Halts the sniffer and displays a summary of the capture session."""
        if self.pcap_writer:
            self.pcap_writer.close()

        duration = 0
        if self.start_time:
            duration = round(time.time() - self.start_time, 2)
            
        logging.info(f"Sniffing stopped. Total captured: {self.packet_count}. Duration: {duration}s")

        if not error:
            console.print("\n\n[bold green]Sniffing Session Terminated.[/bold green]")
        
        # Display Summary Table
        summary_table = Table(title="Capture Session Summary", show_header=True, header_style="bold magenta")
        summary_table.add_column("Metric", style="dim", width=20)
        summary_table.add_column("Value")
        
        summary_table.add_row("Total Packets", str(self.packet_count))
        summary_table.add_row("Duration", f"{duration} seconds")
        summary_table.add_row("CSV File", self.output_csv)
        summary_table.add_row("Log File", self.log_file)
        if self.pcap_export:
            summary_table.add_row("PCAP File", self.output_pcap)
            
        console.print(summary_table)
        
        # Display Protocol Breakdown
        if self.protocol_counts:
            proto_table = Table(title="Protocol Breakdown", show_header=True, header_style="bold cyan")
            proto_table.add_column("Protocol")
            proto_table.add_column("Count")
            for proto, count in sorted(self.protocol_counts.items(), key=lambda item: item[1], reverse=True):
                proto_table.add_row(proto, str(count))
            console.print(proto_table)

        sys.exit(1 if error else 0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CodeAlpha Basic Network Sniffer - A student cybersecurity project.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "-i", "--interface", 
        help="Network interface to sniff on (e.g., eth0, wlan0).\nIf omitted, the default system interface is used.", 
        default=None
    )
    parser.add_argument(
        "-p", "--protocol", 
        help="Filter traffic by protocol (Options: TCP, UDP, ICMP, ARP, OTHER).", 
        default=None
    )
    parser.add_argument(
        "--pcap", 
        help="Enable PCAP export to save raw packets for Wireshark analysis.", 
        action="store_true"
    )
    
    args = parser.parse_args()

    sniffer = NetworkSniffer(
        interface=args.interface, 
        protocol_filter=args.protocol, 
        pcap_export=args.pcap
    )
    
    sniffer.start()
