#! /usr/bin/env python

import scapy.all as scapy
import argparse
import socket
import ipaddress
import sys
import os
import json
import csv
import manuf

parser = manuf.MacParser()
# Colors
RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"

def check_permissions():
    if os.geteuid() != 0:
        sys.exit(f"{RED}[!] Run with sudo/Administrator privileges.{RESET}")

def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP/CIDR (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", help="Export results (CSV/JSON/TXT)")
    options = parser.parse_args()
    try:
        ipaddress.ip_network(options.target, strict=False)
    except ValueError:
        sys.exit(f"{RED}[!] Invalid IP/CIDR.{RESET}")
    return options

def scan(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        clients_list = []
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = "Unknown"
            vendor = parser.get_manuf(mac) or "Unknown"
            clients_list.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})
        return clients_list
    except Exception as e:
        sys.exit(f"{RED}[!] Scan failed: {e}{RESET}")

def print_result(results_list):
    print(f"\n{GREEN}[+] Network Scan Results:{RESET}")
    print(f"{BLUE}{'IP':<16}{RESET} {'MAC':<18} {'Hostname':<20} {'Vendor':<20}")
    print("-" * 80)
    for client in sorted(results_list, key=lambda x: ipaddress.ip_address(x['ip'])):
        print(f"{BLUE}{client['ip']:<16}{RESET} {client['mac']} {client['hostname']:<20} {client['vendor']}")

def export_results(results, filename):
    try:
        ext = filename.split('.')[-1].lower()
        if ext == "json":
            with open(filename, 'w') as f:
                json.dump(results, f, indent=4)
        elif ext == "csv":
            with open(filename, 'w') as f:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        elif ext == "txt":
            with open(filename, 'w') as f:
                for client in results:
                    f.write(f"{client['ip']}\t{client['mac']}\t{client['hostname']}\t{client['vendor']}\n")
        print(f"{GREEN}[+] Results saved to {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Export failed: {e}{RESET}")

if __name__ == '__main__':
    check_permissions()
    options = get_arguments()
    results = scan(options.target)
    print_result(results)
    if options.output:
        export_results(results, options.output)