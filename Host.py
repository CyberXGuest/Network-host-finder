#!/usr/bin/env python3
"""
Codeccia - GitHub Hostname Checker
----------------------------------
A command-line tool to resolve hostnames from IP addresses.
Useful for network diagnostics, DevOps, or checking GitHub infrastructure.

Usage:
    python codeccia.py <IP_ADDRESS_1> <IP_ADDRESS_2> ...
Example:
    python codeccia.py 140.82.121.3 185.199.108.153
"""

import sys
import socket

BANNER = r"""
   ____          _           _       
  / ___|___   __| | ___  ___(_)_ __  
 | |   / _ \ / _` |/ _ \/ __| | '_ \ 
 | |__| (_) | (_| |  __/\__ \ | | | |
  \____\___/ \__,_|\___||___/_|_| |_|
       Network Hostname Checker by Hackrate.inc
"""

def get_hostname_from_ip(ip_address):
    """Return the hostname for a given IP address."""
    try:
        hostname = socket.gethostbyaddr(ip_address)
        return hostname[0]
    except socket.herror:
        return "Hostname could not be resolved"
    except Exception as e:
        return f"Error: {e}"

def main():
    print(BANNER)
    
    if len(sys.argv) < 2:
        print("Usage: python codeccia.py <IP_ADDRESS_1> <IP_ADDRESS_2> ...")
        sys.exit(1)

    ips = sys.argv[1:]
    print("🔍 Checking hostnames...\n")

    for ip in ips:
        hostname = get_hostname_from_ip(ip)
        print(f"IP: {ip:<15} → Hostname: {hostname}")

if __name__ == "__main__":
    main()
