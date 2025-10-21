#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codeccia - GitHub Hostname Checker (Termux Edition)
---------------------------------------------------
A CLI tool to resolve hostnames from IP addresses.
Works on Termux, Linux, or any Unix system with Python 3.

Usage:
    python codeccia.py <IP_ADDRESS_1> <IP_ADDRESS_2> ...
Example:
    python codeccia.py 140.82.121.3 185.199.108.153
"""

import sys
import socket
import os

# ANSI colors for Termux
RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"

BANNER = f"""{CYAN}
   ____          _           _       
  / ___|___   __| | ___  ___(_)_ __  
 | |   / _ \ / _` |/ _ \/ __| | '_ \ 
 | |__| (_) | (_| |  __/\__ \ | | | |
  \____\___/ \__,_|\___||___/_|_| |_|
{RESET}{YELLOW}       GitHub Hostname Checker (Codeccia)
{RESET}
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
    os.system("clear")
    print(BANNER)
    
    if len(sys.argv) < 2:
        print(f"{RED}Usage:{RESET} python codeccia.py <IP_ADDRESS_1> <IP_ADDRESS_2> ...")
        sys.exit(1)

    ips = sys.argv[1:]
    print(f"{YELLOW}🔍 Checking hostnames...{RESET}\n")

    for ip in ips:
        hostname = get_hostname_from_ip(ip)
        color = GREEN if "github" in hostname else CYAN
        print(f"{CYAN}IP:{RESET} {ip:<15} → {color}{hostname}{RESET}")

if __name__ == "__main__":
    main()
