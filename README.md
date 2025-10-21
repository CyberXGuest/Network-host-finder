Install on termux
pkg update -y
pkg install python git -y
pip install requests colorama tabulate
# Optional (faster traceroute/port tools)
pkg install whois nmap -y

# Basic resolve + ping + geo
python goomsy.py --host example.com --ping --geo

# Scan ports 1-1024 and save JSON
python goomsy.py --host example.com --scan --ports 1-1024 --json ~/goomsy_result.json

# Quick scan common ports and save CSV of open ports
python goomsy.py --ip 8.8.8.8 --scan --csv ~/open_ports.csv

# Traceroute and whois
python goomsy.py --host example.com --traceroute --whois
