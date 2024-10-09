#!/usr/bin/env python

import os
import subprocess
import argparse
from multiprocessing import Pool
from libnmap.parser import NmapParser

COLOURS = {
    "blue": "\033[1;34m",
    "green": "\033[1;32m",
    "red": "\033[1;31m",
    "yellow": "\033[1;33m",
    "reset": "\033[0m"
}
SYMBOLS = {
    "plus": f"{COLOURS['blue']}[{COLOURS['reset']}{COLOURS['green']}+{COLOURS['reset']}{COLOURS['blue']}]",
    "minus": f"{COLOURS['blue']}[{COLOURS['reset']}{COLOURS['red']}-{COLOURS['reset']}{COLOURS['blue']}]",
    "cross": f"{COLOURS['blue']}[{COLOURS['reset']}{COLOURS['red']}x{COLOURS['reset']}{COLOURS['blue']}]",
    "star": f"{COLOURS['blue']}[*]{COLOURS['reset']}",
    "warn": f"{COLOURS['blue']}[{COLOURS['reset']}{COLOURS['yellow']}!{COLOURS['reset']}{COLOURS['blue']}]",
    "end": f"{COLOURS['reset']}"
}


def banner():
    banner_text = f"""
    
    {COLOURS['yellow']}
              _                _                     
   __ _ _   _| |_ ___  ___ ___| |___  ___ __ _ _ __  
  / _` | | | | __/ _ \/ __/ __| / __|/ __/ _` | '_ \ 
 | (_| | |_| | || (_) \__ \__ \ \__ \ (_| (_| | | | |
  \__,_|\__,_|\__\___/|___/___/_|___/\___\__,_|_| |_|
                                                     
    
    @BeeSec
    Helping you Bee Secure
    
    usage: auto-sslscan.py -i [nmap-ouput.xml] -o [output-directory] -t [num-threads]{COLOURS['reset']}
    
    """
    print(banner_text)


def parse_args():
    parser = argparse.ArgumentParser(description="Auto-sslscan - SSL scanning for open ports in Nmap XML report.")
    parser.add_argument("-i", "--input", dest="nmapxml", required=True, help="Path to the Nmap XML output file")
    parser.add_argument("-o", "--output", dest="output_directory", required=True, help="Path to the output directory")
    parser.add_argument("-t", "--threads", dest="num_threads", type=int, default=10,
                        help="Number of threads for parallel execution")
    return parser.parse_args()


# Function to perform SSL scanning using sslscan
def perform_ssl_scan(ip_port):
    ip, port = ip_port
    try:
        result = subprocess.run(
            ["sslscan", "--no-sigs", "--no-fallback", f"{ip}:{port}"],
            capture_output=True, text=True, check=True
        )
        return (ip, port, result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"{SYMBOLS['cross']} Error running sslscan for {ip}:{port}: {e}")
        return (ip, port, None)


# Main function that performs the SSL scanning and analysis
def main():
    banner()
    args = parse_args()
    nmapxml = args.nmapxml
    output_directory = args.output_directory
    num_threads = args.num_threads

    # Create output directories
    sslscan_folder = os.path.join(output_directory, "sslscan")
    os.makedirs(sslscan_folder, exist_ok=True)

    # Parse Nmap XML file and collect hosts and services
    report = NmapParser.parse_fromfile(nmapxml)
    ssl_services = [(host.address, s.port) for host in report.hosts for s in host.services if
                    "https" in s.service.lower() or "ssl" in s.service.lower()]

    # Create a multiprocessing pool for parallel SSL scans
    with Pool(processes=num_threads) as pool:
        results = pool.map(perform_ssl_scan, ssl_services)

    # Process the results
    for ip, port, scan_output in results:
        if scan_output:
            # Save the SSL scan output to a file
            output_file = os.path.join(sslscan_folder, f"sslscan-{ip}-{port}.txt")
            with open(output_file, 'w') as f:
                f.write(scan_output)

    print(f"{SYMBOLS['star']} SSL scan results saved to: {sslscan_folder}")


if __name__ == "__main__":
    main()
