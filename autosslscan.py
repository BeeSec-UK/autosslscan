#!/usr/bin/env python

import os
import subprocess
import argparse
from multiprocessing import Pool
from libnmap.parser import NmapParser
import datetime
import re
import xml.dom.minidom

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

def remove_ansi_escape_sequences(text):
    # Regular expression to match ANSI escape sequences
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    return ansi_escape.sub('', text)


def main():
    banner()
    args = parse_args()
    nmapxml = args.nmapxml
    output_directory = args.output_directory
    num_threads = args.num_threads

    # Create output directories
    sslscan_folder = os.path.join(output_directory, "sslscan")
    os.makedirs(sslscan_folder, exist_ok=True)

    items = os.listdir(sslscan_folder)
    for item in items:
        item_path = os.path.join(sslscan_folder, item)
        if os.path.isfile(item_path):
            os.remove(item_path)


    # Parse Nmap XML file and collect hosts and services
    # format xml file
    with open(nmapxml, 'r') as file:
        xml_content = file.read()

    temp = xml.dom.minidom.parseString(xml_content)
    formatted_xml = temp.toprettyxml(indent="  ")

    with open(nmapxml, 'w') as file:
        file.write(formatted_xml)

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
            output_file = os.path.join(sslscan_folder, f"sslscan-{ip}:{port}.txt")
            with open(output_file, 'w') as f:
                f.write(scan_output)
            print(f"{SYMBOLS['star']} SSL scan results for {ip}:{port}")
            print(scan_output)

    print(f"{SYMBOLS['star']} SSL scan results saved to: {sslscan_folder}")

    # Iterate over SSL scan results and check for legacy protocols
    for sslscan_result in os.listdir(sslscan_folder):
        result_path = os.path.join(sslscan_folder, sslscan_result)
        print(f"\n{SYMBOLS['plus']} Now scanning {result_path}")
        #remove ANSI escape codes from the output txt
        with open(result_path, 'r') as f:
            raw = f.read()
        clean_text = remove_ansi_escape_sequences(raw)
        with open(result_path, 'w') as f:
            f.write(clean_text)


        # Read the contents of the file
        with open(result_path, 'r') as s:
            scan_output = s.read()
            check_legacy_protocols(scan_output, result_path)
            extract_certificate_dates(scan_output, result_path)
            check_dhe_ciphers(scan_output, result_path)
            check_untrusted_certificate(scan_output, result_path)
            check_cbc3_ciphers(scan_output, result_path)
            check_rc4_ciphers(scan_output, result_path)
            check_null_ciphers(scan_output, result_path)
            check_medium_strength_ciphers(scan_output, result_path)

# Function to perform SSL scanning using sslscan
def perform_ssl_scan(ip_port):
    ip, port = ip_port
    try:
        result = subprocess.run(
            ["sslscan", "--no-sigs", "--no-fallback", f"{ip}:{port}"],
            capture_output=True, text=True, check=True
        )
        return ip, port, result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{SYMBOLS['cross']} Error running sslscan for {ip}:{port}: {e}")
        return ip, port, None


# Function to check for vulnerable legacy protocols in SSL scan output
def check_legacy_protocols(scan_output, result_path):
    legacy_protocols = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
    vulnerable_protocols = set()

    for line in scan_output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lower() == "enabled" and parts[0] in legacy_protocols:
            vulnerable_protocols.add(parts[0])
            print(f"{SYMBOLS['warn']} Legacy protocols in use")

    if len(vulnerable_protocols) == 0:
        print(f"{SYMBOLS['plus']} No legacy protocols found!")
        with open(result_path, 'a') as s:
            s.write("\n\n+ No legacy protocols found! \n")
    else:
        print("Legacy protocols found")
        with open(result_path, 'a') as s:
            s.write(f"\n- Legacy protocols found: \n{vulnerable_protocols}")



# Function to extract certificate validity dates from the SSL scan output
def extract_certificate_dates(scan_output, result_path):
    valid_from = None
    valid_until = None

    for line in scan_output.splitlines():
        if line.startswith("Not valid before:"):
            valid_from = line.replace("Not valid before:", "").strip()
            valid_from = valid_from.replace('\x1b[32m', '').replace('\x1b[0m', '')  # Remove color codes
        elif line.startswith("Not valid after:"):
            valid_until = line.replace("Not valid after:", "").strip()
            valid_until = valid_until.replace('\x1b[32m', '').replace('\x1b[0m', '')  # Remove color codes

    # Print and write to the file based on what we found
    if valid_from or valid_until:
        # Call check_certificate_expiry only if both valid_from and valid_until are found
        if valid_from and valid_until:
            expiry_status = check_certificate_expiry(valid_from, valid_until, result_path)
    else:
        print(f"{SYMBOLS['warn']} No certificate validity dates found")
        with open(result_path, 'a') as s:
            s.write("\n- No certificate validity dates found! \n")

    return valid_from, valid_until



# Function to check certificate expiry
def check_certificate_expiry(valid_from, valid_until, result_path):
    current_date = datetime.datetime.utcnow()
    valid_from_date = datetime.datetime.strptime(valid_from, "%b %d %H:%M:%S %Y %Z")
    valid_until_date = datetime.datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z")

    days_remaining = (valid_until_date - current_date).days

    with open(result_path, 'a') as s:
        if current_date < valid_from_date:
            print(f"{SYMBOLS['warn']} Certificate is not yet valid.")
            s.write("- Certificate Status: Not yet valid \n")
            return "Not yet valid"
        elif current_date > valid_until_date:
            print(f"{SYMBOLS['warn']} SSL Certificate Expired.")
            s.write("- Certificate Status: Expired \n")
            return "Expired"
        elif days_remaining <= 30:
            print(f"{SYMBOLS['warn']} SSL Certificate expiring in next 30 days.")
            s.write(f"- Certificate Status: Expiring in {days_remaining} days \n")
            return f"Expiring in {days_remaining} days"
        elif days_remaining > 365:
            print(f"{SYMBOLS['warn']} SSL Certificate expires in >1 year.")
            s.write("- Certificate Status: Long expiry (>1 year) \n")
            return "Long expiry"
        else:
            print(f"{SYMBOLS['plus']} SSL Certificate is valid with normal expiry.")
            s.write("+ Certificate Status: Valid with normal expiry \n")
            return "Valid"

# Function to check for DHE ciphers with <= 1024 bits
def check_dhe_ciphers(scan_output, result_path):
    vulnerable_ciphers = set()
    for line in scan_output.splitlines():
        parts = line.split()
        if "DHE" in parts and not any(part.startswith("Curve") for part in parts):
            if len(parts) >= 7:
                # print(parts[6])
                if int(parts[6]) <= 1024:
                    vulnerable_ciphers.add(parts[-1])
                    for p in parts:
                        if p.startswith("DHE-"):
                            cipher_name = p
                    print(f"{SYMBOLS['warn']} The cipher {cipher_name} is only {int(parts[6])} bits!")
                    with open(result_path, 'a') as s:
                        s.write(f"- The cipher {cipher_name} is only {int(parts[6])} bits! \n")

    # Check if any vulnerable ciphers were found
    if len(vulnerable_ciphers) == 0:
        print(f"{SYMBOLS['plus']} No vulnerable DHE ciphers found")
        with open(result_path, 'a') as s:
            s.write(f"+ No vulnerable DHE ciphers found \n")

    return vulnerable_ciphers


# Function to check if certificate is untrusted (Issuer in red)
def check_untrusted_certificate(scan_output, result_path):
    is_untrusted = False
    for line in scan_output.splitlines():
        if "Issuer:" in line and "\x1b[31m" in line:
            is_untrusted = True
            message = f"{SYMBOLS['warn']} SSL Certificate is untrusted: Unknown Issuer"
            print(message)

            # Write to the result file
            with open(result_path, 'a') as f:
                f.write(f"{message}\n")
            break

    if not is_untrusted:
        message = "SSL Certificate is trusted."
        print(f"{SYMBOLS['plus']} {message}")

        # Write trusted message to the result file
        with open(result_path, 'a') as f:
            f.write(f"+ {message} \n")

    return is_untrusted


# Function to check for CBC3 ciphers
def check_cbc3_ciphers(scan_output, result_path):
    vulnerable_ciphers = set()
    for line in scan_output.splitlines():
        parts = line.split()
        if "DES-CBC3-SHA" in parts:
            vulnerable_ciphers.add(parts[-1])
            message = f"{SYMBOLS['warn']} Weak Ciphers: CBC Mode Ciphers in use."
            print(message)

            # Write to the result file
            with open(result_path, 'a') as f:
                f.write(f"{message}\n")

    if not vulnerable_ciphers:
        message = "No vulnerable CBC3 ciphers found."
        print(f"{SYMBOLS['plus']} {message}")

        # Write no vulnerable ciphers message to the result file
        with open(result_path, 'a') as f:
            f.write(f"+ {message} \n")

    return vulnerable_ciphers


# Function to check for RC4 ciphers
def check_rc4_ciphers(scan_output, result_path):
    vulnerable_ciphers = set()
    for line in scan_output.splitlines():
        parts = line.split()
        if "RC4" in parts:
            vulnerable_ciphers.add(parts[-1])
            message = f"{SYMBOLS['warn']} Weak Ciphers: RC4 Ciphers in use."
            print(message)

            # Write to the result file
            with open(result_path, 'a') as f:
                f.write(f"{message}\n")

    if not vulnerable_ciphers:
        message = "No vulnerable RC4 ciphers found."
        print(f"{SYMBOLS['plus']} {message}")

        # Write no vulnerable ciphers message to the result file
        with open(result_path, 'a') as f:
            f.write(f"+ {message} \n")

    return vulnerable_ciphers


# Function to check for NULL ciphers
def check_null_ciphers(scan_output, result_path):
    vulnerable_ciphers = set()
    for line in scan_output.splitlines():
        parts = line.split()
        if "NULL" in parts:
            vulnerable_ciphers.add(parts[-1])
            message = f"{SYMBOLS['warn']} Weak Ciphers: NULL Ciphers in use."
            print(message)

            # Write to the result file
            with open(result_path, 'a') as f:
                f.write(f"{message}\n")

    if not vulnerable_ciphers:
        message = "No vulnerable NULL ciphers found."
        print(f"{SYMBOLS['plus']} {message}")

        # Write no vulnerable ciphers message to the result file
        with open(result_path, 'a') as f:
            f.write(f"+ {message} \n")

    # Function to check for medium strength ciphers
    def check_medium_strength_ciphers(scan_output, result_path):
        medium_strength_ciphers = set()
        for line in scan_output.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2].isdigit() and int(parts[2]) <= 112:
                cipher = " ".join(parts[3:])
                medium_strength_ciphers.add(cipher)
                message = f"{SYMBOLS['warn']} Weak Ciphers: <= 112 Bit Encryption: {cipher}"
                print(message)

                # Write to the result file
                with open(result_path, 'a') as f:
                    f.write(f"{message}\n")

        if not medium_strength_ciphers:
            message = "No medium strength ciphers found."
            print(message)

            # Write no medium strength ciphers message to the result file
            with open(result_path, 'a') as f:
                f.write(f"{message}\n")
        return medium_strength_ciphers
    return vulnerable_ciphers


# Function to check for medium strength ciphers
def check_medium_strength_ciphers(scan_output, result_path):
    medium_strength_ciphers = set()
    for line in scan_output.splitlines():
        if not line.startswith("OpenSSL"):
            parts = line.split()
            if len(parts) >= 3 and parts[2].isdigit() and int(parts[2]) <= 112:
                cipher = parts[4]
                medium_strength_ciphers.add(cipher)
                message = f"Weak Medium Strength Cipher has only {int(parts[2])} bits: {cipher}"
                print(f"{SYMBOLS['warn']} {message}")

                # Write to the result file
                with open(result_path, 'a') as f:
                    f.write(f"- {message}\n")

    if not medium_strength_ciphers:
        message = "No medium strength ciphers found."
        print(f"{SYMBOLS['plus']} {message}")

        # Write no medium strength ciphers message to the result file
        with open(result_path, 'a') as f:
            f.write(f"+ {message} \n")

    return medium_strength_ciphers


if __name__ == "__main__":
    main()
