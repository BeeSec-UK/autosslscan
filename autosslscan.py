#!/usr/bin/env python
# Authors: Tom, Max and MaxGPT ;).

import os
import subprocess
import argparse
from multiprocessing import Pool
from libnmap.parser import NmapParser
import datetime
import re

from rpyc.utils import service

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
    "star": f"{COLOURS['green']}[*]{COLOURS['reset']}{COLOURS['green']}",
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
    Helping you Bee Secure - https://github.com/BeeSec-UK/
    
    usage: autosslscan.py -i [nmap-ouput.xml] -o [output-directory] -t [num-threads]{COLOURS['reset']}
    
    """
    print(banner_text)


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.
    :return:  The parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Auto-sslscan - SSL scanning for open ports in Nmap XML report.")
    parser.add_argument("-i", "--input", dest="nmapxml", required=True, help="Path to the Nmap XML output file")
    parser.add_argument("-o", "--output", dest="output_directory", required=True, help="Path to the output directory")
    parser.add_argument("-t", "--threads", dest="num_threads", type=int, default=10,
                        help="Number of threads for parallel execution")
    return parser.parse_args()


def remove_ansi_escape_sequences(text: str) -> str:
    """
    Remove ANSI escape sequences from a string.
    :param text: The text to remove the escape sequences from.
    :return: The text with the escape sequences removed.
    """
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    return ansi_escape.sub('', text)

scan_counter = 0

def main():
    args = parse_args()
    nmapxml = args.nmapxml
    output_directory = args.output_directory
    num_threads = args.num_threads

    # make output folders
    sslscan_folder = os.path.join(output_directory, "sslscan")
    os.makedirs(sslscan_folder, exist_ok=True)

    raw_output_folder = os.path.join(sslscan_folder, "raw_output")
    os.makedirs(raw_output_folder, exist_ok=True)

    vuln_output_folder = os.path.join(sslscan_folder, "ssl")
    os.makedirs(vuln_output_folder, exist_ok=True)

    starttls_vuln_folder = os.path.join(sslscan_folder, "starttls")
    os.makedirs(starttls_vuln_folder, exist_ok=True)

    output_folders = {
        "raw_output": raw_output_folder,
        "vuln_output": vuln_output_folder,
        "sslscan_folder": sslscan_folder
    }

    # remove any existing files in the folder
    for folder in [sslscan_folder, raw_output_folder, vuln_output_folder, starttls_vuln_folder]:
        items = os.listdir(folder)
        for item in items:
            item_path = os.path.join(folder, item)
            if os.path.isfile(item_path):
                os.remove(item_path)

    # get the merged nmap file and look for ssl services.
    report = NmapParser.parse_fromfile(nmapxml)

    hosts_with_ssl = 0
    hosts_with_extra_ports = 0
    extra_ports = 0
    ssl_services = []
    starttls_services = {
        "ftp": [],
        "imap": [],
        "irc": [],
        "ldap": [],
        "mysql": [],
        "pop3": [],
        "psql": [],
        "smtp": [],
        "xmpp": []
    }

    #get the ssl services and starttls services
    for host in report.hosts:
        host_has_ssl = False
        extra_port = False
        #print(host.address)
        for s in host.services:
            if s.tunnel == "ssl":
                ssl_services.append(f'{host.address}:{s.port}')
                host_has_ssl = True
            elif s.service in starttls_services:
                #print(s.service)
                starttls_services[s.service].append(f'{host.address}:{s.port}')
                extra_port = True
                extra_ports += 1
        if host_has_ssl:
            hosts_with_ssl += 1
        if extra_port:
            hosts_with_extra_ports += 1

    print(f"{SYMBOLS['plus']} Scanning {len(ssl_services)} ssl services on {hosts_with_ssl} hosts")
    if extra_ports != 0:
        print(f"{SYMBOLS['plus']} Will also scan {extra_ports} extra services on {hosts_with_extra_ports} hosts\n")

    files_to_make = [
        "Legacy_SSL_And_TLS_Protocols.txt",
        "Non_Valid_Certificates.txt",
        "NULL_Ciphers.txt",
        "Diffie_Hellman Modulus_<2048-bits.txt",
        "Untrusted_Certificates.txt",
        "Weak_Ciphers_<128-bit_or_RC4_CBC.txt",
        "No_TLS_Fallback_SCSV_Support.txt",
        "Weak_Signed_Certificate_RSA_Keylength.txt",
        "SSL_Wildcard_Present.txt",
        "TLSv1.3_Disabled.txt",
        "SHA-1_Hash.txt",
        "Final_Results.txt"
    ]

    #create the files here
    with open(f"{sslscan_folder}/errors.txt", "w") as f:
        pass
    for file in files_to_make:
        file_path = os.path.join(vuln_output_folder, file)
        with open(file_path, "w") as f:
            pass
        file_path = os.path.join(starttls_vuln_folder, file)
        with open(file_path, "w") as f:
            pass

    with Pool(processes=num_threads) as pool:
        ssl_results = pool.map(perform_ssl_scan, ssl_services)
        print(f'\n{SYMBOLS["warn"]} Finished scanning SSL services, moving onto STARTTLS services{COLOURS["reset"]}\n')
        starttls_results = pool.starmap(perform_ssl_scan_tls_service, [(host, service) for service, hosts in starttls_services.items() for host in hosts])

    def process_results(results, output_folders, vuln_folder):
        for result in results:
            ip, port, scan_output = result
            temp = remove_ansi_escape_sequences(scan_output).splitlines()
            if scan_output and len(temp) > 4:
                check_ssl_wildcard(scan_output, f"{vuln_folder}/SSL_Wildcard_Present.txt", ip, port, output_folders)
                check_signed_cert_rsa_keylength(scan_output, f"{vuln_folder}/Weak_Signed_Certificate_RSA_Keylength.txt", ip, port, output_folders)
                check_tls_fallback(scan_output, f"{vuln_folder}/No_TLS_Fallback_SCSV_Support.txt", ip, port, output_folders)
                check_legacy_protocols(scan_output, f"{vuln_folder}/Legacy_SSL_And_TLS_Protocols.txt", ip, port, output_folders)
                check_medium_strength_ciphers(scan_output, f"{vuln_folder}/Weak_Ciphers_<128-bit_or_RC4_CBC.txt", ip, port, output_folders)
                check_null_ciphers(scan_output, f"{vuln_folder}/NULL_Ciphers.txt", ip, port, output_folders)
                check_dhe_ciphers(scan_output, f"{vuln_folder}/Diffie_Hellman Modulus_<2048-bits.txt", ip, port, output_folders)
                check_untrusted_certificate(scan_output, f"{vuln_folder}/Untrusted_Certificates.txt", ip, port, output_folders)
                check_cbc_ciphers(scan_output, f"{vuln_folder}/Weak_Ciphers_<128-bit_or_RC4_CBC.txt", ip, port, output_folders)
                check_rc4_ciphers(scan_output, f"{vuln_folder}/Weak_Ciphers_<128-bit_or_RC4_CBC.txt", ip, port, output_folders)
                check_certificate_expiry(scan_output, f"{vuln_folder}/Non_Valid_Certificates.txt", ip, port, output_folders)
                check_tls_v1_3_disabled(scan_output, f"{vuln_folder}/TLSv1.3_Disabled.txt", ip, port, output_folders)
                check_sha1_hash(scan_output, f"{vuln_folder}/SHA-1_Hash.txt", ip, port, output_folders)
            elif len(temp) <= 4:
                with open(f"{output_folders['sslscan_folder']}/errors.txt", "a") as f:
                    f.write(f"{ip}:{port}\n")

    process_results(ssl_results, output_folders, vuln_output_folder)
    process_results(starttls_results, output_folders, starttls_vuln_folder)

    def write_final_results(vuln_folder):
        with open(f"{vuln_folder}/Final_Results.txt", 'a') as f:
            for text_file in os.listdir(vuln_folder):
                if text_file != 'Final_Results.txt':
                    title = f"{text_file.replace('_', ' ').replace('.txt', '')}"
                    with open(f"{vuln_folder}/{text_file}", 'r') as s:
                        results = s.read()
                        if results:
                            f.write(f"{title}:\n{results}\n")

    write_final_results(vuln_output_folder)
    write_final_results(starttls_vuln_folder)

    print(f'\n{SYMBOLS["plus"]} Please check {vuln_output_folder}/Final_Results.txt')
    if extra_ports != 0:
        print(f'{SYMBOLS["plus"]} Please check {starttls_vuln_folder}/Final_Results.txt')
    banner()


def perform_ssl_scan_tls_service(host: str, service_name: str) -> tuple:
    ip, port = host.split(':')
    try:
        print(f"{SYMBOLS['plus']} Performing sslscan {ip}:{port}")
        result = subprocess.run(
            ["sslscan", "--no-sigs", f"--starttls-{service_name}", f"{ip}:{port}"],
            capture_output=True, text=True, check=True
        )
        #print(result.stdout)
        print(f"{SYMBOLS['star']}{COLOURS['green']} Finished scanning {ip}:{port}")
        return ip, port, result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{SYMBOLS['cross']} Error running sslscan for {ip}:{port}: {e}")
        return ip, port, None


def perform_ssl_scan(host: str) -> tuple:
    """
    Perform an SSL scan on a host.
    :param host: The host to scan.
    :return: A tuple containing the host, port, and scan output.
    """
    ip, port = host.split(':')
    print(f"{SYMBOLS['plus']} Performing sslscan {ip}:{port}")
    try:
        result = subprocess.run(
            ["sslscan", "--no-sigs", f"{ip}:{port}"],
            capture_output=True, text=True, check=True
        )
        print(f"{SYMBOLS['star']} Finished scanning {ip}:{port}")
        return ip, port, result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{SYMBOLS['cross']} Error running sslscan for {ip}:{port}: {e}")
        return ip, port, None


def check_legacy_protocols(scan_output: str, result_path: str, ip: str, port: str, output_folders: dict[str,str]) -> None:
    """
    Check for vulnerable legacy protocols in SSL scan output.
    :param: scan_output (str): The output from the SSL scan.
    :param: result_path (str): The path to the result file where findings will be appended.
    :param: ip (str): The IP address of the host.
    :param: port (str): The SSL port being scanned.
    :return: None
    """
    legacy_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lower() == "enabled" and parts[0] in legacy_protocols:
            message = f"{ip}:{port}"
            with open(result_path, 'a') as f:
                f.write(f"{message}\n")
            return


def check_tls_v1_3_disabled(scan_output: str, result_path: str, ip: str, port: str, output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lower() == "disabled" and parts[0] == "TLSv1.3":
            with open(result_path, 'a') as s:
                s.write(f"{ip}:{port}\n")
            return


def check_certificate_expiry(scan_output: str, result_path: str, ip: str, port: str, output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    valid_from = None
    valid_until = None
    for line in scan_output.splitlines():
        if line.startswith("Not valid before:"):
            valid_from = line.replace("Not valid before:", "").strip()
        elif line.startswith("Not valid after:"):
            valid_until = line.replace("Not valid after:", "").strip()

    if valid_from and valid_until:
        current_date = datetime.datetime.utcnow()
        valid_from_date = datetime.datetime.strptime(valid_from, "%b %d %H:%M:%S %Y %Z")
        valid_until_date = datetime.datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z")
        days_remaining = (valid_until_date - current_date).days

        if current_date < valid_from_date or current_date > valid_until_date or days_remaining <= 30 or days_remaining > 365:
            with open(result_path, 'a') as s:
                s.write(f"{ip}:{port}\n")
            return


def check_signed_cert_rsa_keylength(scan_output: str, result_path: str, ip: str, port: str,
                                    output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        if line.startswith('RSA Key Strength:'):
            parts = line.split()
            if int(parts[3]) < 2048:
                with open(result_path, 'a') as s:
                    s.write(f"{ip}:{port}\n")
                return


def check_tls_fallback(scan_output: str, result_path: str, ip: str, port: str, output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        if line == 'Server does not support TLS Fallback SCSV':
            with open(result_path, 'a') as s:
                s.write(f"{ip}:{port}\n")
            return


def check_3des_ciphers(scan_output: str, result_path: str, ip: str, port: str, output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        parts = line.split()
        if any("3-DES" in part for part in parts):
            with open(result_path, 'a') as s:
                s.write(f"{ip}:{port}\n")
            return


def check_dhe_ciphers(scan_output: str, result_path: str, ip: str, port: str, output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        parts = line.split()
        if len(parts) >= 7:
            if parts[4].startswith("DHE") and not any("Curve" in part for part in parts):
                if int(parts[6]) < 2024:
                    with open(result_path, 'a') as s:
                        s.write(f"{ip}:{port}\n")
                    return


def check_untrusted_certificate(scan_output: str, result_path: str, ip: str, port: str,
                                output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        if "Issuer:" in line and "\x1b[31m" in line:
            with open(result_path, 'a') as s:
                s.write(f"{ip}:{port}\n")
            return


def check_cbc_ciphers(scan_output: str, result_path: str, ip: str, port: str, output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        parts = line.split()
        if any("CBC" in part for part in parts):
            with open(result_path, 'a') as f:
                f.write(f"{ip}:{port}\n")
            return


def check_sha1_hash(scan_output: str, result_path: str, ip: str, port: str, output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        parts = line.split()
        if any("SHA-1" in part for part in parts):
            with open(result_path, 'a') as f:
                f.write(f"{ip}:{port}\n")
            return


def check_rc4_ciphers(scan_output: str, result_path: str, ip: str, port: str, output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        parts = line.split()
        if any("RC4" in part for part in parts):
            with open(result_path, 'a') as f:
                f.write(f"{ip}:{port}\n")
            return


def check_medium_strength_ciphers(scan_output: str, result_path: str, ip: str, port: str,
                                  output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        if not line.startswith("OpenSSL"):
            parts = line.split()
            if (len(parts) >= 3 and parts[2].isdigit() and 1 <= int(parts[2]) < 128):
                message = f"{ip}:{port}"
                with open(result_path, 'a') as f:
                    f.write(f"{message}\n")
                return


def check_null_ciphers(scan_output: str, result_path: str, ip: str, port: str, output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        parts = line.split()
        if any("NULL" in part for part in parts):
            message = f"{ip}:{port}"
            with open(result_path, 'a') as f:
                f.write(f"{message}\n")
            return


def check_ssl_wildcard(scan_output: str, result_path: str, ip: str, port: str, output_folders: dict[str,str]) -> None:
    scan_output = remove_ansi_escape_sequences(scan_output)
    with open(f'{output_folders["raw_output"]}/{ip}:{port}.txt', 'w') as f:
        f.write(scan_output)
    for line in scan_output.splitlines():
        parts = line.split()
        if line.startswith("Subject:") and parts[1].startswith('*'):
            message = f"{ip}:{port}"
            with open(result_path, 'a') as f:
                f.write(f"{message}\n")
            return


if __name__ == "__main__":
    main()
