#!/usr/bin/env python
# Authors: Tom, Max and MaxGPT ;).

import os
import subprocess
import argparse
from multiprocessing import Pool
from libnmap.parser import NmapParser
import datetime
import re

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


def main():
    banner()
    args = parse_args()
    nmapxml = args.nmapxml
    output_directory = args.output_directory
    num_threads = args.num_threads

    sslscan_folder = os.path.join(output_directory, "sslscan")
    os.makedirs(sslscan_folder, exist_ok=True)

    items = os.listdir(sslscan_folder)
    for item in items:
        item_path = os.path.join(sslscan_folder, item)
        if os.path.isfile(item_path):
            os.remove(item_path)

    report = NmapParser.parse_fromfile(nmapxml)

    hosts_with_ssl = 0
    ssl_services = []
    for host in report.hosts:
        host_has_ssl = False
        for s in host.services:
            if s.tunnel == "ssl":
                ssl_services.append(f'{host.address}:{s.port}')
                host_has_ssl = True
        if host_has_ssl:
            hosts_with_ssl += 1

    print(f"{SYMBOLS['plus']} Found {hosts_with_ssl} hosts with {len(ssl_services)} total SSL services\n")

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

    for file in files_to_make:
        file_path = os.path.join(sslscan_folder, file)
        with open(file_path, "w") as f:
            pass  # Create an empty file

    with Pool(processes=num_threads) as pool:
        results = pool.map(perform_ssl_scan, ssl_services)

    for result in results:
        ip, port, scan_output = result
        #ip, port = ip_port.split(':')
        if scan_output:
            # print(scan_output)
            check_ssl_wildcard(scan_output, f"{sslscan_folder}/SSL_Wildcard_Present.txt", ip, port)
            check_signed_cert_rsa_keylength(scan_output, f"{sslscan_folder}/Weak_Signed_Certificate_RSA_Keylength.txt", ip, port)
            check_tls_fallback(scan_output, f"{sslscan_folder}/No_TLS_Fallback_SCSV_Support.txt", ip, port)
            check_legacy_protocols(scan_output, f"{sslscan_folder}/Legacy_SSL_And_TLS_Protocols.txt", ip, port)
            check_medium_strength_ciphers(scan_output, f"{sslscan_folder}/Weak_Ciphers_<128-bit_or_RC4_CBC.txt", ip, port)
            check_null_ciphers(scan_output, f"{sslscan_folder}/NULL_Ciphers.txt", ip, port)
            check_dhe_ciphers(scan_output, f"{sslscan_folder}/Diffie_Hellman Modulus_<2048-bits.txt", ip, port)
            check_untrusted_certificate(scan_output, f"{sslscan_folder}/Untrusted_Certificates.txt", ip, port)
            check_cbc_ciphers(scan_output, f"{sslscan_folder}/Weak_Ciphers_<128-bit_or_RC4_CBC.txt", ip, port)
            check_rc4_ciphers(scan_output, f"{sslscan_folder}/Weak_Ciphers_<128-bit_or_RC4_CBC.txt", ip, port)
            check_certificate_expiry(scan_output, f"{sslscan_folder}/Non_Valid_Certificates.txt", ip, port)
            check_tls_v1_3_disabled(scan_output, f"{sslscan_folder}/TLSv1.3_Disabled.txt", ip, port)
            check_sha1_hash(scan_output, f"{sslscan_folder}/SHA-1_Hash.txt", ip, port)

    with open(f"{sslscan_folder}/Final_Results.txt", 'a') as f:
        for text_file in os.listdir(sslscan_folder):
            if text_file != 'Final_Results.txt':
                title = f"{text_file.replace('_', ' ').replace('.txt', '')}"
                with open(f"{sslscan_folder}/{text_file}", 'r') as s:
                    results = s.read()
                    if results:
                        f.write(f"{title}:\n{results}\n")

    print(f'\n{SYMBOLS["plus"]} Please check {sslscan_folder}/Final_Results.txt')

def perform_ssl_scan(host: str) -> tuple:
    """
    Perform an SSL scan on a host.
    :param host: The host to scan.
    :return: A tuple containing the host, port, and scan output.
    """
    ip, port = host.split(':')
    print(f"{SYMBOLS['plus']} Started {ip}:{port}")
    try:
        result = subprocess.run(
            ["sslscan", "--no-sigs", f"{ip}:{port}"],
            capture_output=True, text=True, check=True
        )
        return ip, port, result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{SYMBOLS['cross']} Error running sslscan for {ip}:{port}: {e}")
        return ip, port, None


def check_legacy_protocols(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check for vulnerable legacy protocols in SSL scan output.
    :param: scan_output (str): The output from the SSL scan.
    :param: result_path (str): The path to the result file where findings will be appended.
    :param: ip (str): The IP address of the host.
    :param: port (str): The SSL port being scanned.
    :return: None
    """
    legacy_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]

    for line in scan_output.splitlines():
        line = remove_ansi_escape_sequences(line)
        parts = line.split()
        if len(parts) == 2 and parts[1].lower() == "enabled" and parts[0] in legacy_protocols:
            message = f"{ip}:{port}"
            with open(result_path, 'a') as f:
                f.write(f"{message}\n")
            return


def check_tls_v1_3_disabled(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if TLSv1.3 is disabled.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    for line in scan_output.splitlines():
        line = remove_ansi_escape_sequences(line)
        parts = line.split()
        if len(parts) == 2 and parts[1].lower() == "disabled" and parts[0] == "TLSv1.3":
            with open(result_path, 'a') as s:
                s.write(f"{ip}:{port}\n")
            return


def check_certificate_expiry(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if the certificate is not valid or is expiring soon.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    valid_from = None
    valid_until = None
    for line in scan_output.splitlines():
        line = remove_ansi_escape_sequences(line)
        if line.startswith("Not valid before:"):
            valid_from = line.replace("Not valid before:", "").strip()
        elif line.startswith("Not valid after:"):
            valid_until = line.replace("Not valid after:", "").strip()

    current_date = datetime.datetime.utcnow()
    valid_from_date = datetime.datetime.strptime(valid_from, "%b %d %H:%M:%S %Y %Z")
    valid_until_date = datetime.datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z")
    days_remaining = (valid_until_date - current_date).days

    if current_date < valid_from_date or current_date > valid_until_date or days_remaining <= 30 or days_remaining > 365:
        with open(result_path, 'a') as s:
            s.write(f"{ip}:{port}\n")
        return


def check_signed_cert_rsa_keylength(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if the RSA key length is less than 2048 bits.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    for line in scan_output.splitlines():
        line = remove_ansi_escape_sequences(line)
        if line.startswith('RSA Key Strength:'):
            parts = line.split()
            if int(parts[3]) < 2048:
                with open(result_path, 'a') as s:
                    s.write(f"{ip}:{port}\n")
                return


def check_tls_fallback(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if the server supports TLS Fallback SCSV.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    for line in scan_output.splitlines():
        line = remove_ansi_escape_sequences(line)
        if line == 'Server does not support TLS Fallback SCSV':
            with open(result_path, 'a') as s:
                s.write(f"{ip}:{port}\n")
            return


def check_3des_ciphers(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if the server supports 3DES ciphers.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    for line in scan_output.splitlines():
        line = remove_ansi_escape_sequences(line)
        parts = line.split()
        if any("3-DES" in part for part in parts):
            with open(result_path, 'a') as s:
                s.write(f"{ip}:{port}\n")
            return


def check_dhe_ciphers(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if the server supports DHE ciphers with less than 2048-bit modulus.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    for line in scan_output.splitlines():
        line = remove_ansi_escape_sequences(line)
        parts = line.split()
        if len(parts) >= 7:
            if parts[4].startswith("DHE") and not any("Curve" in part for part in parts):
                if int(parts[6]) < 2024:
                    with open(result_path, 'a') as s:
                        s.write(f"{ip}:{port}\n")
                    return


def check_untrusted_certificate(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if the certificate is untrusted.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    for line in scan_output.splitlines():
        if "Issuer:" in line and "\x1b[31m" in line:
            with open(result_path, 'a') as s:
                s.write(f"{ip}:{port}\n")
            return


def check_cbc_ciphers(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if the server supports CBC ciphers.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    for line in scan_output.splitlines():
        line = remove_ansi_escape_sequences(line)
        parts = line.split()
        if any("CBC" in part for part in parts):
            with open(result_path, 'a') as f:
                f.write(f"{ip}:{port}\n")
            return


def check_sha1_hash(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if the server supports SHA-1 hash.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    for line in scan_output.splitlines():
        line = remove_ansi_escape_sequences(line)
        parts = line.split()
        if any("SHA-1" in part for part in parts):
            with open(result_path, 'a') as f:
                f.write(f"{ip}:{port}\n")
            return


def check_rc4_ciphers(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if the server supports RC4 ciphers.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    for line in scan_output.splitlines():
        line = remove_ansi_escape_sequences(line)
        parts = line.split()
        if any("RC4" in part for part in parts):
            with open(result_path, 'a') as f:
                f.write(f"{ip}:{port}\n")
            return


def check_medium_strength_ciphers(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if the server supports medium strength ciphers.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    for line in scan_output.splitlines():
        if not line.startswith("OpenSSL"):
            line = remove_ansi_escape_sequences(line)
            parts = line.split()
            # < 128 bits and >= 1 bit
            if (len(parts) >= 3 and parts[2].isdigit()
                    and 1 <= int(parts[2]) < 128):
                message = f"{ip}:{port}"
                with open(result_path, 'a') as f:
                    f.write(f"{message}\n")
                return


def check_null_ciphers(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if the server supports NULL ciphers.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    for line in scan_output.splitlines():
        parts = line.split()
        if any("NULL" in part for part in parts):
            message = f"{ip}:{port}"
            with open(result_path, 'a') as f:
                f.write(f"{message}\n")
            return


def check_ssl_wildcard(scan_output: str, result_path: str, ip: str, port: str) -> None:
    """
    Check if the server has a wildcard SSL certificate.
    :param scan_output: The output from the SSL scan.
    :param result_path: The path to the result file where findings will be appended.
    :param ip: The IP address of the host.
    :param port: The SSL port being scanned.
    :return: None
    """
    for line in scan_output.splitlines():
        line = remove_ansi_escape_sequences(line)
        parts = line.split()
        if line.startswith("Subject:") and parts[1].startswith('*'):
            message = f"{ip}:{port}"
            with open(result_path, 'a') as f:
                f.write(f"{message}\n")
            return


if __name__ == "__main__":
    main()
