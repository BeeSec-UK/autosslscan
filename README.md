# Auto-SSLScan
Auto-SSLScan is a Python script designed to automate SSL scanning for open ports found in an Nmap XML report. The script identifies SSL services, runs `sslscan` against the discovered services, and analyses the scan results to detect potential vulnerabilities.

## Prerequisites
- [sslscan](https://github.com/rbsec/sslscan) should be installed and available in your system's PATH.

# Vulnerabilities Detected
- Legacy SSL and TLS Protocols
- TLSv1.3 Disabled
- Certificate Expiry
- Weak Signed Certificate RSA Keylength
- No TLS Fallback SCSV Support
- 3DES Ciphers
- Diffie-Hellman Modulus < 2048-bits
- Untrusted Certificate
- CBC Ciphers
- SHA-1 Hash
- RC4 Ciphers
- Medium Strength Ciphers
- NULL Ciphers
- SSL Wildcard Certificate

## Installation and Usage
<pre>
git clone https://github.com/BeeSec-UK/autosslscan
cd autosslscan
pip install -r requirements.txt
auto-sslscan.py -i [nmap-output.xml] -o [output-directory] -t [num-threads]
</pre>

