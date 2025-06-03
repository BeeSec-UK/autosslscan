# autosslscan

**autosslscan** is a Python tool that parses Nmap XML files, identifies SSL/TLS and STARTTLS-enabled services, runs `sslscan`, and reports common SSL misconfigurations.

### Features
- Parses Nmap XML and resolves hostnames
- Detects SSL/TLS support (incl. STARTTLS: FTP, IMAP, SMTP, etc.)
- Runs `sslscan` in parallel
- Extracts and categorises vulnerabilities:
  - Legacy protocols (SSLv2/3, TLS 1.0/1.1)
  - TLSv1.3 disabled
  - Expired/self-signed/wildcard certs
  - Weak key lengths, SHA-1/MD5 hashes
  - CBC/RC4/NULL/3DES ciphers
  - No TLS Fallback (SCSV)
  - Hostname mismatch

### Requirements
- [sslscan](https://github.com/rbsec/sslscan)

### Usage
```
python autosslscan.py -d <nmap-xml-dir> -o <output-dir> [options]
```