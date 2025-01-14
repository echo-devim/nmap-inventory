# NMAP Report Converter to Excel

Nmap is a great open-source tool to perform a network inventory.
This repo contains a simple script to convert the xml report produced by nmap into the more readable format xlsx (Excel).

## Example Usage

1. Run nmap:
```sh
$ sudo nmap -sV --script=http-title --system-dns -vv --script smb-os-discovery -O --scan-delay 100ms --max-scan-delay 300ms 10.20.30.0/24 20.30.40.0/24 -oX /tmp/scan.xml
```

2. Run this tool:
```sh
$ python3 nmapreport.py /tmp/scan.xml out.xlsx
```