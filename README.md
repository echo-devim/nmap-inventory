# NMAP Report Converter to Excel

Nmap is a great open-source tool to perform a network inventory.
This repo contains a simple script to convert the xml report produced by nmap into the more readable format xlsx (Excel).
I developed also a custom NSE script called `default-creds.nse` to test specific default credentials based on operating system type for the following protocols: ssh, smb, telnet and ftp. The goal is to perform a non-invasive test (just one or two attempts in order to not trigger alarms).

## Example Usage

1. Run nmap:
```sh
$ sudo nmap -sV --script=http-title --system-dns -vv --script smb-os-discovery --script rdp-ntlm-info --script default-creds.nse --script-args default-creds.csv=./default_creds.csv -O --osscan-limit --max-os-tries 2 --scan-delay 100ms --max-scan-delay 300ms 10.20.30.0/24 20.30.40.0/24 -oX /tmp/scan.xml
```

2. Run this tool:
```sh
$ python3 nmapreport.py /tmp/scan.xml out.xlsx
```