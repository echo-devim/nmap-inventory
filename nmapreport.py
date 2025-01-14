# NMAP Report Converter to Excel
# Example command:
# sudo nmap -sV --script=http-title --system-dns -vv -O --scan-delay 100ms --max-scan-delay 300ms 10.20.30.0/24 20.30.40.0/24 -oX /tmp/scan.xml

import sys
import xml.etree.ElementTree as ET
import xlsxwriter
import random
import string

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    scan_results = {}
    
    for host in root.findall('host'):
        if host.find('status').get('state','') == "down":
            continue
        address = host.find('address').get('addr')
        mac_vendor = 'n/a'
        for addr in host.findall('address'):
            if addr.get('addrtype','') == "mac":
                mac_vendor = addr.get('vendor','n/a')
        os = "n/a"
        hostname = "n/a"
        open_ports = []
        
        if host.find('os'):
            os_info = host.find('os').find('osmatch')
            if os_info is not None:
                os = os_info.get('name')
                if os_info.get('version'):
                    os += " " + os_info.get('version')
        
        if host.find('hostnames'):
            hostname_info = host.find('hostnames').find('hostname')
            if hostname_info is not None:
                hostname = hostname_info.get('name')
        
        for port in host.findall('.//port'):
            port_id = port.get('portid')
            service_name = port.find('service').get('name', '')
            service_product = port.find('service').get('product', '')
            service_extrainfo = port.find('service').get('extrainfo', '')
            service_version = port.find('service').get('version', '')
            title = port.find('script')
            if title != None:
                title = title.get('http-title', '')
            else:
                title = ""
            details = f"{port_id}/{service_name}"
            if service_product != "":
                details += " "+service_product
            if service_version != "":
                details += " "+service_version
            if service_extrainfo != "":
                details += " "+service_extrainfo
            if title != "":
                details += " "+title
            open_ports.append(details)
        
        subnet = address.rsplit('.', 1)[0] + '.0'
        
        if subnet not in scan_results:
            scan_results[subnet] = []
        
        scan_results[subnet].append({
            'host': address,
            'os': os,
            'mac_vendor': mac_vendor,
            'hostname': hostname,
            'service_count' : len(open_ports),
            'open_ports': '\n'.join(open_ports)
        })
    
    return scan_results

def get_icon(osname):
    icon_path = "./icons/"
    icon = "default.png"
    if "windows server" in osname:
        icon = "winserv.png"
    elif "windows" in osname:
        icon = "win.png"
    elif "linux" in osname:
        icon = "linux.png"
    elif "mac" in osname:
        icon = "mac.png"
    elif "forti" in osname:
        icon = "firewall.png"
    elif "cisco" in osname:
        icon = "switch.png"
    elif "vmware" in osname:
        icon = "vmware.png"
    
    return f"{icon_path}{icon}"

def create_excel(scan_results, output_file):
    workbook = xlsxwriter.Workbook(output_file)

    # Define formats
    title_format = workbook.add_format({'bold': True, 'font_color': 'blue', 'font_size': 14})
    header_format = workbook.add_format({'bold': True, 'bg_color': '#DDEBF7'})
    
    for subnet, hosts in scan_results.items():
        # Create new worksheet with random id and subnet
        worksheet = workbook.add_worksheet(''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(5)) + "_" + subnet)
        
        row = 0
        col = 0
        
        # Write the title
        #worksheet.write(row, col, 'Network Scan Results', title_format)
        #row += 2
        
        # Write the subnet title
        #worksheet.write(row, col, f"Subnet: {subnet}", header_format)
        #row += 1
        
        # Write the table headers
        headers = ["Icon", "Host", "Operating System", "Hostname", "MAC Vendor", "Service count", "Open Ports"]
        for header in headers:
            worksheet.write(row, col, header, header_format)
            col += 1
        row += 1
        col = 0
        
        # Write the table data
        for host in hosts:
            icon = get_icon(host['os'].lower())
            worksheet.embed_image(row, col, icon)
            worksheet.write(row, col + 1, host['host'])
            worksheet.write(row, col + 2, host['os'])
            worksheet.write(row, col + 3, host['hostname'])
            worksheet.write(row, col + 4, host['mac_vendor'])
            worksheet.write(row, col + 5, host['service_count'])
            worksheet.write(row, col + 6, host['open_ports'])
            row += 1
        
    # Autofit the worksheet.
    worksheet.autofit()
    workbook.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_xml> <output_excel>")
        sys.exit(1)
    
    input_xml = sys.argv[1]
    output_excel = sys.argv[2]
    
    scan_results = parse_nmap_xml(input_xml)
    create_excel(scan_results, output_excel)