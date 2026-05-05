import nmap


def run_nmap_scan(ip):

    nm=nmap.PortScanner()
    nm.scan(ip,arguments='-sV')
    list_port = []  
    for host in nm.all_hosts():     
        for proto in nm[host].all_protocols():
            ports=nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                product = nm[host][proto][port].get('product', '')
                version = nm[host][proto][port].get('version', '')

                if state != 'open':
                    continue
                if product:
                   product = product.strip()
                else:
                    product = ''
                
                list_port.append({
                    'port':port,
                    'state':state,
                    'product':product,
                    'version':version
                })
    return list_port    