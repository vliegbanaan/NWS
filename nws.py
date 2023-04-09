import socket
import threading
import nmap
from scapy.all import ARP, Ether, srp

def scan_host(ip_address):
    """
    Scans a single host and returns a tuple containing the IP address, MAC address, open ports, hostname (if available),
    and operating system (if available)
    """
    # Mac adres van het opgegeven IP adres
    mac_address = get_mac_address(ip_address)

    # Scan voor openstaande poorten op opgegeven host
    open_ports = detect_open_ports(ip_address)

    # Get hostname van de host van het opgegeven IP adres.
    hostname = get_hostname(ip_address)

    # Scan voor de services op de poorten van het opgegeven IP adres.
    services = detect_services(ip_address)

    # Get operating system van het apparaat van het opgegeven IP adres.
    os_name = detect_os(ip_address)

    #  Retouneer het in een F string.
    return f'IP address: {ip_address}\nMAC address: {mac_address}\nOpen ports: {", ".join(str(port) for port in open_ports)} \nHostname: {hostname}\n Operating system: {os_name}, \n Detected services: {detect_services}' 
    
# Scan host moet doorverwijzen naar de andere functies, en deze functies halen allemaal apart de waardes op en format ze terug als F string. alles returnen naar scan_host, en deze returned het naar main.

def scan_subnet(ip_subnet):
    """
    Scan het opgegeven subnet voor apparaten voor een ARP request en retourneer deze in een lijst van dictionaries die de IP's en MAC addressen bevatten van de apparaten in het opgegeven subnet.

    Arg:
        ip_subnet (string): De sybbet wat gescanned moet worden in CIDR notatie, dat is bijvoorbeeld 192.168.1.1.

    Return:
        list: een lijst van dictionaries, elk die de IP en mac addressen bevatten van de appparaten op het subnet.
    """
    arp = ARP(pdst=ip_subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3 ,verbose=0)[0]

    clients = []

    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    print("beschikbare apparaten: ")
    print("IP" + " " * 18+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))

def get_mac_address(ip_address):
    """
    Verkrijg de mac addressen van de apparaten in het opgegeven subnet d.m.v. een ARP-request."

    Return:
        Retouneer het MAC adres als deze gevonden is, anders een none.
    """
    arp = ARP(pdst=ip_address)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    return result[0][1].hwsrc

def is_port_open(ip_address, port):
    """
    Controleer of de TCP poort open is op de host van het opgegeven IP adres.
    
    Return:
        
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.1)
        result = sock.connect_ex((ip_address, port))
        return result == 0

def detect_open_ports(ip_address):
    """
    Detecteert de open staande poorten op de host met de gegeven IP.
    """
    open_ports = []
    for port in range(1, 80):
        if is_port_open(ip_address, port):
            open_ports.append(port)
    return open_ports

def get_hostname(ip_address):
    """
    Verkrijg de hostname van het opgegeven IP adres via DNS.
    """
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        hostname = 'Wij zijn mannen die geen host nodig hebben, no cap.'
    return hostname

def detect_services(ip_address):
    """
    Detects the services running on open ports of a host with a given IP address.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments='-sS -sV --version-all')
    services = {}
    for host in nm.all_hosts():
        for port in nm[host]['tcp']:
            if nm[host]['tcp'][port]['state'] == 'open':
                services[port] = nm[host]['tcp'][port]['name']
    return services

def detect_os(ip_address):
    """
    Detects the operating system of a host with a given IP address.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments='-A')
    os_name = nm[ip_address]['osmatch'][0]['name']
    return os_name

def main():
    choice = input("Kies een optie: \n 1. Scan Host \n 2. Scan Subnet \n")
    if choice == '1':
        functions = (scan_host, detect_services, detect_os)
    elif choice == '2':
        functions = (scan_subnet,)
    else:
        print("Ongeldige keuze, Kies 1 of 2.")
        return

    argument = input("Geef het IP adres op van de host, of het IP van de subnet: ")
    for function in functions:
        result = function(argument)
        print(result)

if __name__ == '__main__':
    main()