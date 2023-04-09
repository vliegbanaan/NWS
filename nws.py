import socket
import threading
import nmap
from scapy.all import ARP, Ether, srp

def scan_host(ip_address):
    """
    Scan een enkele host en retourneer een formatted (Fstr) string die de informatie bevat van de host.

    Parameters:
        ip_address(str): Het ip adres die gescanned moet worden.

    Return:
        Fstr: een formatted string die het IP adres, MAC adres, Open ports, Hostname, Operating system name en detected services bevat van de host die gescanned is.
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
    
def scan_subnet(ip_subnet):
    """
    Scan het opgegeven subnet voor apparaten voor een ARP request en retourneer deze in een lijst van dictionaries die de IP's en MAC addressen bevatten van de apparaten in het opgegeven subnet.

    Parameter:
        ip_subnet(str): het subnet wat gescanned moet worden in CIDR notatie, dat is bijvoorbeeld 192.168.1.1.

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

    Parameter:
        ip_address(str): Het ip-adres van het subnet of host waar de ARP-request heen gaat en waarvan de MAC addres(sen) verzameld word(en).

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
    
    Parameters:
        ip_address(str): Het IP-adres van de host om te scannen.
        port(int): De poort die gescanned moet worden.
   
    Return:
        boolean: False als port gesloten is, True als poort open is.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.1)
        result = sock.connect_ex((ip_address, port))
        return result == 0

def detect_open_ports(ip_address):
    """
    Detecteert de open staande poorten op de host met de gegeven IP. je kan de range opgeven tussen de 1 en 65535.

    Parameter:
        ip_address(str): Het IP adres van de host waar de poorten gescanned worden.

    Return:
        List: Een lijst met openstaande poorten van de host die gescanned is.
    """
    open_ports = []
    for port in range(1, 70):
        if is_port_open(ip_address, port):
            open_ports.append(port)
    return open_ports

def get_hostname(ip_address):
    """
    Verkrijg de hostname van het opgegeven IP adres via DNS.

    Parameter:
        ip_address(str) : Het ip adres van de host waar de hostname van moet worden verkregen.

    Return:
        String : De hostname van de opgegeven host als deze gevonden kan worden, anders retouneert er een foutmelding.
    """
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        hostname = 'Hostname is helaas niet gevonden, big sad UwU'
    return hostname

def detect_services(ip_address):
    """
    Detecteer de services die draaien op de open poorten van de host van het opgegeven IP-Adres.

    Parameter:
        ip_address(str) : Het IP-Adres van de host waar wordt gekeken naar de services.

    Return:
        Een dictionary van de poorten met de naam van de service die op de poort draait.
        Als er geen openstaande poorten gevonden worden, wordt er een lege dictionary geretourneerd.
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
    Detecteer het besturingssysteem van een host van het opgegeven IP-Adres.

    Paramter:
        ip_address(str) : Het IP-Adres van de host.

    Return:
        String: De naam van het besturingssysteem als deze is gevonden, anders wordt er none geretourneerd.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments='-A')
    os_name = nm[ip_address]['osmatch'][0]['name']
    return os_name

def main():
    """
    De gebruiker krijg twee opties om uit te kiezen.

    [1] Scan host: 
    Hierbij wordt een enkele host gescanned. De verkregen informatie wordt via een Formatted string geretourneerd. De volgende informatie wordt geprobeert te verkrijgen bij de host:
        * Mac adres van de host.
        * Open poorten van de host.
        * De hostname van de host.
        * Operating system van de host.
        * De services die draaien op de open poorten van de host.

    Na het kiezen van optie 1 worden de respectievelijke functies uitgevoerd.

    [2] Scan Subnet: 
    Hier wordt er op het gehele subnet gescanned, en worden alle gevonden IP addressen + mac addressen geretourneerd in een lijst van dictionaries.

    Na het kiezen van optie 2 worden de respectievelijke functies uitgevoerd.
    """
    choice = input("Kies een optie: \n 1. Scan Host \n 2. Scan Subnet \n Keuze: ")
    if choice == '1':
        functions = (scan_host,)
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