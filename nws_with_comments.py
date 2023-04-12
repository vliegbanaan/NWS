import socket
import threading
import nmap
from scapy.all import ARP, Ether, srp

def scan_host(ip_address):
    """
    Scan een enkele host en retourneer een formatted (Fstr) string die de informatie bevat van de host.

    Parameter:
        ip_address(str): Het IP-adres die gescanned moet worden.

    Return:
        Fstr: een formatted string die het IP adres, MAC adres, Open ports, Hostname, Operating system name en detected services bevat van de host die gescanned is.
    """
    # Get het MAC adres van het opgegeven IP adres
    mac_address = get_mac_address(ip_address)

    # Scan voor openstaande poorten op opgegeven host
    open_ports = detect_open_ports(ip_address)

    # Get de hostname van de host van het opgegeven IP adres.
    hostname = get_hostname(ip_address)

    # Scan voor de services op de poorten van het opgegeven IP adres.
    services = detect_services(ip_address)

    # Get het operating system van het apparaat van het opgegeven IP adres.
    os_name = detect_os(ip_address)

    # Retouneer het in een F string.
    return f'IP address: {ip_address}\nMAC address: {mac_address}\nOpen ports: {", ".join(str(port) for port in open_ports)} \nHostname: {hostname}\n Operating system: {os_name}, \n Detected services: {detect_services}' 
    
def scan_subnet(ip_subnet):
    """
    Scan het opgegeven subnet voor apparaten voor een ARP request en retourneer deze in een lijst van dictionaries die de IP's en MAC addressen bevatten van de apparaten in het opgegeven subnet.

    Parameter:
        ip_subnet(str): het subnet wat gescanned moet worden in CIDR notatie, dat is bijvoorbeeld 192.168.1.1.

    Return:
        list: een lijst van dictionaries, elk die de IP en mac addressen bevatten van de appparaten op het subnet.
    """
    arp = ARP(pdst=ip_subnet)                                                               #Maak Scapy object van het type ARP.
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")                                                  #Maak Scapy object van het type Ether (frame). De bestemming van de frame is het broadcast MAC.
    packet = ether/arp                                                                      #Combineer de twee objecten tot 1 packet. Dit is nodig om het ARP-verzoek te versturen.
    result = srp(packet, timeout=3 ,verbose=0)[0]                                           #Verstuur packet naar alle apparaten, wacht 3 seconden op reactie en return een lijst met IP en MAC addressen.

    clients = []                                                                            #Maak lege lijst.

    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})                        #Loop door result heen, voeg gevonden IP en MAC addressen toe aan clients list en return deze.

    print("beschikbare apparaten: ")
    print("IP" + " " * 18+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))                            #Loop door clients heen, print gevonden IP en mac addressen. Ip addressen worden afgedrukt in kolom van 16 chars en MAC in het volgende kolom.

def get_mac_address(ip_address):
    """
    Verkrijg de mac addressen van de apparaten in het opgegeven subnet d.m.v. een ARP-request."

    Parameter:
        ip_address(str): Het ip-adres van het subnet of host waar de ARP-request heen gaat en waarvan de MAC addres(sen) verzameld word(en).

    Return:
        Retouneer het MAC adres als deze gevonden is, anders een none.
    """
    arp = ARP(pdst=ip_address)                                                              #Maak Scapy object van het type ARP.                                                              
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")                                                  #Maak Scapy object van het type Ether (frame). De bestemming van de frame is het broadcast MAC.
    packet = ether/arp                                                                      #Combineer de twee objecten tot 1 packet. Dit is nodig om het ARP-verzoek te versturen.
    result = srp(packet, timeout=3, verbose=0)[0]                                           #Verstuur packet naar alle apparaten, wacht 3 seconden op reactie en return een lijst met IP en MAC addressen.
    return result[0][1].hwsrc                                                               #Return het MAC adres van het eerste apparaat van het ARP-verzoek, Elke tuple in de lijst heeft 2 elementen waar de eerste gestuurde packet is en tweede het antwoord van het apparaat.

def is_port_open(ip_address, port):
    """
    Controleer of de TCP poort open is op de host van het opgegeven IP adres.
    
    Parameters:
        ip_address(str): Het IP-adres van de host om te scannen.
        port(int): De poort die gescanned moet worden.
   
    Return:
        boolean: False als port gesloten is, True als poort open is.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:                         #Open socket en gebruik TCP om verbinding te maken.
        sock.settimeout(0.1)                                                                #Time-out in van 0.1 seconden voor het opzetten verbinding met de host en poort.
        result = sock.connect_ex((ip_address, port))                                        #Poging verbinding met IP-adres en poort, status verbinding wordt opgeslagen in result.
        return result == 0                                                                  #Vergelijk result met nul. Bij true is poort open, bij False is poort dicht.

def detect_open_ports(ip_address):
    """
    Scan de open staande poorten op de host met de gegeven IP. je kan de range opgeven tussen de 1 en 65535.

    Parameter:
        ip_address(str): Het IP adres van de host waar de poorten gescanned worden.

    Return:
        List: Een lijst met openstaande poorten van de host die gescanned is.
    """
    open_ports = []                                                                         #Maak lege lijst.
    for port in range(1, 1024):                                                             #Range poorten die gescanned moeten worden.
        if is_port_open(ip_address, port):                                                  #For loop voor het scannen van alle poorten. Loop is variabel maar in ons geval 1-1024 omdat in dit gebied de meest gebruikte poorten zijn.
            open_ports.append(port)                                                         #Als poort open is, wordt deze toegevoegd aan lijst open_ports.
    return open_ports

def get_hostname(ip_address):
    """
    Probeer de hostname van het opgegeven IP adres via DNS te verkrijgen.

    Parameter:
        ip_address(str) : Het ip adres van de host waar de hostname van moet worden verkregen.

    Return:
        String : De hostname van de opgegeven host als deze gevonden kan worden, anders retouneert er een foutmelding.
    """
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]                                      #Hostname wordt opgevraagd d.m.v. DNS. 
    except socket.herror:                                                                   #Als de hostname niet kan worden gevonden, zal socket.herror activeert worden en wordt er een foutmelding geretourneerd.
        hostname = 'Hostname is helaas niet gevonden, big sad UwU'
    return hostname                                                                         #Return de hostname of foutmelding.

def detect_services(ip_address):
    """
    Detecteer de services die draaien op de open poorten van de host van het opgegeven IP-Adres.

    Parameter:
        ip_address(str) : Het IP-Adres van de host waar wordt gekeken naar de services.

    Return:
        Een dictionary van de poorten met de naam van de service die op de poort draait.
        Als er geen openstaande poorten gevonden worden, wordt er een lege dictionary geretourneerd.
    """
    nm = nmap.PortScanner()                                                                 #Maak een instantie van Nmap portscanner en wijs variabel nm toe.
    nm.scan(hosts=ip_address, arguments='-sS -sV --version-all')                            #Start scan met IP-adres. -sS = SYN-scan, -sV = Versie detectie, --version-all = zoveel mogelijk versie info verzamelen, sla deze results op in nm.
    services = {}                                                                           #Maak lege dictionary.
    for host in nm.all_hosts():                                                             #Loop door alle host(s) in nmap scan resultaten.
        for port in nm[host]['tcp']:                                                        #Loop over alle poorten van het TCP-protocol die draaien bij de host.
            if nm[host]['tcp'][port]['state'] == 'open':                                    
                services[port] = nm[host]['tcp'][port]['name']                              #Als de status van de poort open is word de poort + naam van de service toegevoegd aan de services dictionary.
    return services

def detect_os(ip_address):
    """
    Detecteer het besturingssysteem van een host van het opgegeven IP-Adres.

    Paramter:
        ip_address(str) : Het IP-Adres van de host.

    Return:
        String: De naam van het besturingssysteem als deze is gevonden, anders wordt er none geretourneerd.
    """
    nm = nmap.PortScanner()                                                                 #Maak een instantie van Nmap portscanner en wijs variabel nm toe.
    nm.scan(hosts=ip_address, arguments='-A')                                               #Start scan op het IP-adres. -A staat voor aggresief die enkele functies activeert van nmap, waaronder versie detectie en operating system detectie.
    os_name = nm[ip_address]['osmatch'][0]['name']                                          #Zoek het OS van IP-adres met nmap en sla de naam op in os_name.
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

    choice = input("Kies een optie: \n 1. Scan Host \n 2. Scan Subnet \n Keuze: ")          #Geef gebruiker keuze uit Scan host of Scan subnet.
    if choice == '1':
        functions = (scan_host,)                                                            #Als keuze 1 wordt gemaakt wordt scan host als functie gekozen.
    elif choice == '2':
        functions = (scan_subnet,)                                                          #Als keuze 2 wordt gemaakt wordt scan subnet als functie gekozen.
    else:
        print("Ongeldige keuze, Kies 1 of 2.")                                              #Als er iets anders dan 1-2 ingevuld word geef foutmelding.
        return

    argument = input("Geef het IP adres op van de host, of het IP van de subnet: ")         #Vraag gebruiker om Ip-adres van host of subnet, geef dit IP als argument mee voor de respectievelijke gekozen functie.
    for function in functions:
        result = function(argument)                                                         #Loop door functies heen en geef bij elke functie de agrument (IP-adres) mee.
        print(result)

if __name__ == '__main__':
    main()