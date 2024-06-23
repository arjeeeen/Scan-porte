from colorama import Fore, Style, init
init(autoreset=True)

special_header = f"""{Fore.YELLOW}
/* ╔──────────────────────────────────────────────────╗ */
/* │ ____                                     _       │ */
/* │/ ___|  ___ __ _ _ __    _ __   ___  _ __| |_ ___ │ */
/* │\___ \ / __/ _` | '_ \  | '_ \ / _ \| '__| __/ _ \│ */
/* │ ___) | (_| (_| | | | | | |_) | (_) | |  | ||  __/│ */
/* │|____/ \___\__,_|_| |_| | .__/ \___/|_|   \__\___|│ */
/* │                        |_|                       │ */
/* ╚──────────────────────────────────────────────────╝ */
{Style.RESET_ALL}"""

print(special_header)

import colorama
from colorama import Back
import netifaces
import ipaddress
import socket
from scapy.layers.l2 import ARP
from scapy.all import Ether, srp
from tqdm import tqdm
import keyboard

init(autoreset=True)
colorama.init(autoreset=True)

def on_keyboard_event(event):
    if event.name == 'esc':
        global return_menu
        return_menu = False

keyboard.hook(on_keyboard_event)

def validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def return_to_menu():
    try:
        choice = input(f"\n{Fore.MAGENTA}Vuoi tornare al menu principale? ({Fore.GREEN}Si{Fore.MAGENTA}/{Fore.RED}No{Fore.MAGENTA}):{Style.RESET_ALL} ")
        if choice.lower() == "si" or choice == "":
            return True
        elif choice.lower() == "no":
            return False
        else:
            print(f"{Fore.RED}Scelta non valida. Riprova.")
            return return_to_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Interruzione rilevata, no, non esci da qui{Style.RESET_ALL} ")
        return return_to_menu()

def get_default_gateway():
    gateways = netifaces.gateways()
    default_gateway = gateways.get('default', {})
    if default_gateway:
        return default_gateway[netifaces.AF_INET][0]
    return None

def get_ip_range(gateway_ip):
    octets = gateway_ip.split('.')
    return '.'.join(octets[:3]) + '.1/24'

def scan_network(ip_range, retries=3, timeout=2):
    print(f"Scanning network: {ip_range}")

    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    all_devices = set()

    progress_bar = tqdm(range(retries), desc="Scanning Network", unit="scan", leave=False)
    for _ in progress_bar:
        result = srp(packet, timeout=timeout, verbose=0)[0]
        for sent, received in result:
            all_devices.add((received.psrc, received.hwsrc))

    devices = [{'ip': ip, 'mac': mac} for ip, mac in all_devices]
    return devices

def check_open_ports(ip_address, ports=[]):
    open_ports = []
    num_ports = len(ports)
    
    for idx, port in enumerate(ports, 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip_address, port))
            if result == 0:
                open_ports.append(port)
                port_status = f"{Fore.GREEN}Porta {port} aperta{Style.RESET_ALL}"
            else:
                port_status = f"{Fore.RED}Porta {port} chiusa{Style.RESET_ALL}"
            tqdm.write(f"Scansione {idx}/{num_ports} ({idx / num_ports * 100:.2f}%): {port_status}", end='\r')
            s.close()
        except Exception as e:
            tqdm.write(f"Errore durante il controllo della porta {port}: {e}")
    
    tqdm.write("Scansione completata!")
    return open_ports

def check_specific_port(ip_address, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip_address, port))
        s.close()
        
        if result == 0:
            return True
        else:
            return False
    except Exception as e:
        print(f"Errore durante il controllo della porta {port}: {e}")
        return False

def check_specific_port_menu():
    while True:
        try:
            ip_to_scan = input(f"\nInserisci l'indirizzo {Fore.YELLOW}IP{Style.RESET_ALL} da controllare: ")
        
            if validate_ip(ip_to_scan):
                break
            else:
                print(f"{Fore.RED}Indirizzo IP non valido. Riprova.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Interruzione rilevata, no, non esci da qui{Style.RESET_ALL}")
            continue
    
    port_to_check = int(input(f"Inserisci la {Fore.YELLOW}porta{Style.RESET_ALL} da controllare: "))
    
    result = check_specific_port(ip_to_scan, port_to_check)
    
    if result:
        print(f"La porta {Fore.YELLOW}{port_to_check}{Style.RESET_ALL} su {Fore.YELLOW}{ip_to_scan}{Style.RESET_ALL} è {Fore.GREEN}aperta{Style.RESET_ALL}")
    else:
        print(f"La porta {Fore.YELLOW}{port_to_check}{Style.RESET_ALL} su {Fore.YELLOW}{ip_to_scan}{Style.RESET_ALL} è {Fore.RED}chiusa{Style.RESET_ALL}")

def scan_network_menu():
    while True:
        gateway_ip = input(f"\nInserisci l'indirizzo {Fore.YELLOW}IP{Style.RESET_ALL} del {Fore.YELLOW}gateway{Style.RESET_ALL} (premi {Fore.GREEN}INVIO{Style.RESET_ALL} per cercare il gateway di default): ")

        if not gateway_ip:
            gateway_ip = get_default_gateway()
            if not gateway_ip:
                print(f"{Fore.RED}Impossibile determinare il gateway di default.")
                return
            print(f"Gateway di default trovato: {Fore.GREEN}{gateway_ip}{Style.RESET_ALL}")
            break
        else:
            if validate_ip(gateway_ip):
                break
            else:
                print(f"{Fore.RED}{gateway_ip} non è un indirizzo IPv4 valido{Style.RESET_ALL}")

    ip_range = get_ip_range(gateway_ip)
    devices = scan_network(ip_range)

    if devices:
        print(f"\n{Fore.CYAN}Dispositivi trovati nella rete:{Style.RESET_ALL}")
        for idx, device in enumerate(devices, start=1):
            print(f"{Fore.YELLOW}{idx}. IP: {device['ip']}, MAC: {device['mac']}")
        
        print(f"\n{Fore.CYAN}Totale dispositivi trovati: {len(devices)}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Nessun dispositivo trovato nella rete{Style.RESET_ALL}")

def main():
    try:
        print(f"{Fore.MAGENTA}Ciao, benvenuto nello script per {Fore.YELLOW}scansionare{Fore.MAGENTA} la rete e cercare {Fore.YELLOW}porte{Fore.MAGENTA} aperte{Style.RESET_ALL}\n")
        
        global return_menu
        return_menu = True
        
        while return_menu:
            print(f"1. {Fore.GREEN}Scansiona{Style.RESET_ALL} la rete")
            print(f"2. Controlla quali {Fore.GREEN}porte{Style.RESET_ALL} sono aperte su un {Fore.YELLOW}IP{Style.RESET_ALL}")
            print(f"3. Controlla se una specifica {Fore.GREEN}porta{Style.RESET_ALL} è aperta su un {Fore.YELLOW}IP{Style.RESET_ALL}")
            
            choice = input(f"{Fore.MAGENTA}Seleziona un'opzione: {Style.RESET_ALL}")
            print(f"\n{Fore.MAGENTA}Tool{Style.RESET_ALL} creato da {Fore.MAGENTA}Arjen{Style.RESET_ALL}! / {Back.MAGENTA}www.mondohacking.com{Style.RESET_ALL}")
    
            if choice == "1":
                scan_network_menu()
            elif choice == "2":
                while True:
                    ip_to_scan = input(f"\nInserisci l'indirizzo {Fore.YELLOW}IP{Style.RESET_ALL} da controllare: ")
                    if validate_ip(ip_to_scan):
                        break
                    else:
                        print(f"{Fore.RED}Indirizzo IP non valido. Riprova.{Style.RESET_ALL}")
                    
                ports_to_check = range(1, 1025)
                open_ports = check_open_ports(ip_to_scan, ports_to_check)
    
                if open_ports:
                    print(f"Ho trovato queste {Fore.GREEN}porte aperte{Style.RESET_ALL}, controlla:")
                    for port in open_ports:
                        print(f"Porta {port} {Fore.GREEN}aperta{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Nessuna porta aperta trovata{Style.RESET_ALL}")
            elif choice == "3":
                check_specific_port_menu()
            else:
                print(f"{Fore.RED}Scelta non valida. Riprova{Style.RESET_ALL}")
            
            return_menu = return_to_menu()
    except KeyboardInterrupt:
        print("\nCiao, a presto!")


if __name__ == "__main__":
    main()