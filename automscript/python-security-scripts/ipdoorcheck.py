import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

#verifies if a specific door is opened in an IP
def verify_door(ip, door):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1) #time limit for conection
            result = s.connect_ex((ip, door))
            if result == 0:
                print(f"[+] Door {door} open in {ip}")
            else:
                print(f"[*] Door {door} closed in {ip}")
    except Exception as e:
        print(f"[-] Error verifying door {door}: {e}")

#scan IP doors
def scan_target(ip, doors):
    verify_doors = []
    print(f"[*] Starting scan in {ip} doors: {doors}")
    with ThreadPoolExecutor(max_workers=10) as executor:
        for door in doors:
            executor.submit(verify_door, ip, door)

def main():
    #script main menu
    print("----Doors Scan----")

    #user entry of IP
    target = input("Type IP or Network (ex.: 192.168.0.1 ou 192.168.0.0/24): ")

    #IP validation
    try:
        if '/' in target:
            ips = list(ipaddress.IPv4Network(target, strict=False))
        else:
            ips = [ipaddress.IPv4Address(target)]
    except ValueError:
        print('[-] IP ou Network invalid!')
        return
    
    #user entry to doors
    doors_input = input("Type doors to be verified (ex.: 22, 80, 443 ou 1-1024): ")
    doors = []
    if '-' in doors_input:
        start, end = map(int, doors_input.split('-'))
        doors = list(range(start, end + 1))
    else:
        doors = [int(p.strip()) for p in doors_input.split(',')]
    
    #start scan
    for ip in ips:
        scan_target(str(ip), doors)
if __name__== "__main__":
    main()
