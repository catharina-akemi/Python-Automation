import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

#verificar se uma porta especifica esta aberta em um ip
def verifica_porta(ip, porta):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1) #tempo limite para conexao
            resultado = s.connect_ex((ip, porta))
            if resultado == 0:
                print(f"[+] Porta {porta} aberta em {ip}")
            else:
                print(f"[*] Porta {porta} fechada em {ip}")
    except Exception as e:
        print(f"[-] Erro ao verificar porta {porta}: {e}")

#realiza o scan das portas de um ip
def scan_alvo(ip, portas):
    print(f"[*] Iniciando o scan em {ip} nas portas: {portas}")
    with ThreadPoolExecutor(max_workers=10) as executor:
        for porta in portas:
            executor.submit(verifica_porta, ip, porta)

def main():
    #menu principal do script
    print("----Scan de Portas----")

    #entrada do usuario de ip ou faixa de ips
    alvo = input("Digite o IP ou a rede (ex.: 192.168.0.1 ou 192.168.0.0/24): ")

    #validacao do ip
    try:
        if '/' in alvo:
            ips = list(ipaddress.IPv4Network(alvo, strict=False))
        else:
            ips = [ipaddress.IPv4Address(alvo)]
    except ValueError:
        print('[-] IP ou rede invalida!')
        return
    
    #entrada do usuario para portas
    portas_input = input("Digite as portas a serem verificadas (ex.: 22, 80, 443 ou 1-1024): ")
    portas = []
    if '-' in portas_input:
        inicio, fim = map(int, portas_input.split('-'))
        portas = list(range(inicio, fim + 1))
    else:
        portas = [int(p.strip()) for p in portas_input.split(',')]
    
    #comecar o scan
    for ip in ips:
        scan_alvo(str(ip), portas)
if __name__== "__main__":
    main()

