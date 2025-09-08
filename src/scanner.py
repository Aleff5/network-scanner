# scanner.py
import scapy.all as scapy
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

def discover_hosts(cidr: str) -> List[Dict[str, str]]:

    try:
        arpRequest = scapy.ARP(pdst=cidr)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arpRequestBroadcast = broadcast / arpRequest

        response = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]

        clients = []
        for elemento in response:
            client_dict = {"ip": elemento[1].psrc, "mac": elemento[1].hwsrc}
            clients.append(client_dict)
        
        return clients

    except Exception as e:
        print(f"[bold red]Erro ao escanear a rede: {e}[/bold red]")
        print("[bold yellow]Dica: No Linux/macOS, tente rodar com 'sudo'. No Windows, use um terminal como Administrador.[/bold yellow]")
        return []

# Placeholder para a próxima funcionalidade
def tcp_port_scan(ip: str, ports: List[int], timeout: float = 0.5) -> Dict[str, Any]:

    print(f"\n[bold blue]Funcionalidade de Port Scan para {ip} nas portas {ports} ainda não implementada.[/bold blue]")
    return {"ip": ip, "open_ports": []}