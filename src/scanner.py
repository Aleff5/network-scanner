# scanner.py
import scapy.all as scapy
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import random
import time

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
def scan_port(ip: str, port: int, timeout: float) -> Optional[int]:

    src_port = scapy.RandShort()

    syn = scapy.IP(dst=ip) / scapy.TCP(sport=src_port, dport=port, flags="S")
    response = scapy.sr1(syn, timeout=timeout, verbose=False)

    if response is None:
        return None

    if response.haslayer(scapy.TCP):
        tcp = response.getlayer(scapy.TCP)
        flags = int(tcp.flags)

        if (flags & 0x12) == 0x12: 
            scapy.send(
                scapy.IP(dst=ip) / scapy.TCP(sport=src_port, dport=port, flags="R", ack=tcp.seq + 1),
                verbose=False
            )
            return port

    return None
def tcp_port_scan(ip: str, ports: List[int], timeout: float = 1.5,
                  batch_size: int = 128, inter: float = 0.003) -> List[int]:
    open_ports: List[int] = []

    for i in range(0, len(ports), batch_size):
        chunk = ports[i:i+batch_size]

        pkts = [
            scapy.IP(dst=ip) / scapy.TCP(sport=random.randint(49152, 65535),
                                         dport=p, flags="S")
            for p in chunk
        ]

        ans, _ = scapy.sr(pkts, timeout=timeout, verbose=False, inter=inter)

        for sent, recv in ans:
            if recv.haslayer(scapy.TCP):
                tcp = recv[scapy.TCP]
                if (int(tcp.flags) & 0x12) == 0x12:  
                    dport = sent[scapy.TCP].dport
                    open_ports.append(dport)
                    scapy.send(
                        scapy.IP(dst=ip) / scapy.TCP(
                            sport=sent[scapy.TCP].sport,
                            dport=dport,
                            flags="R",
                            ack=tcp.seq + 1
                        ),
                        verbose=False
                    )
        time.sleep(0.02)

    return sorted(set(open_ports))
def tcp_port_scan_many(hosts, ports, timeout=0.8):

    pkts = []
    for ip in hosts:
        for p in ports:
            pkts.append(scapy.IP(dst=ip)/scapy.TCP(sport=random.randint(49152,65535), dport=p, flags="S"))
    ans, _ = scapy.sr(pkts, timeout=timeout, verbose=False)

    results = {ip: [] for ip in hosts}
    for sent, recv in ans:
        if recv.haslayer(scapy.TCP):
            tcp = recv[scapy.TCP]
            if (int(tcp.flags) & 0x12) == 0x12:
                ip = sent[scapy.IP].dst
                dport = sent[scapy.TCP].dport
                results[ip].append(dport)
                scapy.send(scapy.IP(dst=ip)/scapy.TCP(sport=sent[scapy.TCP].sport, dport=dport, flags="R", ack=tcp.seq+1),
                           verbose=False)
    for ip in results:
        results[ip] = sorted(set(results[ip]))
    return results
