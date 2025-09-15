import scapy.all as scapy
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Iterable, Tuple
import random
import time
import socket
import ipaddress
try:
    import dns.resolver
    import dns.reversename
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


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

def reverse_dns_lookup(ip: str, timeout: float = 2.0, nameserver: Optional[str] = None) -> Optional[str]:
    """
    Faz DNS reverso (PTR) de um único IP.
    Retorna o hostname (sem ponto final) ou None se não houver resposta/PTR.
    - Se dnspython estiver disponível, usa-o (permite nameserver e timeout).
    - Caso contrário, usa socket.gethostbyaddr() (sem nameserver customizável).
    """
    # Valida IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None

    # Caminho com dnspython (preferencial)
    if _HAS_DNSPYTHON:
        try:
            resolver = dns.resolver.Resolver(configure=True)
            resolver.lifetime = timeout
            resolver.timeout = timeout
            if nameserver:
                resolver.nameservers = [nameserver]

            rev = dns.reversename.from_address(ip)  # usa ip6.arpa/in-addr.arpa automaticamente
            ans = resolver.resolve(rev, "PTR")
            # Pode haver múltiplos PTRs; pegamos o primeiro
            target = str(ans[0].target).rstrip(".")
            return target or None
        except Exception:
            return None

    # Fallback: socket.gethostbyaddr (usa resolvers do sistema)
    try:
        host, _aliases, _ips = socket.gethostbyaddr(ip)
        return host.rstrip(".")
    except Exception:
        return None
def reverse_dns_many(ips: List[str], timeout: float = 2.0, nameserver: Optional[str] = None, workers: int = 50) -> Dict[str, Optional[str]]:
    """
    Resolve PTR para uma lista de IPs em paralelo.
    Retorna { ip: hostname_ou_None }.
    """
    results: Dict[str, Optional[str]] = {}

    # normaliza/dedup
    uniq_ips = []
    seen = set()
    for ip in ips:
        ip = ip.strip()
        if not ip or ip in seen:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        uniq_ips.append(ip)
        seen.add(ip)

    if not uniq_ips:
        return results

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(reverse_dns_lookup, ip, timeout, nameserver): ip for ip in uniq_ips}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                results[ip] = fut.result()
            except Exception:
                results[ip] = None

    return results



def _udp_payload_for(port: int, profile: str = "none") -> Optional[bytes]:

    if profile != "smart":
        return None
    if port == 53:
        import struct
        qname = b"\x07example\x03com\x00"  
        header = struct.pack("!HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0)
        question = qname + struct.pack("!HH", 1, 1)  
        return header + question
    if port == 123:
        pkt = bytearray(48)
        pkt[0] = (0 << 6) | (4 << 3) | 3  
        return bytes(pkt)
    if port == 69:
        return b"\x00\x01" + b"test\x00" + b"netascii\x00"
    return None


def udp_port_scan(
    ip: str,
    ports: List[int],
    timeout: float = 1.5,
    batch_size: int = 128,
    inter: float = 0.002,
    retries: int = 1,
    payload_profile: str = "none",
) -> Dict[str, List[int]]:
    
    state: Dict[int, str] = {p: "unknown" for p in ports}

    def _classify_icmp(code: int) -> str:
        if code == 3:
            return "closed"
        if code in (1, 2, 9, 10, 13):  
            return "filtered"
        return "filtered"

    pending = set(ports)

    for attempt in range(retries + 1):
        if not pending:
            break

        this_batch = sorted(list(pending))[:batch_size]
        pkts = []
        sent_map: Dict[Tuple[str, int, int], int] = {}  
        for p in this_batch:
            sport = random.randint(49152, 65535)
            payload = _udp_payload_for(p, payload_profile)
            layer = scapy.IP(dst=ip) / scapy.UDP(sport=sport, dport=p)
            if payload is not None:
                layer = layer / scapy.Raw(load=payload)
            pkts.append(layer)
            sent_map[(ip, sport, p)] = p

        ans, unans = scapy.sr(pkts, timeout=timeout, verbose=False, inter=inter)

        for sent, recv in ans:
            dport = sent[scapy.UDP].dport
            if recv.haslayer(scapy.ICMP) and recv[scapy.ICMP].type == 3:
                code = int(recv[scapy.ICMP].code)
                state[dport] = _classify_icmp(code)
                if dport in pending:
                    pending.remove(dport)
                continue

            if recv.haslayer(scapy.UDP):
                state[dport] = "open"
                if dport in pending:
                    pending.remove(dport)
                continue

            state[dport] = "filtered"
            pending.discard(dport)

        pending = {p for p in pending if state[p] == "unknown"}

    for p in ports:
        if state[p] == "unknown":
            state[p] = "open|filtered"

    out: Dict[str, List[int]] = {"open": [], "closed": [], "filtered": [], "open|filtered": []}
    for p, s in state.items():
        out[s].append(p)
    for k in out:
        out[k].sort()
    return out







