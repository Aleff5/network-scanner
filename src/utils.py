import requests 

MAC_VENDOR_CACHE = {}

def get_mac_vendor(mac_address: str) -> str:

    if not mac_address:
        return "N/A"
    
    if mac_address in MAC_VENDOR_CACHE:
        return MAC_VENDOR_CACHE[mac_address]
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            vendor = response.text
            MAC_VENDOR_CACHE[mac_address] = vendor
            return vendor
        else:
            return "Fabricante não encontrado"
    except requests.RequestException:
        return "Erro: Impossível conectar à API"

# utils.py
import socket
import ipaddress
from contextlib import closing
from typing import List

def get_primary_ipv4(probe_host: str = "8.8.8.8", probe_port: int = 80) -> str:
    
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
            s.connect((probe_host, probe_port))  
            return s.getsockname()[0]
    except Exception:
        try:
            candidates = []
            hostname = socket.gethostname()
            for fam, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP):
                if fam == socket.AF_INET:
                    ip = sockaddr[0]
                    ipobj = ipaddress.ip_address(ip)
                    if not (ipobj.is_loopback or ipobj.is_link_local):
                        candidates.append(ip)
            return candidates[0] if candidates else "127.0.0.1"
        except Exception:
            return "127.0.0.1"


def list_local_ipv4() -> List[str]:

    ips = set()

    try:
        from scapy.all import get_if_list, get_if_addr  
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip and ip != "0.0.0.0" and not ip.startswith("127."):
                    ips.add(ip)
            except Exception:
                pass
    except Exception:
        pass

    if not ips:
        try:
            hostname = socket.gethostname()
            for fam, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
                if fam == socket.AF_INET:
                    ip = sockaddr[0]
                    if ip and not ip.startswith("127."):
                        ips.add(ip)
        except Exception:
            pass

    return sorted(ips)
