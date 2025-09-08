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