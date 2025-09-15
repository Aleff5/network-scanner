# NetScan — Scanner de rede em Python

NetScan é uma ferramenta de linha de comando (CLI), escrita em Python, para demonstrar **conceitos práticos de redes**:

- Descoberta de hosts via **ARP** (`discover`)
- **TCP port scan** em um host e **multi-host** (`tcpscan`, `tcpscan-many`)
- **UDP port scan** com classificação (open / closed / filtered / open|filtered) (`udpscan`)
- **DNS reverso (PTR)** de IP único, lista ou CIDR (`rdns`)
- Descoberta do **IP local** (principal por rota) e listagem de todos os IPv4 (`myip`)
- **Exportação** de resultados em **JSON/CSV** (`--out` / `-o`)

> ⚠️ **Aviso legal:** Use esta ferramenta apenas em redes e equipamentos nos quais você tenha **autorização explícita**. Varreduras podem ser detectadas e bloqueadas por sistemas de detecção de intrusão (IDS/IPS) e firewalls.

---

## Sumário

- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Como executar](#como-executar)
- [Comandos](#comandos)
  - [Descoberta de hosts (ARP)](#1-descoberta-de-hosts-arp)
  - [TCP port scan (SYN)](#2-tcp-port-scan-syn)
  - [TCP port scan (multi-host)](#3-tcp-port-scan-em-vários-hosts)
  - [UDP port scan](#4-udp-port-scan)
  - [DNS reverso (PTR)](#5-dns-reverso-ptr)
  - [IP da máquina (local)](#6-ip-da-máquina-local)
- [Exportação](#exportação)
- [Dicas & Solução de Problemas](#dicas--solução-de-problemas)
- [Como funciona (resumo técnico)](#como-funciona-resumo-técnico)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Arquivos úteis](#arquivos-úteis)
- [Licença](#licença)
- [Roadmap (ideias futuras)](#roadmap-ideias-futuras)

---

## Requisitos

- **Python**: 3.10+ (testado em 3.10)
- **Sistemas**: Windows 10/11, Linux, macOS
- **Dependências Python**:
  - `scapy` — envio/captura de pacotes
  - `typer` — CLI
  - `rich` — tabelas e cores no terminal
  - `typing_extensions`
  - `dnspython` — *opcional* (melhora `rdns` com `--ns` e controle de timeout)

**Permissões / Drivers**

- **Windows**: Instale **Npcap** (habilite o modo de compatibilidade com WinPcap) e execute o terminal como **Administrador**.
- **Linux/macOS**: Para ARP e envio de pacotes raw, execute com **sudo**.
- **Firewalls**: Podem bloquear ou filtrar respostas, especialmente em scans UDP.

---

## Instalação

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/](https://github.com/)<seu-usuario>/network-scanner.git
    cd network-scanner
    ```

2.  **Crie e ative um ambiente virtual:**
    ```bash
    # Crie o ambiente
    python -m venv venv

    # Ative no Windows
    venv\Scripts\activate

    # Ative no Linux/macOS
    # source venv/bin/activate
    ```

3.  **Instale as dependências:**
    ```bash
    pip install -r requirements.txt
    ```

---

## Como executar

Navegue até a pasta `src/` e use o Python para executar o `main.py`.

```bash
# Exibe a ajuda geral
python main.py --help

# Exibe a ajuda de um subcomando específico
python main.py discover --help
```
---
## Comandos

### 1) Descoberta de hosts (ARP)

Descobre IPs e MACs ativos em um intervalo de rede (CIDR) usando broadcast ARP.

**Uso:**
```bash
python main.py discover 192.168.0.0/24
```
**Opções:**

* ``-m``, ``--mac``: Consulta o fabricante do dispositivo (OUI) com base no MAC address.

* ``-o``, ``--out``: Exporta o resultado para um arquivo .json ou .csv.

Exemplos:
```bash
# Scan básico
python main.py discover 192.168.0.0/24

# Incluindo fabricante e exportando para JSON
python main.py discover 192.168.0.0/24 -m -o hosts.json
```
---
### 2) TCP port scan (SYN)

Realiza um scan do tipo SYN (half-open) em um único host. Portas abertas respondem com SYN/ACK (o scanner envia RST para encerrar).

**Uso:**
```bash
python main.py tcpscan 192.168.0.113 -p 1-1024 -t 0.7

```

**Opções:**

* ``-p``, ``--ports``: Lista ou intervalo de portas (ex.: 22,80,443 ou 1-1024).

* ``-t``, ``--timeout``: Timeout por tentativa (segundos).

* ``-o``, ``--out``: Exporta o resultado para .json ou .csv.

**Exemplos:**
```bash
# Portas específicas
python main.py tcpscan 192.168.0.113 -p 22,80,443 -t 0.5

# Intervalo completo e exportação
python main.py tcpscan 10.0.0.5 -p 1-1024 -o tcp_10_0_0_5.csv
```
### 3) TCP port scan em vários hosts

Executa TCP scan em uma lista de IPs ou em um intervalo CIDR.

**Uso:**
```bash
# Lista de IPs
python main.py tcpscan-many 192.168.0.10,192.168.0.20 -p 135,139,445
```


**Opções:**

* hosts (posicional): IPs separados por vírgula (ex.: ip1,ip2,...) ou um CIDR (ex.: 192.168.0.0/24).

* ``-p``, ``--ports``: Lista/intervalo de portas.

* ``-t``, ``--timeout``: Timeout por tentativa (segundos).

* ``-o``, ``--out``: Exporta o resultado para .json ou .csv.

**Exemplos:**
```bash
# Em uma lista de IPs
python main.py tcpscan-many 192.168.0.10,192.168.0.20 -p 135,139,445

# Em um CIDR com exportação
python main.py tcpscan-many 192.168.0.0/29 -p 1-1024 -t 0.8 -o tcp_many.json
```

### 4) UDP port scan

Como UDP não tem handshake, a classificação é heurística:

* ``open``: houve resposta UDP (ou do protocolo esperado).

* ``closed``: recebeu ICMP Type 3 Code 3 (Port Unreachable).

* ``filtered``: recebeu ICMP administrativamente proibido (outros codes do Type 3) ou outro filtro explícito.

* ``open|filtered``: sem resposta; pode estar aberto e silencioso ou filtrado.


**Uso:**
```bash
python main.py udpscan 192.168.0.113 -p 53,123,161,500,1900 --payloads smart -t 1.5 --retries 1
```


**Opções:**

* ``-p``, ``--ports``: Lista ou intervalo de portas (ex.: 53,123,161 ou 1-1024).

* ``-t``, ``--timeout``: Tempo de espera por lote (segundos).

* ``--retries``: Reenvios para portas sem resposta.

* ``--batch``: Tamanho do lote de envio (padrão: 128).

* ``--inter``: Intervalo entre pacotes (segundos) para evitar bursts.

* ``--payloads``: none (pacote vazio) ou smart (pequenos payloads para provocar respostas — DNS/NTP/TFTP).

* ``-o``, ``--out``: Exporta o resultado para .json ou .csv.

**Exemplos:**
```bash
# UDP com payloads para provocar respostas (DNS/NTP/TFTP)
python main.py udpscan 192.168.0.113 -p 53,123,69,161 --payloads smart -t 2 --retries 1

# Varredura ampla (ajustando taxa e exportando)
python main.py udpscan 192.168.0.113 -p 1-1024 --batch 128 --inter 0.003 -t 1.5 -o udp_113.json
```

### 5) DNS Reverso (PTR)

Resolve o hostname associado a um IP (ou vários IPs/CIDR). Com dnspython, é possível especificar nameserver e timeout.

**Uso:**
```bash
python main.py rdns 192.168.0.113,192.168.0.1
```


**Opções:**

* targets (posicional): IP único, lista ip1,ip2,... ou um CIDR.

* ``--ns``: Nameserver para consulta (ex.: 8.8.8.8).

* ``-t``, ``--timeout``: Timeout por consulta (segundos).

* ``-w``, ``--workers``: Paralelismo máximo das consultas.

* ``-o``, ``--out``: Exporta o resultado para .json ou .csv.

**Exemplos:**
```bash
# Lista de IPs
python main.py rdns 192.168.0.113,192.168.0.1

# Intervalo CIDR usando o DNS do roteador e exportando
python main.py rdns 192.168.0.0/30 --ns 192.168.0.1 -t 2 -w 50 -o rdns.csv
```
>__Nota: Sem a biblioteca dnspython, o comando usa socket.gethostbyaddr() (DNS do sistema) e ignora --ns.__

### 6) IP da máquina (local)

Mostra o IP “principal” (usado pela rota de saída) e pode listar todos os IPv4 locais.

**Uso:**
```bash
python main.py myip
```


**Opções:**

* `--all`, ``-a``: Lista todos os IPv4 locais.

* ``--probe``: Host de referência para a rota (padrão: 8.8.8.8).

* ``-o``, ``--out``: Exporta o resultado para .json ou .csv.

**Exemplos:** 
```bash
# IP principal (rota até 8.8.8.8)
python main.py myip

# Listar todos os IPv4 locais e exportar
python main.py myip --all -o myips.json

# Alterar o host de referência
python main.py myip --probe 1.1.1.1
```
---

## Exportação
Quase todos os comandos suportam a flag -o ou --out para exportar os resultados para:

* json: Um array de objetos.

* csv: Um arquivo de valores separados por vírgula com cabeçalhos.

**Exemplos:**
```bash
python main.py discover 192.168.0.0/24 -m -o hosts.json
python main.py tcpscan 192.168.0.113 -p 1-1024 -o scan.csv
```
---
## Dicas & Solução de Problemas
* Permissões: Se os scans ARP/TCP/UDP não retornam resultados, verifique se você está executando como Administrador (Windows) ou com sudo (Linux/macOS).

* Npcap (Windows): É crucial instalar este driver e habilitar o "WinPcap API-compatible Mode" durante a instalação.

* Firewall/Antivírus: Podem bloquear pacotes e interferir nos resultados, especialmente causando o estado open|filtered no UDP.

* Wi-Fi/VMs: Em modo NAT, os scans podem não alcançar a rede externa. Para escanear a rede local a partir de uma VM, prefira o modo bridge.

* Desempenho: Ajuste --inter e --batch (UDP) e --timeout (TCP/UDP) conforme a latência e a capacidade do host e da rede.
---

## Como funciona (resumo técnico)
* ARP: Envia um pacote Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=CIDR) e coleta as respostas, mapeando o IP de origem (psrc) ao MAC de origem (hwsrc).

* TCP (SYN scan): Para cada porta, envia um pacote TCP com a flag SYN. Se a resposta for SYN/ACK, a porta é considerada open (e um RST é enviado para fechar a conexão). Ausência de resposta ou um RST indica que a porta não está aberta.

* UDP: Envia datagramas UDP. Um ICMP Port Unreachable (type 3, code 3) indica uma porta closed. Uma resposta UDP indica open. Outras mensagens ICMP de erro indicam filtered. Ausência de resposta resulta em open|filtered.

* RDNS (PTR): Com dnspython, constrói a consulta no formato in-addr.arpa e a envia. Sem dnspython, utiliza a chamada de sistema gethostbyaddr().
---

## Estrutura do projeto
```bash
network-scanner/
├── requirements.txt
├── src/
│   ├── main.py        # Lógica da CLI (Typer)
│   ├── scanner.py     # Funções de scan (ARP/TCP/UDP/RDNS)
│   └── utils.py       # Utilitários (exportação, IP local, etc.)
└── README.md
```
---
## Arquivos úteis
* requirements.txt:
```bash 

scapy>=2.5
typer>=0.12
rich>=13.7
typing_extensions>=4.10
dnspython>=2.6

```
* .gitignore:
```bash
# Python
__pycache__/
*.py[cod]
*.pyo
*.pyd
*.egg-info/
.venv/
venv/
.env

# OS
.DS_Store
Thumbs.db

# Saídas / dados
*.pcap
*.csv
*.json

# IDE
.vscode/
.idea/
```
---
## Licença
Este projeto é distribuído sob a licença MIT. Crie um arquivo ``LICENSE`` na raiz do projeto com o texto da licença