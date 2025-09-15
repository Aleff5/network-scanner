import ipaddress
import typer
from rich.console import Console
from rich.table import Table
from typing_extensions import Annotated
from typing import Optional, List, Dict, Any

import scanner
import utils

app = typer.Typer(help="NetScan: Uma ferramenta de scanner de rede em Python.")
console = Console()


def _parse_ports(ports_str: str) -> List[int]:
    if "-" in ports_str:
        start, end = ports_str.split("-", 1)
        return list(range(int(start), int(end) + 1))
    return [int(p.strip()) for p in ports_str.split(",") if p.strip()]

@app.command(help="Descobre hosts ativos na rede (ex: 192.168.1.0/24).")
def discover(
    cidr: Annotated[str, typer.Argument(help="O endereço da rede no formato CIDR.")],
    mac_vendor: Annotated[bool, typer.Option("--mac", "-m", help="Consultar fabricante (OUI) dos MACs.")] = False,
    out: Annotated[Optional[str], typer.Option("--out", "-o", help="Exportar resultados para .json ou .csv.")] = None,
):
    console.print(f"[bold cyan]Iniciando descoberta de hosts em {cidr}...[/bold cyan]")
    found_hosts = scanner.discover_hosts(cidr)

    if not found_hosts:
        console.print("[bold yellow]Nenhum host ativo encontrado ou ocorreu um erro.[/bold yellow]")
        raise typer.Exit()

    title = "Hosts Ativos Encontrados"
    table = Table(title=title)
    table.add_column("IP", justify="left", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    if mac_vendor:
        table.add_column("Fabricante", style="green")

    rows: List[Dict[str, Any]] = []

    status_msg = "[bold green]Buscando fabricantes...[/bold green]" if mac_vendor else "[bold green]Montando lista...[/bold green]"
    with console.status(status_msg, spinner="dots"):
        for host in found_hosts:
            ip = host["ip"]
            mac = host["mac"]
            if mac_vendor:
                vendor = utils.get_mac_vendor(mac)
                table.add_row(ip, mac, vendor)
                rows.append({"ip": ip, "mac": mac, "vendor": vendor})
            else:
                table.add_row(ip, mac)
                rows.append({"ip": ip, "mac": mac})

    console.print(table)

    if out:
        utils.export_table(rows, out)
        console.print(f"[bold green]Exportado para[/bold green] {out}")

@app.command(help="Escaneia portas TCP abertas de um host.")
def tcpscan(
    host: Annotated[str, typer.Argument(help="O IP do host para escanear.")],
    ports: Annotated[str, typer.Option("--ports", "-p", help="Portas para escanear (ex: 22,80,443 ou 1-1024).")] = "1-1024",
    timeout: Annotated[float, typer.Option("--timeout", "-t", help="Timeout de resposta em segundos.")] = 0.5,
    out: Annotated[Optional[str], typer.Option("--out", "-o", help="Exportar resultados para .json ou .csv.")] = None,
):
    try:
        port_list = _parse_ports(ports)
    except Exception:
        console.print("[bold red]Erro: Formato de portas inválido. Use '22,80,443' ou 'inicio-fim'.[/bold red]")
        raise typer.Exit()

    with console.status(f"[bold green]Escaneando {len(port_list)} portas em {host}...", spinner="earth"):
        open_ports = scanner.tcp_port_scan(host, port_list, timeout)

    if open_ports:
        table = Table(title=f"Portas Abertas em {host}")
        table.add_column("Porta", style="cyan")
        table.add_column("Estado", style="green")
        for port in open_ports:
            table.add_row(str(port), "Aberta")
        console.print(table)
    else:
        console.print(f"[bold yellow]Nenhuma porta aberta encontrada em {host}.[/bold yellow]")

    if out:
        utils.export_table([{"ip": host, "open_tcp": open_ports}], out)
        console.print(f"[bold green]Exportado para[/bold green] {out}")

@app.command(name="tcpscan-many", help="Escaneia portas TCP abertas em vários hosts (lista de IPs ou um CIDR).")
def tcpscan_many(
    hosts: Annotated[str, typer.Argument(help="IPs separados por vírgula (ex: 192.168.0.10,192.168.0.20) OU um CIDR (ex: 192.168.0.0/24).")],
    ports: Annotated[str, typer.Option("--ports", "-p", help="Portas (ex: 135,139,445 ou 1-1024).")] = "1-1024",
    timeout: Annotated[float, typer.Option("--timeout", "-t", help="Timeout em segundos.")] = 0.8,
    out: Annotated[Optional[str], typer.Option("--out", "-o", help="Exportar resultados para .json ou .csv.")] = None,
):
    try:
        port_list = _parse_ports(ports)
    except Exception:
        console.print("[bold red]Erro: Formato de portas inválido.[/bold red]")
        raise typer.Exit()

    # Detecta CIDR vs lista
    if "/" in hosts:
        try:
            net = ipaddress.ip_network(hosts, strict=False)
            host_list = [str(ip) for ip in net.hosts()]
        except ValueError:
            console.print("[bold red]CIDR inválido.[/bold red]")
            raise typer.Exit()
    else:
        host_list = [h.strip() for h in hosts.split(",") if h.strip()]

    if not host_list:
        console.print("[bold yellow]Nenhum host para escanear.[/bold yellow]")
        raise typer.Exit()

    with console.status(f"[bold green]Escaneando {len(port_list)} portas em {len(host_list)} hosts...", spinner="earth"):
        results = scanner.tcp_port_scan_many(host_list, port_list, timeout=timeout)

    table = Table(title="Portas Abertas por Host")
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Portas Abertas", style="green")
    for ip in host_list:
        opened = results.get(ip, [])
        table.add_row(ip, ", ".join(map(str, opened)) if opened else "—")
    console.print(table)

    if out:
        rows = [{"ip": ip, "open_tcp": results.get(ip, [])} for ip in host_list]
        utils.export_table(rows, out)
        console.print(f"[bold green]Exportado para[/bold green] {out}")

@app.command(help="DNS reverso (PTR) para IP único, lista de IPs ou um CIDR.")
def rdns(
    targets: Annotated[str, typer.Argument(help="IP único (ex: 192.168.0.10), lista separada por vírgula ou CIDR (ex: 192.168.0.0/24).")],
    nameserver: Annotated[Optional[str], typer.Option("--ns", help="Nameserver DNS para consulta (ex: 8.8.8.8).")] = None,
    timeout: Annotated[float, typer.Option("--timeout", "-t", help="Timeout por consulta (s).")] = 2.0,
    workers: Annotated[int, typer.Option("--workers", "-w", help="Máximo de consultas em paralelo.")] = 50,
    out: Annotated[Optional[str], typer.Option("--out", "-o", help="Exportar resultados para .json ou .csv.")] = None,
):
    # constrói lista de IPs a partir de IP único, lista, ou CIDR
    if "/" in targets:
        try:
            net = ipaddress.ip_network(targets, strict=False)
            host_list = [str(ip) for ip in net.hosts()]
        except ValueError:
            console.print("[bold red]CIDR inválido.[/bold red]")
            raise typer.Exit()
    else:
        host_list = [h.strip() for h in targets.split(",") if h.strip()]

    if not host_list:
        console.print("[bold yellow]Nenhum IP fornecido.[/bold yellow]")
        raise typer.Exit()

    with console.status(f"[bold green]Resolvendo PTR para {len(host_list)} IP(s)...", spinner="dots"):
        results = scanner.reverse_dns_many(host_list, timeout=timeout, nameserver=nameserver, workers=workers)

    table = Table(title="DNS Reverso (PTR)")
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Hostname", style="green")
    for ip in host_list:
        host = results.get(ip)
        table.add_row(ip, host or "—")
    console.print(table)

    if out:
        rows = [{"ip": ip, "ptr": results.get(ip)} for ip in host_list]
        utils.export_table(rows, out)
        console.print(f"[bold green]Exportado para[/bold green] {out}")

@app.command(help="Mostra o(s) IP(s) desta máquina.")
def myip(
    all: Annotated[bool, typer.Option("--all", "-a", help="Listar todos os IPv4 locais.")] = False,
    probe: Annotated[str, typer.Option("--probe", help="Host de referência para rota (default: 8.8.8.8).")] = "8.8.8.8",
    out: Annotated[Optional[str], typer.Option("--out", "-o", help="Exportar resultados para .json ou .csv.")] = None,
):
    if all:
        addrs = utils.list_local_ipv4()
        table = Table(title="IPv4 locais")
        table.add_column("IP", style="cyan")
        for ip in addrs:
            table.add_row(ip)
        console.print(table if addrs else "[bold yellow]Nenhum IPv4 local encontrado.[/bold yellow]")
        if out:
            utils.export_table([{"ip": ip} for ip in addrs], out)
            console.print(f"[bold green]Exportado para[/bold green] {out}")
    else:
        ip = utils.get_primary_ipv4(probe_host=probe)
        table = Table(title="IP principal (rota de saída)")
        table.add_column("IP", style="cyan")
        table.add_row(ip)
        console.print(table)
        if out:
            utils.export_table([{"ip": ip, "type": "primary"}], out)
            console.print(f"[bold green]Exportado para[/bold green] {out}")

@app.command(help="Escaneia portas UDP de um host (classificação: open, closed, filtered, open|filtered).")
def udpscan(
    host: Annotated[str, typer.Argument(help="O IP do host para escanear.")],
    ports: Annotated[str, typer.Option("--ports", "-p", help="Portas ex: 53,123,161 ou 1-1024.")] = "53,123,161,500,1900",
    timeout: Annotated[float, typer.Option("--timeout", "-t", help="Timeout (s).")] = 1.5,
    retries: Annotated[int, typer.Option("--retries", help="Reenvios para portas sem resposta.")] = 1,
    batch_size: Annotated[int, typer.Option("--batch", help="Tamanho do lote de envio.")] = 128,
    inter: Annotated[float, typer.Option("--inter", help="Intervalo entre pacotes (s).")] = 0.002,
    profile: Annotated[str, typer.Option("--payloads", help="Perfil de payloads UDP: none|smart")] = "none",
    out: Annotated[Optional[str], typer.Option("--out", "-o", help="Exportar .json ou .csv.")] = None,
):
    def _parse_ports(s: str) -> List[int]:
        if "-" in s:
            a, b = s.split("-", 1)
            return list(range(int(a), int(b) + 1))
        return [int(x.strip()) for x in s.split(",") if x.strip()]

    try:
        port_list = _parse_ports(ports)
    except Exception:
        console.print("[bold red]Formato de portas inválido.[/bold red]")
        raise typer.Exit()

    with console.status(f"[bold green]UDP scan em {host} ({len(port_list)} portas)...", spinner="dots"):
        res = scanner.udp_port_scan(
            host, port_list, timeout=timeout, batch_size=batch_size, inter=inter, retries=retries, payload_profile=profile
        )

    table = Table(title=f"UDP scan em {host}")
    table.add_column("Estado", style="green")
    table.add_column("Portas", style="cyan")
    for state in ["open", "closed", "filtered", "open|filtered"]:
        ports_str = ", ".join(map(str, res[state])) if res[state] else "—"
        table.add_row(state, ports_str)
    console.print(table)

    if out:
        rows = [{"ip": host, "state": state, "ports": res[state]} for state in res]
        utils.export_table(rows, out)
        console.print(f"[bold green]Exportado para[/bold green] {out}")



if __name__ == "__main__":
    app()
