# main.py
import ipaddress
import typer
from rich.console import Console
from rich.table import Table
from typing_extensions import Annotated
import scanner
import utils

app = typer.Typer(help="NetScan: Uma ferramenta de scanner de rede em Python.")
console = Console()

# --- helper reutilizável ---
def _parse_ports(ports_str: str):
    if "-" in ports_str:
        try:
            start, end = ports_str.split("-", 1)
            return list(range(int(start), int(end) + 1))
        except ValueError:
            console.print("[bold red]Erro: range de portas inválido. Use 'inicio-fim'.[/bold red]")
            raise typer.Exit()
    else:
        try:
            return [int(p.strip()) for p in ports_str.split(",") if p.strip()]
        except ValueError:
            console.print("[bold red]Erro: lista de portas inválida. Use '22,80,443'.[/bold red]")
            raise typer.Exit()

@app.command(help="Descobre hosts ativos na rede (ex: 192.168.1.0/24).")
def discover(cidr: Annotated[str, typer.Argument(help="O endereço da rede no formato CIDR.")] ):
    console.print(f"[bold cyan]Iniciando descoberta de hosts em {cidr}...[/bold cyan]")
    found_hosts = scanner.discover_hosts(cidr)
    if not found_hosts:
        console.print("[bold yellow]Nenhum host ativo encontrado ou ocorreu um erro.[/bold yellow]")
        raise typer.Exit()

    table = Table(title="Hosts Ativos Encontrados")
    table.add_column("IP", justify="left", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    table.add_column("Fabricante", style="green")

    with console.status("[bold green]Buscando fabricantes...", spinner="dots"):
        for host in found_hosts:
            vendor = utils.get_mac_vendor(host['mac'])
            table.add_row(host['ip'], host['mac'], vendor)

    console.print(table)

@app.command(help="Escaneia portas TCP abertas de um host.")
def portscan(
    host: Annotated[str, typer.Argument(help="O IP do host para escanear.")],
    ports: Annotated[str, typer.Option("--ports", "-p", help="Portas (ex: 22,80,443 ou 1-1024).")] = "1-1024",
    timeout: Annotated[float, typer.Option("--timeout", "-t", help="Timeout em segundos.")] = 0.5,
):
    port_list = _parse_ports(ports)

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

# ---------- NOVO COMANDO: vários hosts ----------
@app.command(name="portscan-many", help="Escaneia portas TCP abertas em vários hosts (lista de IPs ou um CIDR).")
def portscan_many(
    hosts: Annotated[str, typer.Argument(help="IPs separados por vírgula (ex: 192.168.0.10,192.168.0.20) OU um CIDR (ex: 192.168.0.0/24).")],
    ports: Annotated[str, typer.Option("--ports", "-p", help="Portas (ex: 135,139,445 ou 1-1024).")] = "1-1024",
    timeout: Annotated[float, typer.Option("--timeout", "-t", help="Timeout em segundos.")] = 2.0,
):
    port_list = _parse_ports(ports)

    # Detecta se é CIDR ou lista de IPs
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

if __name__ == "__main__":
    app()
