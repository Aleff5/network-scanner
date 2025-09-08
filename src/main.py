import typer
from rich.console import Console
from rich.table import Table
from typing_extensions import Annotated
import scanner
import utils

app = typer.Typer(help="NetScan: Uma ferramenta de scanner de rede em Python.")
console = Console()

@app.command(help="Descobre hosts ativos na rede (ex: 192.168.1.0/24).")
def discover(cidr: Annotated[str, typer.Argument(help="O endereço da rede no formato CIDR.")],):
    
    console.print(f"[bold cyan]Iniciando descoberta de hosts em {cidr}...[/bold cyan]")
    found_hosts = scanner.discover_hosts(cidr)

    if not found_hosts:
        console.print("[bold yellow]Nenhum host ativo encontrado ou ocorreu um erro.[/bold yellow]")
        raise typer.Exit()

    table = Table(title="Hosts Ativos Encontrados")
    table.add_column("IP", justify="left", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    table.add_column("Fabricante", style="green")

    with console.status("[bold green]Buscando fabricantes...", spinner="dots") as status:
        for host in found_hosts:
            vendor = utils.get_mac_vendor(host['mac'])
            table.add_row(host['ip'], host['mac'], vendor)

    console.print(table)


@app.command(help="Escaneia portas TCP abertas de um host (NÃO IMPLEMENTADO).")
def portscan(
    host: Annotated[str, typer.Argument(help="O IP do host para escanear.")],
    ports: Annotated[str, typer.Option("--ports", "-p", help="Portas para escanear (ex: 22,80,443).")] = "22,80,443,8080",
):
    port_list = [int(p.strip()) for p in ports.split(',')]
    console.print(f"[bold yellow]A função de Port Scan para {host} nas portas {port_list} ainda não foi implementada.[/bold yellow]")


if __name__ == "__main__":
    app()