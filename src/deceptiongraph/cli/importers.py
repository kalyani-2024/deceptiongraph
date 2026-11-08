"""``dgraph import`` - build a network file from a real inventory.

    dgraph import nmap scan.xml --zones zones.yaml -o network.yaml
    dgraph import cmdb exports/ -o network.yaml

The output is an ordinary network file, so every other command takes it.
"""

from __future__ import annotations

from pathlib import Path

import typer
import yaml
from rich.console import Console

import_app = typer.Typer(name="import", no_args_is_help=True,
                         help="Build a network file from an nmap scan or a CMDB export.")
console = Console()


def _write(raw: dict, out: Path, source: str) -> None:
    from ..graph.loader import build_model

    try:
        model = build_model(raw)  # validate before writing anything
    except ValueError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=1) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"# Imported by `dgraph import {source}`.\n"
                   + yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    summary = model.summary()
    console.print(
        f"[green]Wrote[/] {out}: {summary['hosts']} hosts, {summary['services']} services, "
        f"{summary['vulnerabilities']} CVEs, {summary['credentials']} credentials, "
        f"{summary['connections']} connections. "
        f"Crown jewels: {', '.join(summary['crown_jewels']) or 'none'}. "
        f"Entry points: {', '.join(summary['entry_points']) or 'none'}."
    )
    console.print(f"Next: [bold]dgraph paths {out}[/]")


@import_app.command()
def nmap(
    scan: Path = typer.Argument(..., help="nmap XML (-oX), ideally run with --script vulners."),
    zones: Path = typer.Option(None, "--zones", "-z",
                               help="Zone policy: subnets, firewall flows, crown jewels, accounts."),
    out: Path = typer.Option(Path("network.yaml"), "--out", "-o"),
    name: str = typer.Option(None, "--name", help="Network name (default: the policy's or file's)."),
) -> None:
    """Import an nmap scan you have already run. This never scans anything itself."""
    from ..discovery.nmap import NmapAssetDiscovery

    try:
        raw = NmapAssetDiscovery(scan, zones, name=name).raw()
    except (FileNotFoundError, ValueError, KeyError) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=1) from exc
    if zones is None:
        console.print("[yellow]note:[/] no --zones policy: every host is INTERNAL, "
                      "so nothing is reachable from the internet. See data/discovery/lab-zones.yaml.")
    _write(raw, out, "nmap")


@import_app.command()
def cmdb(
    directory: Path = typer.Argument(..., help="Directory with hosts.csv (+ services, "
                                     "connections, credentials, users)."),
    out: Path = typer.Option(Path("network.yaml"), "--out", "-o"),
    name: str = typer.Option(None, "--name"),
) -> None:
    """Import a CMDB export (CSV files)."""
    from ..discovery.cmdb import CmdbAssetDiscovery

    try:
        raw = CmdbAssetDiscovery(directory, name=name).raw()
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=1) from exc
    _write(raw, out, "cmdb")
