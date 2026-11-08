"""``dgraph db`` - the storage backends from the command line.

    dgraph db status                       which backends are configured and reachable
    dgraph db push data/lanl/network.yaml  write a network into Neo4j
    dgraph db paths acme-enterprise web01  routes to the crown jewels, in Cypher

Configuration comes from the same ``DG_*`` environment variables as the API
(see ``.env.example``).
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

db_app = typer.Typer(name="db", help="Check and use the Neo4j / PostgreSQL / Redis backends.",
                     no_args_is_help=True)
console = Console()


def _backends():
    from ..config import settings
    from ..storage.backends import Backends

    return Backends.from_settings(settings())


@db_app.command()
def status() -> None:
    """Which backends are configured, and whether they answer."""
    backends = _backends()
    try:
        table = Table(title="Storage backends", header_style="bold cyan")
        table.add_column("Backend")
        table.add_column("Status")
        for name, state in backends.status().items():
            colour = "green" if state == "live" else "dim" if state == "not configured" else "red"
            table.add_row(name, f"[{colour}]{state}[/]")
        console.print(table)
        if backends.neo4j_live:
            from ..storage.neo4j_repository import Neo4jGraphRepository

            repo = Neo4jGraphRepository(backends._neo4j_driver,
                                        database=backends.settings.neo4j.database)
            console.print(f"Networks in Neo4j: {', '.join(repo.networks()) or '-'}")
        if backends.store is not None:
            console.print(f"PostgreSQL record: {backends.store.counts()}")
    finally:
        backends.close()


@db_app.command()
def push(network: Path = typer.Argument(..., help="Network YAML to write into Neo4j.")) -> None:
    """Write a network into Neo4j (replacing any earlier copy of the same network)."""
    from ..graph.loader import load_network

    backends = _backends()
    try:
        if not backends.neo4j_live:
            console.print("[bold red]error:[/] Neo4j is not reachable: "
                          f"{backends.status()['neo4j']}. Set DG_NEO4J_URI.")
            raise typer.Exit(code=1)
        model = load_network(network)
        repository = backends.graph_repository(model)
        summary = model.summary()
        console.print(
            f"[green]Wrote[/] {model.name} to Neo4j: {summary['hosts']} hosts, "
            f"{summary['credentials']} credentials, {summary['connections']} connections. "
            f"Browse it at http://localhost:7474 with "
            f"[bold]MATCH (h:Host {{network: '{repository.network}'}}) RETURN h LIMIT 100[/]"
        )
    finally:
        backends.close()


@db_app.command()
def paths(
    network: str = typer.Argument(..., help="Network name in Neo4j (see `dgraph db status`)."),
    start: str = typer.Argument(..., help="Host to start from."),
    limit: int = typer.Option(10, "--limit", "-n"),
) -> None:
    """Routes from a host to the crown jewels, traversed server-side in Cypher."""
    from ..storage.neo4j_repository import Neo4jGraphRepository

    backends = _backends()
    try:
        if not backends.neo4j_live:
            console.print("[bold red]error:[/] Neo4j is not reachable. Set DG_NEO4J_URI.")
            raise typer.Exit(code=1)
        repo = Neo4jGraphRepository(backends._neo4j_driver,
                                    database=backends.settings.neo4j.database, network=network)
        found = repo.paths_to_crown_jewel(start, limit=limit)
        if not found:
            console.print(f"No route from {start} to a crown jewel in {network}.")
        for row in found:
            console.print(f"{row['hops']} hops: {' -> '.join(row['hosts'])}")
    finally:
        backends.close()
