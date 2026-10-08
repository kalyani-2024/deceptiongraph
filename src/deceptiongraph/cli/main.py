"""DeceptionGraph command line interface.

    dgraph discover   data/networks/enterprise.yaml
    dgraph paths      data/networks/enterprise.yaml --target db01
    dgraph risk       data/networks/enterprise.yaml
    dgraph predict    data/networks/enterprise.yaml --from web01
    dgraph deceive    data/networks/enterprise.yaml --budget 3
    dgraph simulate   data/networks/campus.yaml --runs 10
    dgraph experiment data/networks/campus.yaml --trials 300
    dgraph compare    data/networks/enterprise.yaml --budget 2
    dgraph report     data/networks/enterprise.yaml --out report.json
    dgraph export     data/networks/enterprise.yaml --out graph.json
    dgraph serve      --port 8000
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from ..analysis.attack_graph import AttackGraphEngine, AttackPath
from ..domain.composite import CompositeComponent, InfrastructureComponent
from ..facade import SecurityFacade
from ..graph.loader import load_network
from ..graph.model import INTERNET
from ..graph.repository import InMemoryGraphRepository

app = typer.Typer(
    name="dgraph",
    help="DeceptionGraph - adaptive cyber-deception digital twin. Analyse a network, place decoys where they will be tripped, and watch the posture adapt.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

NetworkArg = typer.Argument(..., help="Path to a network definition YAML file.")


def _load(path: Path) -> InMemoryGraphRepository:
    try:
        model = load_network(path)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=1) from exc
    return InMemoryGraphRepository(model)


@app.command()
def discover(
    network: Path = NetworkArg,
    show_tree: bool = typer.Option(True, "--tree/--no-tree", help="Show the asset hierarchy."),
) -> None:
    """Load a network and report what asset discovery found."""
    repo = _load(network)
    model = repo.model
    summary = model.summary()

    table = Table(title=f"Discovered assets: {model.name}", header_style="bold cyan")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for key in ("hosts", "users", "services", "vulnerabilities", "credentials", "connections"):
        table.add_row(key.replace("_", " ").title(), str(summary[key]))
    table.add_row("Entry points", ", ".join(summary["entry_points"]) or "-")
    table.add_row("Crown jewels", ", ".join(summary["crown_jewels"]) or "-")
    console.print(table)

    hosts = Table(title="Hosts", header_style="bold cyan")
    for column, justify in (
        ("ID", "left"),
        ("Name", "left"),
        ("Exposure", "left"),
        ("Crit", "right"),
        ("Patch", "right"),
        ("Surface", "right"),
        ("Svc", "right"),
        ("CVE", "right"),
    ):
        hosts.add_column(column, justify=justify)
    for host in model.hosts.values():
        hosts.add_row(
            f"[bold]{host.id}[/]" if host.is_crown_jewel else host.id,
            host.name,
            host.exposure.value,
            f"{host.criticality:.2f}",
            f"{host.patch_level:.2f}",
            _heat(host.attack_surface),
            str(len(host.services)),
            str(len(host.vulnerabilities)),
        )
    console.print(hosts)

    if show_tree and model.root is not None:
        console.print(_composite_tree(model.root))


@app.command()
def paths(
    network: Path = NetworkArg,
    target: str = typer.Option(None, "--target", "-t", help="Target host id. Default: crown jewels."),
    source: str = typer.Option(INTERNET, "--source", "-s", help="Where the attacker starts."),
    top: int = typer.Option(5, "--top", "-n", help="How many paths to list."),
    all_paths: bool = typer.Option(
        False, "--all", help="Enumerate every simple path instead of only the best one."
    ),
) -> None:
    """Show the attack paths an intruder can take."""
    repo = _load(network)
    engine = AttackGraphEngine(repo)

    targets = [target] if target else list(repo.model.crown_jewels) or list(repo.model.hosts)
    for host_id in targets:
        if host_id not in repo.model.hosts:
            console.print(f"[bold red]error:[/] unknown host {host_id!r}")
            raise typer.Exit(code=1)

        if all_paths:
            found = engine.paths(host_id, source=source)[:top]
        else:
            best = engine.best_path(host_id, source=source)
            found = [best] if best else []

        if not found:
            console.print(f"[yellow]No attack path from {source} to {host_id}.[/]")
            continue

        console.print(
            Panel(
                "\n\n".join(_render_path(p) for p in found),
                title=f"Attack paths to [bold]{host_id}[/] from {source}",
                border_style="red",
            )
        )

    worst = engine.most_dangerous_path(source=source)
    if worst is not None and not target:
        console.print(
            Panel(
                _render_path(worst),
                title="[bold]Most dangerous attack path[/]",
                border_style="bold red",
            )
        )

    chokes = engine.choke_points(source=source)
    if chokes:
        table = Table(title="Choke points on routes to crown jewels", header_style="bold cyan")
        table.add_column("Host")
        table.add_column("Route coverage", justify="right")
        for node, coverage in sorted(chokes.items(), key=lambda kv: kv[1], reverse=True):
            table.add_row(node, f"{coverage:.0%}")
        console.print(table)
        console.print(
            "[dim]High-coverage hosts are where stage 2 will place decoys first.[/]"
        )


@app.command()
def risk(
    network: Path = NetworkArg,
    source: str = typer.Option(INTERNET, "--source", "-s", help="Where the attacker starts."),
    top: int = typer.Option(10, "--top", "-n", help="How many assets to list."),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    """Rank assets by risk and score the network."""
    from ..analysis.risk import RiskEngine

    repo = _load(network)
    report = RiskEngine(repo).network_risk(source=source)

    if as_json:
        console.print_json(json.dumps(report.as_dict()))
        return

    console.print(
        Panel(
            f"Network risk       [bold]{report.score:.2f}[/]\n"
            f"Crown jewel exposure {report.crown_jewel_exposure:.2f}\n"
            f"Mean asset score     {report.mean_asset_score:.2f}",
            title=f"Risk report: {report.name}",
            border_style="magenta",
        )
    )

    table = Table(title="Assets by risk", header_style="bold cyan")
    for column in ("Host", "Name", "Score", "P(compromise)", "Crit", "Intrinsic", "Hops"):
        table.add_column(column, justify="right" if column != "Host" and column != "Name" else "left")
    for asset in report.top(top):
        table.add_row(
            f"[bold]{asset.host_id}[/]" if asset.is_crown_jewel else asset.host_id,
            asset.name,
            _heat(asset.score),
            f"{asset.compromise_probability:.2f}",
            f"{asset.criticality:.2f}",
            f"{asset.intrinsic:.2f}",
            "-" if asset.hops_from_internet is None else str(asset.hops_from_internet),
        )
    console.print(table)

    if report.intrinsic is not None:
        console.print(_risk_tree(report.intrinsic))


@app.command()
def predict(
    network: Path = NetworkArg,
    from_host: str = typer.Option(..., "--from", "-f", help="The host assumed compromised."),
    depth: int = typer.Option(4, "--depth", "-d", help="How many hops to roll out."),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    """Predict where an attacker on a given host moves next."""
    from ..analysis.prediction import PathPredictor

    repo = _load(network)
    if from_host != INTERNET and from_host not in repo.model.hosts:
        console.print(f"[bold red]error:[/] unknown host {from_host!r}")
        raise typer.Exit(code=1)

    predictor = PathPredictor(repo)
    hops = predictor.next_hops(from_host)
    trajectory = predictor.predict_trajectory(from_host, depth=depth)
    objective = predictor.objective(from_host)

    if as_json:
        console.print_json(
            json.dumps(
                {
                    "from": from_host,
                    "objective": objective,
                    "next_hops": [h.as_dict() for h in hops],
                    "trajectory": trajectory.as_dict(),
                }
            )
        )
        return

    if not hops:
        console.print(f"[yellow]{from_host} has no onward moves - it is a dead end.[/]")
        return

    table = Table(title=f"If {from_host} is compromised, next move", header_style="bold cyan")
    for column in ("Target", "Name", "Likelihood", "Hop P", "Onward value", "Vector", "To jewel"):
        table.add_column(column)
    for hop in hops:
        table.add_row(
            hop.target,
            hop.name,
            _heat(hop.probability),
            f"{hop.hop_probability:.2f}",
            f"{hop.onward_value:.2f}",
            hop.vector.value,
            "yes" if hop.leads_to_crown_jewel else "no",
        )
    console.print(table)

    console.print(
        Panel(
            f"Predicted route    [bold]{trajectory.describe()}[/]\n"
            f"Confidence         {trajectory.confidence:.2f}\n"
            f"Likely objective   {objective or 'unknown'}",
            title="Projected movement",
            border_style="yellow",
        )
    )


@app.command()
def export(
    network: Path = NetworkArg,
    out: Path = typer.Option(..., "--out", "-o", help="Destination JSON file."),
    kind: str = typer.Option(
        "attack", "--kind", "-k", help="Which graph to export: attack, assets or connectivity."
    ),
) -> None:
    """Export a graph as node-link JSON for visualisation or later stages."""
    import networkx as nx

    repo = _load(network)
    graphs = {
        "attack": lambda: AttackGraphEngine(repo).graph(),
        "assets": repo.asset_graph,
        "connectivity": repo.connectivity_graph,
    }
    if kind not in graphs:
        console.print(f"[bold red]error:[/] unknown graph kind {kind!r} (expected: {', '.join(graphs)})")
        raise typer.Exit(code=1)

    graph = graphs[kind]()
    data = nx.node_link_data(graph, edges="links")
    # AttackStep objects are rich for analysis but not JSON-serialisable.
    for link in data.get("links", []):
        link.pop("step", None)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    console.print(
        f"[green]Wrote[/] {kind} graph: {graph.number_of_nodes()} nodes, "
        f"{graph.number_of_edges()} edges -> {out}"
    )


@app.command()
def deceive(
    network: Path = NetworkArg,
    strategy: str = typer.Option(
        "attack-path", "--strategy", "-S", help="random | risk | centrality | attack-path."
    ),
    budget: int = typer.Option(3, "--budget", "-b", help="How many decoys to place."),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    """Decide where to place decoys, and report what that buys you."""
    from ..deception.placement import strategy_for

    repo = _load(network)
    try:
        chosen = strategy_for(strategy)
    except ValueError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=1) from exc
    if budget < 1:
        console.print("[bold red]error:[/] budget must be at least 1")
        raise typer.Exit(code=1)

    facade = SecurityFacade(repo, strategy=chosen)
    deployment = facade.deploy_deception(budget=budget)

    if as_json:
        console.print_json(json.dumps(deployment.as_dict()))
        return

    if not deployment.assets:
        console.print("[yellow]Nothing to defend: no reachable hosts.[/]")
        return

    console.print(
        Panel(
            "\n".join(deployment.recommendations()),
            title=f"Recommended deception placement ([bold]{deployment.strategy}[/])",
            border_style="green",
        )
    )

    table = Table(title="Deployed decoys", header_style="bold cyan")
    for column in ("Host", "Kind", "Decoy", "Mimics", "Believability", "P(detect)"):
        table.add_column(column)
    for asset in deployment.assets:
        table.add_row(
            asset.host_id,
            asset.kind.value,
            asset.lure.name,
            asset.protects or "-",
            f"{asset.lure.believability:.2f}",
            _heat(asset.detection_probability),
        )
    console.print(table)

    for asset in deployment.assets:
        console.print(f"[dim]{asset.host_id}: {asset.rationale}[/]")
        console.print(f"[dim]  watches: {asset.sensor.watches}[/]")

    console.print(_coverage_panel(deployment.coverage))


@app.command()
def compare(
    network: Path = NetworkArg,
    budget: int = typer.Option(3, "--budget", "-b", help="Decoy budget given to each strategy."),
    seed: int = typer.Option(1337, "--seed", help="Seed for the random baseline."),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    """Run the placement strategies head to head on the same network."""
    repo = _load(network)
    if budget < 1:
        console.print("[bold red]error:[/] budget must be at least 1")
        raise typer.Exit(code=1)

    results = SecurityFacade(repo).deception.compare(budget=budget, seed=seed)

    if as_json:
        console.print_json(json.dumps([d.as_dict() for d in results]))
        return

    table = Table(
        title=f"Placement strategies at a budget of {budget}", header_style="bold cyan"
    )
    table.add_column("Strategy", no_wrap=True)
    for column in ("P(detect)", "Hops", "Jewels", "Residual", "Hosts"):
        table.add_column(column, justify="right" if column != "Hosts" else "left")
    for deployment in results:
        coverage = deployment.coverage
        table.add_row(
            deployment.strategy,
            _heat(coverage.detection_probability),
            "-" if coverage.mean_hops_to_detection is None
            else f"{coverage.mean_hops_to_detection:.2f}",
            f"{coverage.critical_asset_coverage:.0%}",
            f"{coverage.undetected_crown_jewel_risk:.3f}",
            ", ".join(deployment.hosts),
        )
    console.print(table)
    console.print(
        "[dim]Lower hops-to-detect is better: the attacker is caught earlier. "
        "'random' is the control - a strategy that cannot beat it is not worth its cost.[/]"
    )


@app.command()
def report(
    network: Path = NetworkArg,
    strategy: str = typer.Option("attack-path", "--strategy", "-S", help="Placement strategy."),
    budget: int = typer.Option(3, "--budget", "-b", help="Decoy budget."),
    out: Path = typer.Option(None, "--out", "-o", help="Write the JSON report to a file."),
) -> None:
    """Analyse, deploy deception and print the combined report."""
    from ..deception.placement import strategy_for

    repo = _load(network)
    try:
        facade = SecurityFacade(repo, strategy=strategy_for(strategy))
    except ValueError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    facade.deploy_deception(budget=budget)
    data = facade.generate_report()

    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]Wrote report ->[/] {out}")
        return

    console.print(
        Panel(
            "\n".join(f"- {line}" for line in data["recommendations"]),
            title=f"Security report: {data['network']}",
            border_style="magenta",
        )
    )
    console.print(_coverage_panel(facade.deployment.coverage))


@app.command()
def simulate(
    network: Path = NetworkArg,
    budget: int = typer.Option(3, "--budget", "-b", help="Decoys to deploy before the attack."),
    strategy: str = typer.Option("attack-path", "--strategy", "-S", help="Placement strategy."),
    runs: int = typer.Option(1, "--runs", "-n", help="How many attacks to simulate."),
    seed: int = typer.Option(None, "--seed", help="Seed, for a repeatable run."),
    adaptive: bool = typer.Option(
        True, "--adaptive/--static", help="Let the system move decoys as the attack unfolds."
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    """Run a simulated attack and watch the adaptation loop respond."""
    from ..deception.placement import strategy_for
    from ..runtime.mediator import SecurityMediator
    from ..runtime.simulator import AttackSimulator

    repo = _load(network)
    try:
        chosen = strategy_for(strategy)
    except ValueError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        raise typer.Exit(code=1) from exc
    if budget < 1 or runs < 1:
        console.print("[bold red]error:[/] budget and runs must both be at least 1")
        raise typer.Exit(code=1)

    facade = SecurityFacade(repo, strategy=chosen)
    deployment = facade.deploy_deception(budget=budget)
    mediator = (
        SecurityMediator(repo, deception=facade.deception, deployment=deployment)
        if adaptive
        else None
    )
    simulator = AttackSimulator(
        repo, mediator=mediator, assets=list(deployment.assets), seed=seed
    )

    results = [simulator.run(actor_id=f"actor-{i + 1}") for i in range(runs)]

    if as_json:
        console.print_json(
            json.dumps(
                {
                    "deployment": deployment.as_dict(),
                    "runs": [r.as_dict() for r in results],
                    "status": mediator.status() if mediator else None,
                }
            )
        )
        return

    console.print(
        Panel(
            "\n".join(deployment.recommendations()),
            title=f"Standing deception ([bold]{deployment.strategy}[/], "
            f"{'adaptive' if adaptive else 'static'})",
            border_style="green",
        )
    )

    detected = 0
    for index, result in enumerate(results, start=1):
        colour = "green" if result.detected else "red"
        console.print(f"[{colour}]Run {index}:[/] {result.describe()}")
        detected += int(result.detected)

        for step in result.steps:
            if step.reaction is not None and step.reaction.triggered:
                console.print(
                    Panel(
                        step.reaction.describe(),
                        title="[bold red]DECEPTION TRIGGERED[/]",
                        border_style="red",
                    )
                )

    console.print(
        f"\nDetected [bold]{detected}[/] of {runs} "
        f"({detected / runs:.0%})" if runs else ""
    )

    if mediator is not None:
        status = mediator.status()
        console.print(
            Panel(
                f"Live decoys      {status['live_decoys']}\n"
                f"Burned decoys    {status['burned_decoys']}\n"
                f"Adaptations      {status['adaptations']}\n"
                f"Open incidents   {len(status['open_incidents'])}\n"
                f"Network risk     {status['network_risk']:.2f}",
                title="Posture after the attack",
                border_style="yellow",
            )
        )
        if status["most_advanced_actor"]:
            actor = status["most_advanced_actor"]
            console.print(
                Panel(
                    f"Stage            {actor['stage']}\n"
                    f"Sophistication   {actor['sophistication']}\n"
                    f"Objective        {actor['objective'] or 'unknown'}\n"
                    f"Next target      {actor['likely_next_target'] or 'unknown'}\n"
                    f"Confidence       {actor['confidence']:.2f}\n"
                    f"Hosts touched    {', '.join(actor['hosts_seen']) or '-'}",
                    title="Attacker profile",
                    border_style="magenta",
                )
            )


@app.command()
def experiment(
    network: Path = NetworkArg,
    budget: int = typer.Option(3, "--budget", "-b", help="Decoy budget for every arm."),
    trials: int = typer.Option(200, "--trials", "-t", help="Simulated attacks per arm."),
    seed: int = typer.Option(2024, "--seed", help="Base seed; arms are paired on it."),
    sweep: bool = typer.Option(False, "--sweep", help="Repeat across budgets 1, 2, 3 and 5."),
    out: Path = typer.Option(None, "--out", "-o", help="Write the full report as JSON."),
) -> None:
    """Measure the placement strategies against each other."""
    from ..experiments.runner import ExperimentRunner

    repo = _load(network)
    if budget < 1 or trials < 1:
        console.print("[bold red]error:[/] budget and trials must both be at least 1")
        raise typer.Exit(code=1)

    runner = ExperimentRunner(repo, trials=trials, seed=seed)
    with console.status(f"Running {trials} simulated attacks per strategy..."):
        reports = runner.sweep(budgets=(1, 2, 3, 5)) if sweep else [runner.run(budget=budget)]

    for report in reports:
        rows = report.table()
        table = Table(
            title=f"{report.network}: budget {report.budget}, {report.trials} trials",
            header_style="bold cyan",
        )
        table.add_column(rows[0][0], no_wrap=True)
        for column in rows[0][1:]:
            table.add_column(column, justify="right")
        for row in rows[1:]:
            table.add_row(*row)
        console.print(table)
        console.print(Panel(report.verdict(), title="Verdict", border_style="magenta"))

    console.print(
        "[dim]Detect = share of simulated attacks caught. Hops = how early. "
        "'random' is the control; a win inside the +/-95% interval is not a win.[/]"
    )

    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = [r.as_dict() for r in reports]
        out.write_text(
            json.dumps(payload[0] if len(payload) == 1 else payload, indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]Wrote[/] {out}")


@app.command()
def serve(
    network: Path = typer.Option(
        None, "--network", help="Network to serve. Defaults to DG_NETWORK."
    ),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8000, "--port", "-p", help="Port."),
    reload: bool = typer.Option(False, "--reload", help="Reload on code changes."),
) -> None:
    """Start the HTTP API (no UI - it is a service for other software)."""
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - depends on the install extra
        console.print(
            "[bold red]error:[/] uvicorn is not installed. "
            'Install the service extra: pip install -e ".[service]"'
        )
        raise typer.Exit(code=1) from exc

    if network is not None:
        import os

        os.environ["DG_NETWORK"] = str(network)

    console.print(f"[green]DeceptionGraph API[/] on http://{host}:{port}  (docs at /docs)")
    uvicorn.run("deceptiongraph.api.app:app", host=host, port=port, reload=reload)


# -- rendering helpers -----------------------------------------------------


def _coverage_panel(coverage) -> Panel:
    hops = (
        "-" if coverage.mean_hops_to_detection is None
        else f"{coverage.mean_hops_to_detection:.2f}"
    )
    return Panel(
        f"Decoys placed         {coverage.decoys_used}\n"
        f"P(detect worst path)  {coverage.detection_probability:.2f}\n"
        f"Hops before detection {hops}\n"
        f"Crown jewel coverage  {coverage.critical_asset_coverage:.0%}\n"
        f"Reachable host cover  {coverage.host_coverage:.0%}\n"
        f"Residual risk         {coverage.undetected_crown_jewel_risk:.3f}",
        title="Deception coverage",
        border_style="green",
    )


def _render_path(path: AttackPath) -> str:
    lines = [f"[bold]{path.describe()}[/]"]
    for index, step in enumerate(path.steps, start=1):
        lines.append(
            f"  {index}. {step.source} -> [bold]{step.target}[/]  "
            f"{step.vector.value}  p={step.probability:.2f}  "
            f"priv={step.privilege_gained.value}"
        )
        if step.detail:
            lines.append(f"     [dim]{step.detail}[/]")
    lines.append(
        f"  P(success)={path.probability:.2f}  impact={path.impact:.2f}  "
        f"[bold]risk={path.risk:.2f}[/]  hops={path.length}"
    )
    return "\n".join(lines)


def _composite_tree(root: InfrastructureComponent) -> Tree:
    score = root.calculate_risk()
    tree = Tree(f"[bold]{root.name}[/] [dim]({root.node_type.value})[/] risk={score.value:.2f}")
    _attach(tree, root)
    return tree


def _attach(branch: Tree, component: InfrastructureComponent) -> None:
    if not isinstance(component, CompositeComponent):
        return
    for child in component.children:
        score = child.calculate_risk()
        node = branch.add(
            f"{child.name} [dim]({child.node_type.value})[/] risk={_heat(score.value, plain=False)}"
        )
        _attach(node, child)


def _risk_tree(score) -> Tree:
    tree = Tree(f"[bold]Intrinsic risk: {score.component_id}[/] = {score.value:.2f}")

    def walk(branch: Tree, node) -> None:
        for child in node.children:
            sub = branch.add(f"{child.component_id} = {_heat(child.value)}")
            walk(sub, child)

    walk(tree, score)
    return tree


def _heat(value: float, plain: bool = False) -> str:
    colour = "green" if value < 0.34 else "yellow" if value < 0.67 else "red"
    text = f"{value:.2f}"
    return text if plain else f"[{colour}]{text}[/]"


def main() -> None:
    app()


if __name__ == "__main__":
    main()
