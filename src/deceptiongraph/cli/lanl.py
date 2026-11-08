"""``dgraph lanl`` - the real-dataset and machine-learning pipeline.

    dgraph lanl prepare  --auth auth.txt.gz --redteam redteam.txt.gz --out data/lanl
    dgraph lanl train    data/lanl
    dgraph lanl evaluate data/lanl --budgets 3,5,10
    dgraph lanl replay   data/lanl --strategy ml --budget 5

After `prepare`, ``data/lanl/network.yaml`` is an ordinary network file: every
other command (`paths`, `risk`, `deceive`, `simulate`, `experiment`, `serve`)
works on the real-data twin unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

lanl_app = typer.Typer(
    name="lanl",
    help="Real data: build a twin from the LANL dataset, train the ML models, "
    "and measure decoy placement against the real red team.",
    no_args_is_help=True,
)
console = Console()

PreparedArg = typer.Argument(..., help="Directory written by `dgraph lanl prepare`.")
ModelsOpt = typer.Option(Path("models"), "--models", "-m", help="Where trained models live.")


def _need_ml() -> None:
    try:
        import sklearn  # noqa: F401
        import joblib  # noqa: F401
    except ImportError as exc:
        console.print('[bold red]error:[/] needs the ml extra: pip install -e ".[ml]"')
        raise typer.Exit(code=1) from exc


def _fail(message: str) -> None:
    console.print(f"[bold red]error:[/] {message}")
    raise typer.Exit(code=1)


@lanl_app.command()
def prepare(
    auth: Path = typer.Option(..., "--auth", help="auth.txt.gz from csr.lanl.gov/data/cyber1"),
    redteam: Path = typer.Option(..., "--redteam", help="redteam.txt.gz"),
    out: Path = typer.Option(Path("data/lanl"), "--out", "-o", help="Output directory."),
    days: float = typer.Option(31.0, "--days", help="Read this many days (red team ends ~day 30)."),
    max_hosts: int = typer.Option(150, "--max-hosts", help="Busiest computers kept in the twin."),
    crown_jewels: int = typer.Option(3, "--crown-jewels", help="Most-used servers to protect."),
    negative_rate: float = typer.Option(0.01, "--negative-rate",
                                        help="Share of normal logons kept for training."),
    include_redteam_hosts: bool = typer.Option(
        False, "--include-redteam-hosts",
        help="Force red-team targets into the twin (selection on the label; recorded)."),
    max_lines: int = typer.Option(None, "--max-lines", help="Stop early (for a quick look)."),
    seed: int = typer.Option(7, "--seed"),
) -> None:
    """Stream the raw LANL files once: twin, features, labels."""
    from ..datasets.lanl import SECONDS_PER_DAY, prepare as run_prepare

    for path in (auth, redteam):
        if not path.exists():
            _fail(f"{path} not found. Download it from https://csr.lanl.gov/data/cyber1/")

    def progress(lines: int, lateral: int) -> None:
        console.print(f"[dim]  {lines / 1e6:,.0f}M lines read, {lateral:,} remote user logons[/]")

    console.print(f"Reading {auth} (the full file takes a while; progress every 1M lines)")
    try:
        summary = run_prepare(
            auth, redteam, out, until=int(days * SECONDS_PER_DAY), max_hosts=max_hosts,
            crown_jewels=crown_jewels, negative_rate=negative_rate,
            include_redteam_hosts=include_redteam_hosts, max_lines=max_lines, seed=seed,
            progress=progress,
        )
    except ValueError as exc:
        _fail(str(exc))

    table = Table(title=f"Prepared {out}", header_style="bold cyan")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for label, value in (
        ("Lines read", f"{summary.lines_read:,}"),
        ("Remote user logons", f"{summary.lateral_logons:,}"),
        ("Red-team events in window", summary.redteam_events),
        ("Red-team events matched in auth", summary.redteam_matched),
        ("Training rows: red team", summary.positive_rows),
        ("Training rows: normal (sampled)", f"{summary.negative_rows:,}"),
        ("Twin hosts", summary.twin_hosts),
        ("Twin connections", summary.twin_connections),
        ("Red-team targets in twin",
         f"{summary.redteam_targets_in_twin} of {summary.redteam_targets}"),
        ("Seconds", summary.seconds),
    ):
        table.add_row(label, str(value))
    console.print(table)
    if summary.redteam_matched < summary.redteam_events:
        console.print(
            f"[yellow]note:[/] {summary.redteam_events - summary.redteam_matched} red-team "
            "events had no exactly matching auth line (outside --max-lines, or failed logons)."
        )
    console.print(f"Next: [bold]dgraph lanl train {out}[/]")


@lanl_app.command()
def train(
    prepared: Path = PreparedArg,
    models: Path = ModelsOpt,
    target_fpr: float = typer.Option(0.001, "--target-fpr",
                                     help="Alert on about this share of normal logons."),
    split_time: int = typer.Option(None, "--split-time",
                                   help="Train before / test after (default: median red-team time)."),
    seed: int = typer.Option(7, "--seed"),
) -> None:
    """Train the lateral-movement detector and the target ranker."""
    _need_ml()
    from ..datasets.lanl import load_redteam_csv
    from ..deception.placement import PlacementContext
    from ..graph.loader import load_network
    from ..graph.repository import InMemoryGraphRepository
    from ..ml.data import load_features, split_by_time
    from ..ml.detector import LateralMovementDetector, evaluate_scores, rule_scores
    from ..ml.targets import TargetRanker

    try:
        with console.status("Loading feature table..."):
            table = load_features(prepared)
        train_rows, test_rows, split = split_by_time(table, split_time)
    except (FileNotFoundError, ValueError) as exc:
        _fail(str(exc))
    if train_rows.positives == 0 or test_rows.positives == 0:
        _fail(f"split at t={split} leaves red-team rows on only one side; pass --split-time")

    console.print(
        f"Split at t={split}: train {len(train_rows):,} rows ({train_rows.positives} red team), "
        f"test {len(test_rows):,} rows ({test_rows.positives} red team)"
    )
    with console.status("Training the lateral-movement detector..."):
        detector = LateralMovementDetector.fit(train_rows, target_fpr=target_fpr, seed=seed)
        ml_metrics = detector.evaluate(test_rows)
        rule = rule_scores(test_rows)
        rule_threshold = 1.0  # all three heuristics fire
        rule_metrics = evaluate_scores(test_rows.y, rule, test_rows.weight,
                                       threshold=rule_threshold, days=test_rows.days)
        importance = detector.feature_importance(test_rows, seed=seed)

    _detector_table(ml_metrics, rule_metrics)
    top = ", ".join(f"{k} ({v:+.3f})" for k, v in list(importance.items())[:5])
    console.print(f"[dim]Most important features (drop in AP when shuffled): {top}[/]")

    with console.status("Training the target ranker on the twin..."):
        repository = InMemoryGraphRepository(load_network(prepared / "network.yaml"))
        context = PlacementContext.build(repository)
        redteam = load_redteam_csv(prepared / "redteam.csv")
        train_targets = {e.dst for e in redteam if e.time < split} & set(repository.model.hosts)
        try:
            ranker = TargetRanker.fit(context, train_targets)
        except ValueError as exc:
            _fail(f"target ranker: {exc}")

    coefficients = ", ".join(f"{k} {v:+.2f}" for k, v in
                             list(ranker.info["coefficients"].items())[:5])
    console.print(
        f"Target ranker: {ranker.info['positives']} targeted hosts of "
        f"{ranker.info['hosts']} in the twin. Strongest weights: {coefficients}"
    )

    detector.info.update({"prepared": str(prepared), "split_time": split})
    ranker.info.update({"prepared": str(prepared), "split_time": split})
    detector_path = detector.save(models / "detector.joblib")
    ranker_path = ranker.save(models / "target_ranker.joblib")
    report = {
        "split_time": split,
        "detector": {"test": ml_metrics.as_dict(), "info": detector.info,
                     "feature_importance": importance},
        "rule_baseline": {"test": rule_metrics.as_dict(),
                          "rule": "new_user_dst AND new_pair AND NTLM"},
        "target_ranker": ranker.info,
    }
    (models / "training_report.json").write_text(json.dumps(report, indent=2, default=str),
                                                 encoding="utf-8")
    console.print(f"[green]Saved[/] {detector_path}, {ranker_path}, "
                  f"{models / 'training_report.json'}")
    console.print(f"Next: [bold]dgraph lanl evaluate {prepared}[/]")


@lanl_app.command()
def evaluate(
    prepared: Path = PreparedArg,
    models: Path = ModelsOpt,
    budgets: str = typer.Option("3,5,10", "--budgets", "-b", help="Comma-separated budgets."),
    random_trials: int = typer.Option(50, "--random-trials"),
    out: Path = typer.Option(None, "--out", "-o", help="Write results as JSON."),
) -> None:
    """Measure every placement strategy against the real red team (held-out period)."""
    _need_ml()
    from ..datasets.lanl import load_redteam_csv
    from ..deception.placement import STRATEGIES, RandomPlacement
    from ..graph.loader import load_network
    from ..graph.repository import InMemoryGraphRepository
    from ..ml.evaluation import evaluate_on_redteam
    from ..ml.targets import MLPlacement, TargetRanker

    try:
        ranker = TargetRanker.load(models / "target_ranker.joblib")
        budget_list = tuple(int(b) for b in budgets.split(",") if b.strip())
    except (FileNotFoundError, ValueError) as exc:
        _fail(str(exc))
    split = int(ranker.info.get("split_time", 0))
    repository = InMemoryGraphRepository(load_network(prepared / "network.yaml"))
    events = [e for e in load_redteam_csv(prepared / "redteam.csv") if e.time >= split]

    strategies = {name: cls() for name, cls in STRATEGIES.items() if name != "random"}
    strategies = {"random": RandomPlacement(), **strategies, "ml": MLPlacement(ranker)}
    with console.status("Placing decoys with each strategy..."):
        try:
            outcomes = evaluate_on_redteam(repository, events, strategies, budget_list,
                                           random_trials=random_trials)
        except ValueError as exc:
            _fail(str(exc))

    in_twin = [e for e in events if e.dst in repository.model.hosts]
    table = Table(
        title=f"Against the real red team: {len(in_twin)} logons to "
        f"{len({e.dst for e in in_twin})} twin hosts after t={split}",
        header_style="bold cyan",
    )
    for column, justify in (("Strategy", "left"), ("Budget", "right"), ("Targets hit", "right"),
                            ("Logons on decoy", "right"), ("Logons before", "right"),
                            ("Hours to detect", "right")):
        table.add_column(column, justify=justify)
    for o in outcomes:
        hit = f"{o.target_hit_rate:.0%}"
        if o.trials > 1:
            hit += f" +/-{o.target_hit_rate_sd:.0%}"
        table.add_row(
            o.strategy, str(o.budget), hit, f"{o.event_coverage:.0%}",
            "-" if o.events_before_detection is None else f"{o.events_before_detection:.0f}",
            "-" if o.hours_to_detection is None else f"{o.hours_to_detection:.1f}",
        )
    console.print(table)
    console.print(
        "[dim]Exposure measure: a red-team logon onto a host carrying a decoy. Whether they "
        "would have taken the bait depends on the decoy, which LANL cannot tell us. "
        "Random is averaged over seeds (+/- 1 sd).[/]"
    )
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps([o.as_dict() for o in outcomes], indent=2), encoding="utf-8")
        console.print(f"[green]Wrote[/] {out}")


@lanl_app.command()
def replay(
    prepared: Path = PreparedArg,
    models: Path = ModelsOpt,
    strategy: str = typer.Option("attack-path", "--strategy", "-s"),
    budget: int = typer.Option(5, "--budget", "-b"),
    seed: int = typer.Option(7, "--seed"),
    out: Path = typer.Option(None, "--out", "-o", help="Write the summary as JSON."),
) -> None:
    """Replay the held-out period through the ML sensor and the live deception loop."""
    _need_ml()
    from ..deception.placement import strategy_for
    from ..ml.detector import LateralMovementDetector
    from ..ml.sensor import replay as run_replay
    from ..ml.targets import MLPlacement, TargetRanker

    try:
        detector = LateralMovementDetector.load(models / "detector.joblib")
        chosen = (MLPlacement(TargetRanker.load(models / "target_ranker.joblib"))
                  if strategy == "ml" else strategy_for(strategy))
    except (FileNotFoundError, ValueError) as exc:
        _fail(str(exc))
    split = int(detector.info.get("split_time", 0))

    with console.status("Replaying the held-out period..."):
        summary = run_replay(prepared, detector, strategy=chosen, budget=budget,
                             start_time=split, seed=seed)

    for line in summary.highlights:
        console.print(Panel(line, border_style="red"))
    hours = summary.hours_to_first_detection
    console.print(Panel(
        f"Logons replayed          {summary.rows:,} ({summary.redteam_rows} red team)\n"
        f"ML alerts                {summary.ml_alerts} "
        f"({summary.ml_true_alerts} red team, {summary.ml_false_alerts} normal)\n"
        f"ML false alerts / day    {summary.ml_false_alerts_per_day:.1f} (scaled to full stream)\n"
        f"Decoy triggers           {summary.decoy_triggers}\n"
        f"Red-team logons before   "
        f"{'-' if summary.redteam_before_first_detection is None else summary.redteam_before_first_detection}"
        f" first detection\n"
        f"Hours to first detection {'-' if hours is None else f'{hours:.1f}'}\n"
        f"Incidents opened         {summary.incidents}\n"
        f"Adaptations              {summary.adaptations}  (live decoys now {summary.live_decoys})",
        title=f"Replay: {summary.strategy}, budget {summary.budget}",
        border_style="green",
    ))
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary.as_dict(), indent=2), encoding="utf-8")
        console.print(f"[green]Wrote[/] {out}")


def _detector_table(ml, rule) -> None:
    table = Table(title="Lateral-movement detection, held-out period", header_style="bold cyan")
    table.add_column("Metric")
    table.add_column("ML model", justify="right")
    table.add_column("Rule baseline", justify="right")

    def fmt(value, pct=False):
        if value is None:
            return "-"
        return f"{value:.1%}" if pct else f"{value:.3f}"

    table.add_row("Average precision", fmt(ml.average_precision), fmt(rule.average_precision))
    table.add_row("ROC AUC", fmt(ml.roc_auc), fmt(rule.roc_auc))
    for key in ml.recall_at_fpr:
        table.add_row(f"Recall at FPR {float(key):.2%}", fmt(ml.recall_at_fpr[key], True),
                      fmt(rule.recall_at_fpr[key], True))
    table.add_row("Recall at alert threshold", fmt(ml.recall_at_threshold, True),
                  fmt(rule.recall_at_threshold, True))
    table.add_row("Precision at alert threshold", fmt(ml.precision_at_threshold, True),
                  fmt(rule.precision_at_threshold, True))
    table.add_row("False alerts / day",
                  "-" if ml.false_alerts_per_day is None else f"{ml.false_alerts_per_day:,.1f}",
                  "-" if rule.false_alerts_per_day is None else f"{rule.false_alerts_per_day:,.1f}")
    table.add_row("Red-team rows / normal rows (weighted)",
                  f"{ml.positives} / {ml.negatives_weighted:,.0f}", "")
    console.print(table)
