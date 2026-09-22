# DeceptionGraph

An adaptive cyber-deception digital twin. Instead of faking a file system, it
builds a graph model of an enterprise network, works out how an attacker would
move through it, and uses that to decide where deception pays off.

**Stage 1 (this release)** covers the analysis half of the architecture:

```
Network definition
        |
        v
Asset discovery  ->  Graph builder  ->  ATTACK GRAPH
                                          /       \
                                Risk analysis   Path prediction
```

The deception engine, event monitoring, attacker profiler and adaptation loop
are stage 2+; see [Roadmap](#roadmap).

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Use

```bash
dgraph discover data/networks/enterprise.yaml           # what discovery found
dgraph paths    data/networks/enterprise.yaml           # how an attacker gets in
dgraph risk     data/networks/enterprise.yaml           # what is most at risk
dgraph predict  data/networks/enterprise.yaml -f web01  # where they go next
dgraph export   data/networks/enterprise.yaml -o g.json # node-link JSON
```

`dgraph paths` on the bundled reference network reports the route from the
project brief:

```
INTERNET -> web01 -> api02 -> db01
  1. INTERNET -> web01  PERIMETER_ENTRY    p=0.52  priv=SERVICE
  2. web01 -> api02     CREDENTIAL_REUSE   p=0.84  priv=SERVICE
  3. api02 -> db01      CREDENTIAL_REUSE   p=0.83  priv=ADMIN
  P(success)=0.36  impact=0.95  risk=0.35  hops=3

Choke points on routes to crown jewels
  web01   100%
  api02   100%
```

Those choke points are the input to stage 2: a decoy on `api02` sits on every
route to the crown jewel.

## Library

```python
from deceptiongraph import load_network, InMemoryGraphRepository
from deceptiongraph import AttackGraphEngine, RiskEngine, PathPredictor

repo = InMemoryGraphRepository(load_network("data/networks/enterprise.yaml"))

path = AttackGraphEngine(repo).most_dangerous_path()
print(path.describe(), path.risk)

report = RiskEngine(repo).network_risk()
print(report.score, report.crown_jewel_exposure)

for hop in PathPredictor(repo).next_hops("web01"):
    print(hop.target, hop.probability, hop.vector.value)
```

## Defining a network

A network is a YAML inventory. See
[`data/networks/enterprise.yaml`](data/networks/enterprise.yaml) for a
commented example.

| Field | Meaning |
| --- | --- |
| `criticality` | Business value of the asset, 0-1 |
| `crown_jewel` | Marks a protection target |
| `patch_level` | 0 unpatched, 1 hardened; damps exploitability |
| `exposure` | `INTERNET`, `DMZ`, `INTERNAL`, `RESTRICTED` |
| `strength` (credential) | 0 trivially replayable, 1 vaulted/rotated |
| `filtered` (connection) | 0 wide open, 1 blocked by segmentation |
| `hierarchy` | Optional org/department/subnet tree for the Composite |

Every reference is validated at load time: a credential granting access to a
host that does not exist is an error, not a silently dropped edge.

## How the scoring works

**Attack surface.** A vulnerability's exploit probability is `cvss/10 x
exploitability`. A service combines its vulnerabilities with a noisy-OR (the
attacker needs only one to work), a host combines its services the same way,
and the result is damped by `patch_level`.

**Attack graph.** One edge per host-to-host transition an attacker could make,
from four vectors:

| Vector | Probability |
| --- | --- |
| `PERIMETER_ENTRY` | reachability x target surface, from `INTERNET` |
| `NETWORK_EXPLOIT` | reachability x target surface |
| `CREDENTIAL_REUSE` | `1 - strength`, halved when no network route is known |
| `TRUSTED_SESSION` | 0.35, damped by the target's patch level |

Where several vectors join the same pair, they combine with a noisy-OR.

**Paths.** Edge cost is `-log(p)`, so the shortest weighted path is the *most
likely* path — `best_path()` finds it without enumerating everything.
`paths()` enumerates when you want the full picture.

**Risk.** Two numbers, deliberately kept apart. *Intrinsic* risk comes from the
Composite: how soft an asset is, times what it is worth. *Path* risk comes from
the attack graph: how likely the attacker arrives, times what arriving costs.
An unpatched host nobody can reach is intrinsically risky but not urgent; a
hardened host at the end of a wide-open chain is the opposite. The ranking
blends them 65/35 towards reachability.

**Prediction.** Each candidate move scores `P(hop) x value(next)`, where
`value` is the best risk-weighted payoff reachable onward, then scores are
normalised into a distribution over the attacker's options.

## Design patterns

| Pattern | Where | Why |
| --- | --- | --- |
| Composite | `domain/composite.py` | `calculate_risk()` works the same on one host or the whole organisation |
| Repository | `graph/repository.py` | The analysis layer never learns whether storage is NetworkX or Neo4j |
| Strategy (proto) | `graph/loader.py` | `AssetDiscovery` — YAML today, a live scanner later |

Abstract Factory, Facade, Strategy, Observer, State and Mediator land with the
deception engine in stage 2, where they have something to coordinate.

## Layout

```
src/deceptiongraph/
  domain/      entities, enums, the infrastructure Composite
  graph/       asset discovery, network model, graph builder, repository
  analysis/    attack graph engine, risk engine, path predictor
  cli/         Typer + Rich commands
data/networks/ example network definitions
tests/         93 tests, no network or database required
```

The asset graph's node and edge labels already match the Neo4j schema
(`HOST`, `SERVICE`, `CREDENTIAL`, `-[:GRANTS_ACCESS]->`, ...), so stage 2's
`Neo4jGraphRepository` is a translation rather than a redesign.

## Tests

```bash
pytest
```

Analysis tests run against a hand-computed linear fixture
(`INTERNET -> web -> app -> db`), so expected numbers are arithmetic rather
than values copied out of a previous run.

## Roadmap

- **Stage 1 — done.** Domain model, graph builder, attack graph, risk
  analysis, path prediction, CLI.
- **Stage 2.** Deception engine: `DeceptionFactory` (credential / network /
  document decoys), placement strategies (random, risk-based, centrality-based)
  behind a common Strategy interface, and a `SecurityFacade`.
- **Stage 3.** Event monitoring and the attacker profiler: Observer on decoy
  triggers, a State machine over the kill chain, a `SecurityMediator`, and the
  adaptation loop.
- **Stage 4.** Persistence and services: Neo4j, PostgreSQL, Redis, FastAPI,
  Docker Compose, OpenTelemetry.
- **Stage 5.** Experiments comparing placement strategies on detection
  probability, time to detection, path length before detection, decoy count,
  false alert rate and critical-asset coverage.
