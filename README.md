# DeceptionGraph

An adaptive cyber-deception digital twin. Instead of faking a file system, it
builds a graph model of an enterprise network, works out how an attacker would
move through it, and uses that to decide where deception pays off.

**Stages 1-2 (this release)** cover analysis and deception:

```
Network definition
        |
        v
Asset discovery  ->  Graph builder  ->  ATTACK GRAPH
                                          /       \
                                Risk analysis   Path prediction
                                          \       /
                                           \     /
                                     DECEPTION ENGINE
                                            |
                          +-----------------+-----------------+
                          |                 |                 |
                      Honeyfile        Decoy host        Honeytoken
```

Event monitoring, the attacker profiler and the adaptation loop are stage 3+;
see [Roadmap](#roadmap).

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
dgraph deceive  data/networks/enterprise.yaml -b 3      # where to put decoys
dgraph compare  data/networks/enterprise.yaml -b 2      # which strategy wins
dgraph report   data/networks/enterprise.yaml -o r.json # everything, as JSON
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

Those choke points are what the deception engine acts on. `dgraph deceive`
turns them into placements:

```
Recommended deception placement (attack-path)
  [1] fake_api_server_password.txt on web01 (mimics api02)
  [2] fake_production_database_password.txt on api02 (mimics db01)
  [3] adm01-replica on db01 (mimics adm01)

Deception coverage
  P(detect worst path)  0.49
  Hops before detection 1.26
  Crown jewel coverage  100%
  Residual risk         0.005
```

And `dgraph compare` shows the placement strategies competing on the same
network and budget:

```
Strategy      P(detect)   Hops   Jewels   Residual   Hosts
attack-path        0.48   1.22     100%      0.016   web01, api02
random             0.44   1.33     100%      0.030   web01, db01
risk               0.41   2.10     100%      0.016   api02, db01
centrality         0.41   2.10     100%      0.016   db01, api02
```

Attack-path placement wins on both counts: it catches more intruders *and*
catches them a hop earlier. At a budget large enough to cover every choke
point the strategies converge — the interesting comparison is a tight budget.

## Library

Most callers want the Facade, which assembles the eight subsystems for you:

```python
from deceptiongraph import SecurityFacade

security = SecurityFacade("data/networks/enterprise.yaml")

analysis = security.analyse_network()
print(analysis.most_dangerous_path.describe(), analysis.choke_points)

deployment = security.deploy_deception(budget=3)
for line in deployment.recommendations():
    print(line)
print(deployment.coverage.detection_probability)

report = security.generate_report()
```

The subsystems stay public for anyone who needs them directly:

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

## How the deception works

**Every decoy is three parts.** A `Lure` (the bait), a `Sensor` (what fires
when it is touched) and a `Marker` (a canary token, so a later sighting traces
back to this decoy on this host). A lure without a sensor is litter: it wastes
the attacker's time and tells you nothing. The factory builds all three as a
matched set, which is why it is an Abstract Factory rather than three loose
constructors.

**Decoys imitate something real.** A fake credential on the app server that
claims to unlock the production database is believable precisely because that
relationship exists. The engine asks the path predictor what the attacker's
likely next move is, and builds the decoy to imitate *that*.

`P(detect | attacker reaches host) = believability x sensor fidelity` — they
have to take the bait *and* the telemetry has to survive.

**Placement strategies** all answer "given N decoys, which hosts?":

| Strategy | Ranks by |
| --- | --- |
| `random` | nothing — the control group |
| `risk` | blended asset risk |
| `centrality` | betweenness on the weighted attack graph |
| `attack-path` | choke-point coverage of crown-jewel routes, weighted towards early interception |

**Scoring a deployment** walks the attacker's route hop by hop. At each hop
they either fail the hop, trip a decoy, or survive undetected and carry on.
Detection is terminal — once the alert fires the run is over, so a decoy
further along cannot claim the same interception twice. That gives both
`P(detect)` and the distribution of *when*, which is what
`mean_hops_to_detection` summarises.

## Design patterns

| Pattern | Where | Why |
| --- | --- | --- |
| Composite | `domain/composite.py` | `calculate_risk()` works the same on one host or the whole organisation |
| Repository | `graph/repository.py` | The analysis layer never learns whether storage is NetworkX or Neo4j |
| Abstract Factory | `deception/factory.py` | Lure, sensor and marker must match; callers ask for a family, never the parts |
| Strategy | `deception/placement.py` | Four placement algorithms, swappable so stage 5 can measure the difference |
| Facade | `facade.py` | `analyse_network()` / `deploy_deception()` / `generate_report()` over eight subsystems |
| Strategy (proto) | `graph/loader.py` | `AssetDiscovery` — YAML today, a live scanner later |

Observer, State and Mediator land in stage 3, where the event pipeline gives
them something to coordinate. `DeceptionState` and `Deployment.asset_by_token()`
are already in place for them.

## Layout

```
src/deceptiongraph/
  domain/      entities, enums, the infrastructure Composite
  graph/       asset discovery, network model, graph builder, repository
  analysis/    attack graph engine, risk engine, path predictor
  deception/   decoy assets, factories, placement strategies, coverage scoring
  facade.py    SecurityFacade - the one entry point most callers want
  cli/         Typer + Rich commands
data/networks/ example network definitions
tests/         175 tests, no network or database required
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
- **Stage 2 — done.** Deception engine: `DeceptionFactory` (credential /
  network / document decoys), four placement strategies behind a common
  Strategy interface, coverage scoring, and the `SecurityFacade`.
- **Stage 3.** Event monitoring and the attacker profiler: Observer on decoy
  triggers, a State machine over the kill chain, a `SecurityMediator`, and the
  adaptation loop.
- **Stage 4.** Persistence and services: Neo4j, PostgreSQL, Redis, FastAPI,
  Docker Compose, OpenTelemetry.
- **Stage 5.** Experiments comparing placement strategies on detection
  probability, time to detection, path length before detection, decoy count,
  false alert rate and critical-asset coverage.
