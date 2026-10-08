# DeceptionGraph

An adaptive cyber-deception digital twin. Instead of faking a file system, it
builds a graph model of an enterprise network, works out how an attacker would
move through it, places decoys where they are most likely to be tripped — and
then **moves them while the intrusion is in progress**.

```
Network definition
        |
        v
Asset discovery  ->  Graph builder  ->  ATTACK GRAPH
                                          /       \
                                Risk analysis   Path prediction
                                          \       /
                                     DECEPTION ENGINE
                            (honeyfile / decoy host / honeytoken)
                                           |
                                   Event monitoring
                                           |
                                   Attacker profiler
                                           |
                                    Adaptation loop
```

**354 tests, no services required.** Neo4j, PostgreSQL and Redis are optional;
with none configured the whole system runs in memory.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[all]"            # or just ".[dev]" for the core
```

Or with the full stack behind it:

```bash
docker compose up -d
curl localhost:8000/health         # says which backends are live
```

## Demo

To walk through the whole system in order — twin, attack paths, risk, decoy
placement, the adaptation loop firing, and the experiment that measures it:

```powershell
.\.venv\Scripts\Activate.ps1
.\scripts\demo.ps1                  # pauses between the 10 sections
.\scripts\demo.ps1 -NoPause         # straight through, about 2 minutes
.\scripts\demo.ps1 -Trials 500      # heavier experiment
```

## Use

```bash
dgraph discover   data/networks/enterprise.yaml      # what discovery found
dgraph paths      data/networks/enterprise.yaml      # how an attacker gets in
dgraph risk       data/networks/enterprise.yaml      # what is most at risk
dgraph predict    data/networks/enterprise.yaml -f web01
dgraph deceive    data/networks/enterprise.yaml -b 3 # where to put decoys
dgraph simulate   data/networks/campus.yaml -n 10    # watch the loop respond
dgraph experiment data/networks/campus.yaml -t 300   # measure the strategies
dgraph compare    data/networks/enterprise.yaml -b 2
dgraph report     data/networks/enterprise.yaml -o report.json
dgraph serve      --port 8000                        # HTTP API (no UI)
```

### Finding the way in

`dgraph paths` on the bundled reference network:

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

### Placing the decoys

```
Recommended deception placement (attack-path)
  [1] fake_api_server_password.txt on web01 (mimics api02)
  [2] fake_production_database_password.txt on api02 (mimics db01)
  [3] adm01-replica on db01 (mimics adm01)

Deception coverage
  P(detect worst path)  0.49
  Hops before detection 1.26
  Crown jewel coverage  100%
```

### Watching it adapt

`dgraph simulate` runs a simulated intrusion through the live loop:

```
Run 5: INTERNET -> web-pub -> app-02  DETECTED at app-02 after 2 hops

DECEPTION TRIGGERED
  DECOY_TOUCHED on app-02: attacker accessed data-01-replica
  Attacker stage: LATERAL_MOVEMENT
  Sophistication: LOW
  Objective: data-01
  Likely next target: app-01
  Incident INC-0004 [HIGH]
  Adapted: +1 decoys on app-02; retired 1 burned
```

## Does the deception actually work?

`dgraph experiment` runs Monte Carlo intrusions against each placement
strategy. Below: the 16-host `campus.yaml`, budget 3, **1000 trials**, all arms
seeded identically so they face the same attacks.

| Strategy | Detect | ±95% | Hops | Decoys | False/day | Jewels |
| --- | --- | --- | --- | --- | --- | --- |
| **adaptive** | **0.52** | 0.06 | 1.62 | 5 | 0.20 | 64% |
| risk | 0.37 | 0.05 | 2.21 | 3 | 0.15 | 100% |
| attack-path | 0.34 | 0.05 | **1.28** | 3 | 0.15 | 50% |
| centrality | 0.25 | 0.05 | 2.36 | 3 | 0.15 | 50% |
| random *(control)* | 0.24 | 0.05 | 2.32 | 3 | 0.11 | 50% |

What this shows, and what it does not:

- **Adaptation is worth its complexity.** It roughly doubles detection over
  random placement, for one extra decoy on average.
- **`attack-path` catches intruders earliest** (1.28 hops) even though `risk`
  catches slightly more of them. Which you prefer depends on whether you would
  rather catch more attackers or catch them before they reach the data.
- **`centrality` does not beat random placement.** Betweenness is a poor proxy
  here: the graph's most *central* host is not the one on the likeliest route.
  That is a negative result and it is reported as one.
- **`risk` has the best crown-jewel coverage** but the worst time-to-detection,
  because it guards the valuable hosts rather than the way in.
- Overlapping confidence intervals mean *no difference shown*, not a small win.
  `verdict()` refuses to call a winner inside the interval.

Reproduce it with `dgraph experiment data/networks/campus.yaml -t 1000 --seed 7`
(about two minutes).

## Library

Most callers want the Facade:

```python
from deceptiongraph import SecurityFacade, SecurityMediator, Event, EventType

security = SecurityFacade("data/networks/enterprise.yaml")

analysis = security.analyse_network()
print(analysis.most_dangerous_path.describe(), analysis.choke_points)

deployment = security.deploy_deception(budget=3)
for line in deployment.recommendations():
    print(line)

# Go live: route events through the mediator and let the posture adapt.
mediator = SecurityMediator(
    security.repository, deception=security.deception, deployment=deployment
)
asset = deployment.assets[1]
reaction = mediator.handle(
    Event(
        type=EventType.DECOY_AUTHENTICATED,
        host_id=asset.host_id,
        actor_id="apt-1",
        token=asset.marker.token,
    )
)
print(reaction.describe())
print(mediator.status())
```

## HTTP API

`dgraph serve`, then `/docs` for the OpenAPI UI. There is no front end — this
is a service for other software.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Liveness, and which backends are configured |
| GET | `/network` `/analysis` | Discovery summary; attack graph and risk |
| GET | `/paths/{host}` `/predict/{host}` | Routes in; predicted movement |
| POST | `/deception/deploy` | Place decoys |
| GET | `/deception` `/deception/compare` | Current posture; strategy comparison |
| POST | `/events` | **Report an observation**, get the response |
| GET | `/status` `/incidents` `/timeline` | Live defensive state |
| POST | `/experiments` | Run the Monte Carlo experiment |

`POST /events` is what a real sensor calls. Supply the canary token and the
decoy is resolved for you:

```bash
curl -X POST localhost:8000/events -H 'content-type: application/json' \
  -d '{"type":"DECOY_AUTHENTICATED","actor_id":"apt-1","token":"credential-a1b2c3d4"}'
```

## Agent integration

The system is exposed as MCP-style tools, so an LLM agent can drive it. Schemas
are JSON Schema, usable directly for MCP or OpenAI-style function calling.

```python
from deceptiongraph.agent import DeceptionGraphTools, tool_schemas

tools = DeceptionGraphTools("data/networks/enterprise.yaml")
schemas = tool_schemas(read_only=True)        # omits the two mutating tools
print(tools.call("analyse_network")["most_dangerous_path"])
```

Seven tools: `analyse_network`, `find_attack_paths`, `predict_movement`,
`compare_strategies`, `get_status` (read-only), plus `deploy_deception` and
`report_event` (flagged `mutates=True`, so a caller can require confirmation —
an agent that can silently re-arrange your deception posture is a worse problem
than the one it solves). Tool errors return `{"error": ...}` rather than
raising, because an exception inside an agent loop usually derails it.

## Defining a network

See [`data/networks/enterprise.yaml`](data/networks/enterprise.yaml) (5 hosts,
the brief's example) and [`campus.yaml`](data/networks/campus.yaml) (16 hosts,
used for the experiments).

| Field | Meaning |
| --- | --- |
| `criticality` | Business value of the asset, 0–1 |
| `crown_jewel` | Marks a protection target |
| `patch_level` | 0 unpatched, 1 hardened; damps exploitability |
| `exposure` | `INTERNET`, `DMZ`, `INTERNAL`, `RESTRICTED` |
| `strength` (credential) | 0 trivially replayable, 1 vaulted/rotated |
| `filtered` (connection) | 0 wide open, 1 blocked by segmentation |
| `hierarchy` | Optional org/department/subnet tree for the Composite |

Every reference is validated at load time: a credential granting access to a
host that does not exist is an error, not a silently dropped edge.

## How the scoring works

**Attack surface.** A vulnerability's exploit probability is
`cvss/10 × exploitability`. A service combines its vulnerabilities with a
noisy-OR (the attacker needs only one), a host combines its services the same
way, and the result is damped by `patch_level`.

**Attack graph.** One edge per host-to-host transition, from four vectors:

| Vector | Probability |
| --- | --- |
| `PERIMETER_ENTRY` | reachability × target surface, from `INTERNET` |
| `NETWORK_EXPLOIT` | reachability × target surface |
| `CREDENTIAL_REUSE` | `1 − strength`, halved when no network route is known |
| `TRUSTED_SESSION` | 0.35, damped by the target's patch level |

Edge cost is `−log(p)`, so the shortest weighted path *is* the most likely
path — `best_path()` finds it without enumerating everything.

**Risk** is two numbers kept apart. *Intrinsic*: how soft an asset is times
what it is worth (from the Composite). *Path*: how likely the attacker arrives
times what arriving costs. An unpatched host nobody can reach is intrinsically
risky but not urgent; a hardened host at the end of a wide-open chain is the
opposite. Ranking blends them 65/35 toward reachability.

**Prediction.** Each candidate move scores `P(hop) × value(next)`, where
`value` is the best risk-weighted payoff reachable onward.

## How the deception works

**Every decoy is three parts.** A `Lure` (bait), a `Sensor` (what fires when
touched), a `Marker` (canary token, so a sighting traces back to this decoy on
this host). A lure without a sensor is litter — it wastes the attacker's time
and tells you nothing. `P(detect | attacker reaches host) = believability ×
fidelity`: they must take the bait *and* the telemetry must survive.

**Decoys imitate the attacker's predicted next move.** A fake database
credential on the app server is believable precisely *because* that
relationship exists.

**The attacker's stage changes the posture.** Each kill-chain stage is an
object that answers both "what does this event mean?" and "what should the
deception look like now?" — decoy hosts during discovery, honeyfiles at
collection, where a false positive costs far less than a miss.

**A burned decoy is re-seeded, not abandoned.** The actor who tripped it knows
that host is watched; the next actor does not. So the position is refilled with
a *different* family rather than leaving a hole where deception was working.
(An earlier version retired burned decoys without replacing them, and the
adaptive arm scored *worse* than static placement as a result.)

**Scoring a deployment** walks the attacker's route hop by hop. At each hop
they fail, trip a decoy, or survive. Detection is terminal — once the alert
fires the run is over, so a later decoy cannot claim the same interception.

## Design patterns

| Pattern | Where | Why |
| --- | --- | --- |
| Composite | `domain/composite.py` | `calculate_risk()` works the same on one host or the whole organisation |
| Repository | `graph/repository.py` | The analysis layer never learns whether storage is NetworkX or Neo4j |
| Abstract Factory | `deception/factory.py` | Lure, sensor and marker must match; callers ask for a family |
| Strategy | `deception/placement.py` | Four placement algorithms, swappable so the experiment can measure them |
| Facade | `facade.py` | Three methods over eight subsystems |
| Observer | `runtime/events.py` | Event fan-out; observers never learn about each other |
| State | `runtime/states.py` | Each kill-chain stage is an object carrying its own deception posture |
| Mediator | `runtime/mediator.py` | Owns the *ordering* of the response, so the subsystems stay decoupled |

**Observer vs Mediator** is worth being precise about, since they overlap in
most descriptions. The **bus** delivers each event to everyone who cares, with
no ordering and no knowledge of what they do with it. The **mediator** owns the
workflow that must happen in order afterwards: profile first (everything keys
off the stage), then adaptation (it needs the fresh profile to know where
"ahead" is), then the incident (its severity reflects both). Observers stay
ignorant of each other; the sequence lives in one place.

## Layout

```
src/deceptiongraph/
  domain/        entities, enums, the infrastructure Composite
  graph/         asset discovery, network model, graph builder, repository
  analysis/      attack graph engine, risk engine, path predictor
  deception/     decoy assets, factories, placement strategies, coverage
  runtime/       events, attacker states, profiler, incidents, adaptation,
                 mediator, attack simulator
  experiments/   Monte Carlo harness and the six metrics
  storage/       Neo4j, PostgreSQL and Redis adapters (all optional)
  api/           FastAPI service
  agent/         MCP-style tool surface
  facade.py      SecurityFacade
  config.py      environment configuration
data/networks/   enterprise.yaml (5 hosts), campus.yaml (16 hosts)
docs/            PlantUML: architecture, patterns, adaptation loop, attack graph
tests/           354 tests
```

## Tests

```bash
pytest                              # 354 tests, ~11 seconds
pytest --cov=deceptiongraph         # with coverage
```

Analysis tests run against a hand-computed linear fixture
(`INTERNET → web → app → db`), so expected numbers are arithmetic rather than
values copied out of a previous run. Experiment tests use small trial counts —
they test the harness, not the security result.

**What is and is not verified.** Everything in `domain/`, `graph/`,
`analysis/`, `deception/`, `runtime/`, `experiments/`, `api/` and `agent/` is
covered against real objects. The storage adapters are not: `RelationalStore`
is tested against in-memory SQLite, and the Neo4j repository and Redis cache
against fakes in `tests/test_storage.py`. The schema builds, the Cypher is well
formed and the mappings round-trip — but none of the three has been run against
a live server, because this project has none to run them against. The docstrings
in those modules say so too.

## Modelling caveats

Worth stating, since the numbers above look precise:

- **The simulated attacker does not learn.** It does not know which assets are
  decoys and does not get warier after tripping one. Real adversaries who spot
  one honeyfile start treating everything with suspicion, so the detection
  rates here are an **upper bound**.
- **Probabilities are judgement calls.** `cvss/10 × exploitability`, the 0.35
  session-hijack base rate, the 65/35 risk blend — all are documented where
  they are used so they can be argued with, but none is empirically calibrated.
- **False-alert rates are estimates**, not measurements from a real estate.
- **The reference network is too small** to separate the strategies; that is
  why `campus.yaml` exists.

## Roadmap

Everything in the brief is built. What a real deployment would need next:

- A live asset-discovery adapter (nmap, or a CMDB import) behind the existing
  `AssetDiscovery` protocol — the seam is already there.
- Integration tests against real Neo4j and PostgreSQL containers.
- An adversary model that learns, to replace the upper-bound estimates.
- OpenTelemetry spans and Prometheus metrics on the mediator.
