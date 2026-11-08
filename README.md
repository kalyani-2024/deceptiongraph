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

**455 tests need no services**, plus 16 integration tests that run against
real Neo4j, PostgreSQL and Redis containers. The databases are optional: with
none configured the whole system runs in memory.

Three ways in:

- **Reference networks** (`data/networks/*.yaml`): hand-written, for
  understanding the system and for the controlled experiment.
- **Real data** ([LANL](#real-data-the-lanl-dataset)): a digital twin built
  from 1.6 billion real enterprise events, with labelled red-team activity as
  ground truth.
- **Machine learning** ([two models](#machine-learning)) trained on those
  labels: one flags malicious logons live, one predicts where attackers go and
  places decoys there.
- **Real inventories** ([nmap, CMDB](#importing-a-real-inventory)): build the
  twin from a scan you have run or from configuration-database exports.

The results are tested for robustness against a [smarter
attacker](#against-a-smarter-attacker), [other guesses for the model's
probabilities](#do-the-results-survive-other-guesses) and [larger
networks](#larger-networks), and the live loop is
[observable](#observability) through OpenTelemetry and Prometheus.

Every result quoted below is in [`results/`](results/) as the JSON the
command wrote, with the command that reproduces it.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[all]"            # or just ".[dev]" for the core
```

Or with the full stack behind it:

```bash
docker compose up -d --build
curl localhost:8000/health         # each backend: live / down / not configured
```

## Demo

To walk through the whole system in order — twin, attack paths, risk, decoy
placement, the adaptation loop firing, the experiment that measures it, the
smarter attacker, the sensitivity check, an nmap import and the LANL results:

```powershell
.\.venv\Scripts\Activate.ps1
.\scripts\demo.ps1                  # pauses between the 14 sections
.\scripts\demo.ps1 -NoPause         # straight through, about 5 minutes
.\scripts\demo.ps1 -Trials 500      # heavier experiment
.\scripts\demo.ps1 -Lanl D:\lanl\prepared500 -LanlModels D:\lanl\models500   # + real-data results
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

# Real inventories, real data, research
dgraph import nmap  scan.xml -z zones.yaml -o net.yaml   # from an nmap scan
dgraph import cmdb  exports/ -o net.yaml                 # from CMDB CSV exports
dgraph lanl ...                                          # LANL dataset + ML models
dgraph adversary    data/networks/campus.yaml            # naive vs cautious vs learning attacker
dgraph sensitivity  data/networks/campus.yaml            # do results survive other guesses?
dgraph generate     -n 200 -o net200.yaml                # larger synthetic networks
dgraph scale        --sizes 50,100,200                   # the experiment as networks grow
dgraph db ...                                            # Neo4j / PostgreSQL / Redis
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
| **adaptive** | **0.52** | 0.03 | 1.61 | 5 | 0.20 | 63% |
| attack-path | 0.37 | 0.03 | **1.43** | 3 | 0.15 | 50% |
| risk | 0.37 | 0.03 | 2.27 | 3 | 0.15 | 100% |
| centrality | 0.24 | 0.03 | 2.29 | 3 | 0.15 | 50% |
| random *(control)* | 0.21 | 0.03 | 1.73 | 3 | 0.22 | 50% |

What this shows, and what it does not:

- **Adaptation is worth its complexity.** It more than doubles detection over
  random placement, for two extra decoys on average.
- **`attack-path` catches intruders earliest** (1.43 hops) at the same
  detection rate as `risk`, which only catches them later. Which you prefer
  depends on whether you would rather catch more attackers or catch them before
  they reach the data.
- **`centrality` does not beat random placement.** Betweenness is a poor proxy
  here: the graph's most *central* host is not the one on the likeliest route.
  That is a negative result and it is reported as one.
- **`risk` has the best crown-jewel coverage** but the worst time-to-detection,
  because it guards the valuable hosts rather than the way in.
- Overlapping confidence intervals mean *no difference shown*, not a small win.
  `verdict()` refuses to call a winner inside the interval.

Reproduce it with `dgraph experiment data/networks/campus.yaml -t 1000 --seed 7`
(about 15 seconds).

### Against a smarter attacker

The attacker above is *naive*: it never notices a decoy and never learns, so
those rates are an upper bound. `runtime/adversary.py` adds two attackers that
replace the bound:

- **cautious** can *spot* a decoy instead of falling for it, likelier the less
  believable the lure is. A spotted decoy fires no alert, and makes the
  attacker warier of that kind of lure, and a little of every kind, for the
  rest of the campaign.
- **learning** is cautious and also carries its wariness from one campaign to
  the next, like a group that keeps coming back. Being caught teaches it too.
  Wariness tops out at 70%: an intruder who refused every credential it found
  would be refusing the real ones as well.

`dgraph adversary data/networks/campus.yaml -t 600 --seed 7` (budget 3; for the
learning attacker the 600 trials are one group's successive campaigns):

| Strategy | Naive | Cautious | Learning | Learning: first ⅓ → last ⅓ | Kept |
| --- | --- | --- | --- | --- | --- |
| **adaptive** | **0.53** | **0.48** | **0.23** | 0.25 → 0.23 | 43% |
| attack-path | 0.39 | 0.35 | 0.14 | 0.15 → 0.15 | 37% |
| risk | 0.38 | 0.34 | 0.12 | 0.12 → 0.10 | 32% |
| centrality | 0.24 | 0.22 | 0.08 | 0.12 → 0.06 | 32% |
| random | 0.21 | 0.18 | 0.06 | 0.09 → 0.04 | 28% |

- **The upper bound was optimistic by a factor of two to three** against an
  attacker who learns. A cautious one costs only about a tenth.
- **The ranking survives.** Every strategy loses detection, but none overtakes
  another: what the naive experiment said about *which* strategy to use holds.
- **Adaptation holds up best** (43% of its naive rate kept). Moving decoys
  means a learned "that host has a fake file" goes stale. Static strategies
  keep less, and random least of all.

### Do the results survive other guesses?

Several probabilities in the model are judgement calls. `dgraph sensitivity`
varies each one from 0.5× to 1.5× of its default, keeps the others fixed,
reruns the experiment on identical seeds, and reports whether the winner
changes and how far the ranking moves (Kendall's tau against the default:
1 means an identical ranking).

`dgraph sensitivity data/networks/campus.yaml -t 300 --seed 7`:

| Parameter (default) | Range | Winner | Min tau | Biggest detection change (strategy, max − min) |
| --- | --- | --- | --- | --- |
| session hijack base (0.35) | 0.18–0.53 | adaptive throughout | 0.60 | centrality, 0.17 |
| unrouted credential penalty (0.5) | 0.25–0.75 | adaptive throughout | 1.00 | centrality, 0.10 |
| risk blend toward reachability (0.65) | 0.33–0.98 | adaptive throughout | 0.80 | risk, 0.11 |
| patch damping (0.7) | 0.35–1.0 | adaptive throughout | 0.80 | adaptive, 0.13 |

The headline result does not depend on any one guess: adaptive placement wins
at every setting of every parameter. The lower places shuffle a little (the
lowest tau, 0.6, is one swap between centrality and its neighbour), so claims
about the lower places are weaker than claims about the winner. Pass
`--adversary cautious` to also vary the attacker's skill.

### Larger networks

`dgraph generate -n 200` builds an enterprise-shaped network of any size: a
DMZ, application and data tiers, workstations, admin jump hosts, synthetic
CVEs per tier, and credentials cached where they plausibly would be.
`dgraph scale` runs the experiment across sizes.

`dgraph scale --sizes 50,100,200,400 -t 100 -b 5` (seed 1):

| Hosts | Analysis | Experiment | adaptive | risk | attack-path | centrality | random |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 50 | 0.02 s | 12 s | 0.36 | **0.40** | 0.28 | 0.04 | 0.07 |
| 100 | 0.05 s | 31 s | **0.35** | 0.25 | 0.23 | 0.04 | 0.05 |
| 200 | 0.11 s | 81 s | **0.31** | 0.28 | 0.21 | 0.05 | 0.02 |
| 400 | 0.38 s | 283 s | 0.26 | **0.27** | 0.12 | 0.01 | 0.02 |

- **The informed strategies keep beating random at every size**, by more as the
  network grows: random's 5 decoys are lost in 400 hosts.
- **Adaptive and risk share the top.** At 100 trials the 95% interval is about
  ±0.09, so their differences here are not resolved, while both stay clearly
  ahead of attack-path and far ahead of centrality.
- **`attack-path` weakens with size** (0.28 → 0.12). With more crown jewels
  and more routes to each, five choke points cover less of the attack surface.
- **Analysis stays fast** (under half a second at 400 hosts) since best routes
  are computed once per source. The experiment is the slow part: the adaptive
  arm rebuilds the whole defence for each of its 100 campaigns.

## Real data: the LANL dataset

The experiment above measures the strategies against the *simulated* attacker,
who walks the attack graph the way the model says attackers walk. That is
circular. To break the circle, the system also runs on the public
[LANL Comprehensive Multi-Source Cyber-Security Events](https://csr.lanl.gov/data/cyber1/)
dataset: 58 days of de-identified events from Los Alamos National Laboratory's
corporate network (12,425 users, 17,684 computers), with a file of labelled
red-team compromises as ground truth.

**1. Download** `auth.txt.gz` (7.2 GB) and `redteam.txt.gz` (4.8 KB). LANL asks
for an email address and a sentence on intended use. Keep them **outside**
OneDrive or Dropbox folders, or 7 GB will start syncing. Cite: A. D. Kent,
"Cybersecurity Data Sources for Dynamic Network Research", 2015.

**2. Prepare** — one streaming pass over the first 31 days, which covers every
red-team event. Expect around half an hour to an hour:

```bash
dgraph lanl prepare --auth D:/lanl/auth.txt.gz --redteam D:/lanl/redteam.txt.gz --out data/lanl
dgraph lanl prepare ... --max-lines 20000000   # a quick first look
```

This writes `data/lanl/`:

| File | What |
| --- | --- |
| `network.yaml` | The digital twin: the 150 busiest computers, their cached credentials, who logs on where |
| `auth_features.csv.gz` | One row per remote logon: every red-team logon plus 1% of normal ones (weighted 100) |
| `redteam.csv` | The labelled compromises in the window |
| `hosts.csv`, `meta.json` | Per-host statistics; provenance and counts |

`network.yaml` is an ordinary network file, so **every existing command works
on real data**: `dgraph paths data/lanl/network.yaml`, `deceive`, `simulate`,
`experiment`, `serve`, `db push`.

How the logs become a twin: a user who logs on from `src` to `dst` leaves a
cached credential on `src` that grants access to `dst`. That is how the red
team actually moved (stolen credentials, mostly NTLM, so pass-the-hash). The
most-used servers (in practice the domain controllers) become the crown jewels.
**The twin is built from normal behaviour only.** Every (user, src, dst)
combination the red team used is left out, so the attacker's own moves cannot
leak into the model that decoys are later placed on. A test checks this.

Assumptions that do not come from the data: LANL publishes no vulnerabilities,
so workstations get one "can be phished" weakness (MITRE T1566) as the entry
point, and servers get none. Lateral movement is therefore credential-driven,
which is also what the red-team data shows.

## Machine learning

Two models, trained by `dgraph lanl train data/lanl` on the first half of the
red-team campaign and **tested on the second half**. The split is by time, not
random: the model never sees the future.

**Lateral-movement detector** (`ml/detector.py`). Gradient-boosted trees over
12 per-logon features, each computed only from what happened *before* that
logon. Examples: has this user ever logged on to this host, has anyone used
this route, how many distinct users has the source machine seen, NTLM or
Kerberos. It is compared on the same test rows against a **rule-based
baseline**: the classic analyst heuristic "first-time user-to-host, first-time
route, NTLM". The alert threshold is set with `--target-fpr`: the weighted
quantile of the final model's scores on normal training logons (default 1 in
1,000; `1e-4` is the quieter setting used below). Metrics use the sampling
weights, so false alerts per day describe the full stream, not the 1% sample.

The detector runs as a **live sensor** (`ml/sensor.py`): a flagged logon
becomes a `HOST_COMPROMISED` event in the mediator. From there the profiler,
incident manager and adaptation engine react exactly as they do to a decoy
being touched.

**Target ranker** (`ml/targets.py`). Logistic regression over 13 host features
of the twin: reachability, betweenness, credentials stored and granting,
attack-path score, risk and so on. It is trained on which hosts the red team
went to, and its coefficients say which signals mattered. It is exposed as a
fifth placement strategy, **`ml`**, usable anywhere the other four are:

```bash
dgraph deceive data/lanl/network.yaml -s ml -b 5
```

**Measuring against the real attacker:**

```bash
dgraph lanl evaluate data/lanl --budgets 3,5,10   # every strategy vs the held-out red team
dgraph lanl replay   data/lanl --strategy ml -b 5 # held-out period through the live loop
```

`evaluate` places decoys with each strategy, then checks the red team's real
test-period logons. It reports what share of their targets had a decoy, what
share of their logons landed on one, and how many logons and hours passed
before the first. `replay` streams the held-out logons through the ML sensor
*and* a live, adapting deception deployment. It shows when each would have
caught the red team, and how many false alerts the detector raised on the way.

### Results on LANL

Days 1–31: 525 million events, 52.7 million remote user logons, and 701 of
the 749 red-team events matched to a logon. The other 48 have no exactly
matching successful logon line. Train on the first half of the campaign (350
red-team logons), test on the second (351). Twin built with
`--max-hosts 500`: 54 of the red team's 301 targets fall inside it.

**Detection, held-out period** (33 million normal logons, weighted):

| At a false-alarm rate of | ML detector catches | Rule baseline catches |
| --- | --- | --- |
| 0.01% of normal logons | **70%** of red-team logons | 22% |
| 0.1% | **92%** | 44% |
| 1% | **100%** | 51% |

ROC AUC 1.000 against 0.980; average precision 0.067 against 0.008. At
`--target-fpr 1e-4` the detector flags 74% of red-team logons with about 855
false alerts a day, out of roughly 1.8 million normal logons a day. The signals
that mattered most were NTLM, a source machine used by unusually many accounts,
and a destination with unusually many users. Those fit the red team's actual
method: stolen credentials replayed from a handful of machines. Precision is
still low (1.6%): at LANL's volume even a 0.01% false-alarm rate is hundreds
of alerts a day. That is the case for pairing the detector with decoys, which
almost never false-alarm.

**Decoy placement against the real red team** (held-out period: 108 red-team
logons to 32 twin hosts; random averaged over 200 seeds):

| Budget | Strategy | Targets with a decoy | Logons onto a decoy | Logons before first | Hours to first |
| --- | --- | --- | --- | --- | --- |
| 5 | random | 1% | 1% | 28 | 32.1 |
| 5 | attack-path | 9% | 6% | 25 | 4.6 |
| 5 | centrality | 9% | 12% | 21 | 2.5 |
| 5 | **ml** | 9% | **12%** | **2** | **0.3** |
| 10 | random | 2% | 2% | 31 | 41.3 |
| 10 | attack-path | 9% | 6% | 25 | 4.6 |
| 10 | centrality | **25%** | 23% | 21 | 2.5 |
| 10 | **ml** | 19% | **23%** | **2** | **0.3** |
| 20 | random | 4% | 4% | 24 | 21.3 |
| 20 | attack-path | 9% | 6% | 25 | 4.6 |
| 20 | centrality | 34% | 43% | 2 | 0.3 |
| 20 | **ml** | **38%** | **44%** | **2** | **0.3** |

- **Every informed strategy beats random by a wide margin.** On the real
  attacker, random placement barely touches it.
- **`ml` catches the red team earliest:** on its third logon of the test
  period, within 20 minutes, from 5 decoys up. `centrality` matches its coverage
  but needs 20 decoys to be as early.
- **`attack-path` stalls at 9%** however many decoys it gets. It guards the
  routes to the crown jewels (the three most-used servers), but only 6 of the
  red team's 108 test-period logons went to one. The other 102 hit other
  servers (85) and workstations (17). On the simulated attacker it was the
  second-best static strategy. **On the real one it is not**, and that gap
  between simulation and reality is the strongest argument for evaluating on
  real data.
- `dgraph lanl replay` (ML sensor plus `ml` decoys, budget 10): the detector
  flagged the first red-team logon of the test period. 23 decoy triggers
  followed, 30 incidents were opened, and the posture adapted 25 times.

Reproduce:
`dgraph lanl prepare ... --max-hosts 500`, then
`dgraph lanl train <dir> --target-fpr 1e-4`, then
`dgraph lanl evaluate <dir> -b 3,5,10,20 --random-trials 200`.

What stays rule-based, and why: the attacker's kill-chain **stage** and
**sophistication**. LANL labels which logons were the red team, not what stage
they were in. A stage classifier trained on labels the simulator invented would
only learn to copy the rules.

Caveats: `evaluate` is an *exposure* measure. It records that the red team
logged on to a host with a decoy, not that they took the bait, since LANL had
no decoys. One red-team campaign is one attacker: the results say how well each
strategy would have done against *this* adversary, not attackers in general.

## Storage backends

Set the variables (see `.env.example`) and the API uses each backend; leave
them unset and it runs in memory. `docker compose up` sets all three.

| Backend | Configured by | What it does |
| --- | --- | --- |
| Neo4j | `DG_NEO4J_URI` | Every network the API loads is written to Neo4j and analysed from there. Several networks share one database, kept apart by a `network` property. Browse at `:7474`. |
| PostgreSQL | `DG_DATABASE_URL` | Records every session, decoy, event, incident and experiment as it happens; read back through `/history/*` |
| Redis | `DG_REDIS_URL` | Caches `/analysis` by a fingerprint of the network |

```bash
dgraph db status                            # live / down / not configured, per backend
dgraph db push data/lanl/network.yaml       # load the real-data twin into Neo4j
dgraph db paths lanl C586                   # routes to the crown jewels, in Cypher
```

A backend that is configured but unreachable is reported as `down` by
`/health`. It does not crash the service. A database error while recording an
event comes back as `persistence_error` in the response rather than as an HTTP
error, because the event has already been acted on and a retry would handle it
twice.

**Integration tests** run every adapter against real servers:

```powershell
.\scripts\integration.ps1          # Windows; scripts/integration.sh elsewhere
```

It starts throwaway Neo4j 5, PostgreSQL 16 and Redis 7 containers
(`docker-compose.test.yml`, odd ports, nothing persisted), runs
`tests/integration/`, and removes them. CI
(`.github/workflows/ci.yml`) does the same on every push. The tests check
that a network saved to Neo4j and reloaded gives *identical* analysis, that
two networks coexist, that two sessions in PostgreSQL never overwrite each
other, and the whole API end to end with all three backends live.

## Importing a real inventory

Two adapters behind the same `AssetDiscovery` interface as the YAML loader
(`discovery/`). Both write an ordinary network file.

**nmap.** Run the scan yourself, on a network you are authorised to scan, then
import the XML. DeceptionGraph never scans anything itself; scanning live
networks is outside this project's scope.

```bash
nmap -sV -O --script vulners -oX scan.xml 10.10.0.0/16     # you, with permission
dgraph import nmap scan.xml --zones zones.yaml -o lab.yaml
```

The scan supplies hosts, open services and versions, the OS, and CVEs with
CVSS scores (from the `vulners` script; a public exploit raises
exploitability). A *zone policy* supplies what a scan cannot see: which subnet
is internet-facing, what the firewall lets through between zones, the crown
jewels, and the credentials cached on each machine. Without one, value is
guessed from services (a directory server or database outranks a web front
end) and the guess is tagged on the host. See
[`data/discovery/lab-scan.xml`](data/discovery/lab-scan.xml) and
[`lab-zones.yaml`](data/discovery/lab-zones.yaml) for a fictional example.

**CMDB.** A directory of CSV exports: `hosts.csv` required; `services.csv`
(with CVEs as `CVE-…:cvss`), `connections.csv`, `credentials.csv`, `users.csv`
optional. Headers are matched loosely, and errors name the file and line.
Example: [`data/discovery/cmdb/`](data/discovery/cmdb/).

## Observability

The mediator is instrumented (`runtime/telemetry.py`). Every event becomes an
**OpenTelemetry trace**: a `mediator.handle` span, with child spans for
profiling, adaptation and the incident, carrying the stage, objective,
severity and what the adaptation changed. **Prometheus metrics** are served at
`/metrics`:

| Metric | Meaning |
| --- | --- |
| `dg_events_total{type}` | Events handled |
| `dg_deception_triggers_total{type}` | Decoys that fired |
| `dg_alerts_total{severity}` | Incident updates, by severity |
| `dg_stage_transitions_total{stage}` | Attackers entering each kill-chain stage |
| `dg_adaptations_total` | Re-plans that changed the deployment |
| `dg_live_decoys`, `dg_open_incidents` | Current posture |
| `dg_mediator_handle_seconds` | Time to handle one event (histogram) |

```bash
DG_OTEL_EXPORTER=otlp docker compose --profile observability up -d --build
# Prometheus  http://localhost:9090   (query dg_events_total)
# Jaeger      http://localhost:16686  (service "deceptiongraph")
```

`DG_OTEL_EXPORTER` is `none` (default), `console` or `otlp`. Simulated
intrusions (experiments, the LANL replay) are kept out of the metrics: they
are not production traffic. Without the `observability` extra installed,
every call is a no-op.

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
| GET | `/health` | Liveness, and whether each backend is live |
| GET | `/network` `/analysis` | Discovery summary; attack graph and risk |
| GET | `/paths/{host}` `/predict/{host}` | Routes in; predicted movement |
| POST | `/deception/deploy` | Place decoys |
| GET | `/deception` `/deception/compare` | Current posture; strategy comparison |
| POST | `/events` | **Report an observation**, get the response |
| GET | `/status` `/incidents` `/timeline` | Live defensive state |
| POST | `/experiments` | Run the Monte Carlo experiment (recorded when PostgreSQL is on) |
| GET | `/graph/paths/{host}` | Routes to the crown jewels, traversed in Neo4j |
| GET | `/history/counts` `/alerts` `/events` `/decoys` `/leaderboard` | The PostgreSQL record |

`POST /events` is what a real sensor calls. Supply the canary token and the
decoy, and the host it sits on, are resolved for you:

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
| Strategy | `deception/placement.py`, `ml/targets.py`, `runtime/adversary.py` | Five placement algorithms (four rule-based, one learned), and three attacker models, each swappable so the experiments can measure them |
| Adapter | `datasets/lanl.py`, `discovery/`, `ml/sensor.py`, `storage/` | LANL logs, nmap XML and CMDB CSV behind the `AssetDiscovery` protocol; raw logons in, mediator events out; NetworkX, Neo4j and SQL behind one repository interface |
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
  graph/         asset discovery, network model, graph builder, repository,
                 network generator
  analysis/      attack graph engine, risk engine, path predictor
  deception/     decoy assets, factories, placement strategies, coverage
  runtime/       events, attacker states, profiler, incidents, adaptation,
                 mediator, attack simulator, attacker models, telemetry
  experiments/   Monte Carlo harness, the six metrics, attacker comparison,
                 sensitivity analysis
  storage/       Neo4j, PostgreSQL and Redis adapters (all optional), backends
  datasets/      LANL adapter: streaming parser, features, twin builder
  ml/            detector, target ranker + `ml` strategy, sensor, replay,
                 evaluation against the real red team
  api/           FastAPI service
  agent/         MCP-style tool surface
  discovery/     nmap XML and CMDB CSV importers
  cli/           dgraph, dgraph lanl, dgraph db, dgraph import, research commands
  facade.py      SecurityFacade
  config.py      environment configuration
data/networks/   enterprise.yaml (5 hosts), campus.yaml (16 hosts)
data/discovery/  sample nmap scan + zone policy, sample CMDB export (fictional)
results/         the JSON behind every reported number (LANL and simulation)
deploy/          Prometheus config for the observability profile
data/lanl/       written by `dgraph lanl prepare` (git-ignored)
models/          written by `dgraph lanl train` (git-ignored)
docs/            PlantUML: architecture, patterns, adaptation loop, attack graph
tests/           455 unit tests; tests/integration/ 16 against live servers
```

## Tests

```bash
pytest                              # 455 tests, no services, under a minute
.\scripts\integration.ps1           # + 16 against real Neo4j/PostgreSQL/Redis
pytest --cov=deceptiongraph         # with coverage
```

Analysis tests run against a hand-computed linear fixture
(`INTERNET → web → app → db`), so expected numbers are arithmetic rather than
values copied out of a previous run. Experiment tests use small trial counts —
they test the harness, not the security result.

**What is and is not verified.** Everything in `domain/`, `graph/`,
`analysis/`, `deception/`, `runtime/`, `experiments/`, `api/` and `agent/` is
covered against real objects. The storage adapters are tested twice: against
SQLite and fakes in `tests/test_storage.py`, and against live Neo4j 5,
PostgreSQL 16 and Redis 7 in `tests/integration/`. Running them live found
bugs the fakes could not. Reloading from Neo4j lost users, services without
vulnerabilities and the hierarchy. Saving one network wiped every other. A
second PostgreSQL session overwrote the first one's decoys and incidents.

The LANL and ML code (`tests/test_lanl_ml.py`) is tested on a small file in
the LANL format (`tests/lanl_fixture.py`), so the pipeline is checked without
the 7 GB download. That fixture tests the code, not the security result: the
detector's and strategies' numbers mean something only on the real dataset.

## Modelling caveats

Worth stating, since the numbers above look precise:

- **The default simulated attacker is naive**, so its detection rates are an
  **upper bound**. The cautious and learning attackers
  ([above](#against-a-smarter-attacker)) give the lower figures. Their own
  parameters (skill 0.6, wariness ceiling 0.7) are judgement calls too.
- **Probabilities are judgement calls.** `cvss/10 × exploitability`, the 0.35
  session-hijack base rate, the 65/35 risk blend — all are documented where
  they are used so they can be argued with, but none is empirically calibrated.
  The `ml` strategy is the one exception: its weights are learned. The
  [sensitivity analysis](#do-the-results-survive-other-guesses) shows the
  winning strategy does not depend on any one of them.
- **False-alert rates are estimates** on the reference networks. On LANL, the
  detector's false alerts per day are measured, scaled up from the 1% sample of
  normal logons.
- **The reference network is too small** to separate the strategies; that is
  why `campus.yaml` exists.
- **One red-team campaign is one attacker.** The LANL results describe how the
  strategies would have fared against that adversary, on that network.

## Status and future work

Everything in the brief is built. So is everything on the original roadmap:

| Roadmap item | Where |
| --- | --- |
| Asset discovery from nmap scans and CMDB exports | `discovery/`, `dgraph import` |
| Integration tests against real Neo4j and PostgreSQL (and Redis) | `tests/integration/`, CI |
| An attacker that becomes cautious after spotting decoys, and learns across campaigns | `runtime/adversary.py`, `dgraph adversary` |
| Sensitivity analysis; experiments on larger generated networks | `experiments/sensitivity.py`, `graph/generator.py`, `dgraph sensitivity`, `dgraph scale` |
| OpenTelemetry traces and Prometheus metrics on the mediator | `runtime/telemetry.py`, `/metrics` |

Beyond the roadmap: real-data evaluation on LANL and two learned models.

Open questions this project cannot settle:

- **One red team.** A second labelled dataset (e.g. DARPA OpTC) would test
  whether the target ranker learned something about attackers in general or
  about this one red team.
- **Calibrating the attacker.** The cautious and learning models are
  plausible, not measured. Their parameters need data on how real intruders
  react to decoys, from red-team exercises run against deployed deception.
- **A live pilot.** Everything here runs offline or in a lab. Deploying decoys
  on a production network, and responding to live incidents, was out of scope
  by design.
