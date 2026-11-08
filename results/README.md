# Results

The raw output behind every number in the main [README](../README.md), so each
claim can be checked against the run that produced it. Everything here is
JSON written by the `dgraph` commands named below.

Not included: the LANL dataset itself, the prepared twin and feature tables
(regenerable, and derived from data LANL distributes under its own terms), and
trained model files (`.joblib` pickles tied to one scikit-learn version). The
`detector.json` and `target_ranker.json` files are the models' metadata:
threshold, training rows, feature list and coefficients.

## Real data: LANL (`lanl/`)

Source: A. D. Kent, *Comprehensive, Multi-Source Cyber-Security Events*, Los
Alamos National Laboratory, 2015 (https://csr.lanl.gov/data/cyber1/).
Days 1–31: 525,453,189 events, 52,673,028 remote user logons, and 701 of 749
red-team events matched. Train before t = 1,072,444 s (350 red-team logons),
test after it (351).

| Directory | Twin | Used for |
| --- | --- | --- |
| [`twin-500/`](lanl/twin-500/) | 500 busiest hosts; 54 of 301 red-team targets inside | **The reported results** |
| [`twin-150/`](lanl/twin-150/) | 150 busiest hosts; 30 of 301 targets inside | The first run, kept for comparison. Too few targets to separate strategies |

Files in each:

| File | Command | What it holds |
| --- | --- | --- |
| `prepare.json` | `dgraph lanl prepare` | Provenance and counts: window, lines read, labels matched, twin size |
| `training_report.json` | `dgraph lanl train --target-fpr 1e-4` | Detector vs rule baseline on the held-out period: average precision, ROC AUC, recall at 0.01/0.1/1% FPR, alerts per day, feature importance; target-ranker coefficients |
| `detector.json`, `target_ranker.json` | (same) | Model metadata |
| `evaluate.json` | `dgraph lanl evaluate` | Every strategy at every budget against the held-out red team: targets hit, logons on a decoy, logons and hours before the first |
| `replay.json` | `dgraph lanl replay` | The held-out period through the ML sensor and a live adaptive deployment |

Headline (`twin-500`):

- Detector recall at a 0.01% false-alarm rate: **70.2%** (rule baseline 21.7%).
  At 0.1%: **91.7%** (44.1%). ROC AUC 1.000 (0.980).
- At budget 10, `ml` and `centrality` both put a decoy under 23% of red-team
  logons. `ml` detects on the 3rd logon (0.3 h), centrality on the 22nd
  (2.5 h). `attack-path` reaches 6%, random 2%.

Reproduce (about 90 minutes for `prepare`, minutes for the rest):

```bash
dgraph lanl prepare --auth auth.txt.gz --redteam redteam.txt.gz --out D:/lanl/prepared500 --max-hosts 500
dgraph lanl train    D:/lanl/prepared500 --models D:/lanl/models500 --target-fpr 1e-4
dgraph lanl evaluate D:/lanl/prepared500 --models D:/lanl/models500 -b 3,5,10,20 --random-trials 200
dgraph lanl replay   D:/lanl/prepared500 --models D:/lanl/models500 -s ml -b 10
```

`twin-150` used `--max-hosts 150` and `evaluate -b 3,5,10` (50 random trials).
Its `replay.json` predates the fix that keeps adaptation under the decoy
ceiling, so it ends with one decoy over the cap.

## Simulation (`simulation/`)

| File | Command | Section in the main README |
| --- | --- | --- |
| [`campus-experiment.json`](simulation/campus-experiment.json) | `dgraph experiment data/networks/campus.yaml -t 1000 --seed 7` | Does the deception actually work? |
| [`campus-adversary.json`](simulation/campus-adversary.json) | `dgraph adversary data/networks/campus.yaml -t 600 --seed 7` | Against a smarter attacker |
| [`campus-sensitivity.json`](simulation/campus-sensitivity.json) | `dgraph sensitivity data/networks/campus.yaml -t 300 --seed 7` | Do the results survive other guesses? |
| [`scale.json`](simulation/scale.json) | `dgraph scale --sizes 50,100,200,400 -t 100 -b 5` | Larger networks |

The simulations are seeded: rerunning a command gives the same detection
numbers. Only the timings in `scale.json` vary from machine to machine.
