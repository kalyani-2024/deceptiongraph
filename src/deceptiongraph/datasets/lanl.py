"""The LANL enterprise dataset, adapted onto DeceptionGraph.

Source: A. D. Kent, "Comprehensive, Multi-Source Cyber-Security Events",
Los Alamos National Laboratory, 2015. https://csr.lanl.gov/data/cyber1/

58 days of de-identified events from LANL's corporate network: 12,425 users,
17,684 computers, and a set of labelled red-team compromise events. Two files
are used here:

``auth.txt.gz`` (7.2 GB)
    ``time,src user@domain,dst user@domain,src computer,dst computer,
    auth type,logon type,auth orientation,success/failure``
``redteam.txt.gz`` (4.8 KB)
    ``time,user@domain,src computer,dst computer`` - the ground truth.

What this module turns them into:

* **A digital twin** (``network.yaml``). Hosts are computers; a user who logged
  on from ``src`` to ``dst`` leaves a cached credential on ``src`` that grants
  access to ``dst`` - which is exactly how the red team moved (stolen
  credentials, mostly NTLM). The twin is built from *normal* behaviour only:
  every (user, src, dst) triple the red team used is left out, so the attacker's
  own moves cannot leak into the model that is later used to place decoys.
* **Per-logon features** (``auth_features.csv.gz``) for the lateral-movement
  detector, computed in one streaming pass in time order, so each row only
  sees the past. All red-team rows are kept; normal rows are sampled at
  ``negative_rate`` and carry weight ``1 / negative_rate`` so metrics can be
  reported as if on the full stream.

Modelling assumptions that do not come from the data, stated so they can be
argued with:

* LANL has no vulnerability data. Workstations get one weakness standing for
  phishing / user execution (MITRE T1566) so the twin has an entry point;
  servers get none, so lateral movement is credential-driven - which is also
  what the red-team data shows.
* Host roles and criticality are inferred from logon patterns: a host many
  distinct users log on *to* is a server, and the most-used servers (in
  practice the domain controllers) become the crown jewels.
* Time is LANL's de-identified clock: seconds from an undisclosed epoch.
  "Hour of day" is therefore a phase, not a wall-clock hour.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import math
import random
import sys
import time as _time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, TextIO

import yaml

from ..graph.loader import build_model
from ..graph.model import NetworkModel

SECONDS_PER_DAY = 86_400

AUTH_FEATURES: tuple[str, ...] = (
    "new_user_dst",
    "new_user_src",
    "new_pair",
    "user_dst_count",
    "user_src_count",
    "dst_user_count",
    "src_user_count",
    "user_fail_count",
    "auth_ntlm",
    "logon_network",
    "hour_sin",
    "hour_cos",
)
"""Features of one remote logon, all computed from history before it.

The ``*_count`` features are ``log1p`` of distinct counts, so a host with 2,000
users and one with 20,000 are not a hundred-fold apart.
"""

PHISHING_WEAKNESS = {
    "cve": "T1566-phishing",
    "cvss": 6.0,
    "exploitability": 0.25,
    "privilege_gained": "USER",
    "description": "Assumed: a user on this workstation can be phished (MITRE T1566). "
    "LANL publishes no vulnerability data.",
}


# -- parsing ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """One line of ``auth.txt``."""

    time: int
    src_user: str
    dst_user: str
    src: str
    dst: str
    auth_type: str
    logon_type: str
    orientation: str
    success: bool

    @property
    def user(self) -> str:
        """The source user without its domain, e.g. ``U748``."""
        return self.src_user.split("@", 1)[0]

    @property
    def is_human(self) -> bool:
        """De-identified people are ``U<n>``; machines end in ``$``."""
        return _is_human(self.user)

    @property
    def is_remote(self) -> bool:
        return self.src != self.dst and "?" not in (self.src, self.dst)

    @property
    def is_lateral_logon(self) -> bool:
        """The kind of event lateral movement consists of."""
        return self.orientation == "LogOn" and self.is_human and self.is_remote


@dataclass(frozen=True, slots=True)
class RedTeamEvent:
    """One line of ``redteam.txt``: a known compromise."""

    time: int
    user: str
    src: str
    dst: str

    @property
    def key(self) -> tuple[int, str, str, str]:
        return (self.time, self.user, self.src, self.dst)

    @property
    def triple(self) -> tuple[str, str, str]:
        return (self.user, self.src, self.dst)


def open_text(path: str | Path) -> TextIO:
    """Open a plain or gzipped text file for streaming."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"dataset file not found: {path}")
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="ascii", errors="replace")
    return path.open("r", encoding="ascii", errors="replace")


def parse_auth_line(line: str) -> AuthEvent | None:
    """Parse one auth line, or None if it is malformed."""
    parts = line.rstrip("\r\n").split(",")
    if len(parts) != 9:
        return None
    try:
        when = int(parts[0])
    except ValueError:
        return None
    return AuthEvent(
        time=when, src_user=parts[1], dst_user=parts[2], src=parts[3], dst=parts[4],
        auth_type=parts[5], logon_type=parts[6], orientation=parts[7],
        success=parts[8] == "Success",
    )


def read_auth(
    path: str | Path, start: int = 0, until: int | None = None
) -> Iterator[AuthEvent]:
    """Stream auth events in ``[start, until)``. The file is time-ordered."""
    with open_text(path) as handle:
        for line in handle:
            event = parse_auth_line(line)
            if event is None or event.time < start:
                continue
            if until is not None and event.time >= until:
                break
            yield event


def read_redteam(
    path: str | Path, start: int = 0, until: int | None = None
) -> list[RedTeamEvent]:
    """Load the labelled compromise events in ``[start, until)``."""
    events = []
    with open_text(path) as handle:
        for line in handle:
            parts = line.strip().split(",")
            if len(parts) != 4:
                continue
            try:
                when = int(parts[0])
            except ValueError:
                continue
            if when < start or (until is not None and when >= until):
                continue
            events.append(
                RedTeamEvent(time=when, user=parts[1].split("@", 1)[0], src=parts[2], dst=parts[3])
            )
    events.sort(key=lambda e: e.time)
    return events


def load_redteam_csv(path: str | Path) -> list[RedTeamEvent]:
    """Read back the ``redteam.csv`` that :func:`prepare` writes."""
    with Path(path).open(newline="", encoding="utf-8") as handle:
        return [
            RedTeamEvent(time=int(r["time"]), user=r["user"], src=r["src"], dst=r["dst"])
            for r in csv.DictReader(handle)
        ]


def _is_human(user: str) -> bool:
    return len(user) > 1 and user[0] == "U" and user[1:].isdigit()


# -- streaming features ----------------------------------------------------


class AuthFeaturizer:
    """Turns a time-ordered stream of logons into feature vectors.

    Stateful and causal: :meth:`step` scores an event against everything seen
    *before* it, then folds it into the history. The same object serves the
    offline pass in :func:`prepare` and a live sensor, so training and
    deployment compute features identically.
    """

    def __init__(self) -> None:
        self._user_dsts: dict[str, set[str]] = defaultdict(set)
        self._user_srcs: dict[str, set[str]] = defaultdict(set)
        self._dst_users: dict[str, set[str]] = defaultdict(set)
        self._src_users: dict[str, set[str]] = defaultdict(set)
        self._pairs: set[tuple[str, str]] = set()
        self._user_fails: Counter[str] = Counter()
        self.observed = 0

    def observe_failure(self, user: str) -> None:
        self._user_fails[user] += 1

    def features(
        self, user: str, src: str, dst: str, auth_type: str, logon_type: str, when: int
    ) -> list[float]:
        """Feature vector for one logon, without updating the history."""
        dsts = self._user_dsts.get(user)
        srcs = self._user_srcs.get(user)
        phase = 2.0 * math.pi * ((when % SECONDS_PER_DAY) / SECONDS_PER_DAY)
        return [
            0.0 if dsts and dst in dsts else 1.0,
            0.0 if srcs and src in srcs else 1.0,
            0.0 if (src, dst) in self._pairs else 1.0,
            math.log1p(len(dsts) if dsts else 0),
            math.log1p(len(srcs) if srcs else 0),
            math.log1p(len(self._dst_users.get(dst, ()))),
            math.log1p(len(self._src_users.get(src, ()))),
            math.log1p(self._user_fails.get(user, 0)),
            1.0 if auth_type == "NTLM" else 0.0,
            1.0 if logon_type == "Network" else 0.0,
            math.sin(phase),
            math.cos(phase),
        ]

    def update(self, user: str, src: str, dst: str) -> None:
        self._user_dsts[user].add(dst)
        self._user_srcs[user].add(src)
        self._dst_users[dst].add(user)
        self._src_users[src].add(user)
        self._pairs.add((src, dst))
        self.observed += 1

    def step(
        self, user: str, src: str, dst: str, auth_type: str, logon_type: str, when: int
    ) -> list[float]:
        """Features for this logon, then remember it."""
        vector = self.features(user, src, dst, auth_type, logon_type, when)
        self.update(user, src, dst)
        return vector

    def step_event(self, event: AuthEvent) -> list[float]:
        return self.step(
            event.user, event.src, event.dst, event.auth_type, event.logon_type, event.time
        )


# -- topology --------------------------------------------------------------


@dataclass(slots=True)
class LanlAggregator:
    """Counts the normal behaviour the digital twin is built from."""

    triples: Counter = field(default_factory=Counter)
    """(user, src, dst) -> successful remote logons."""
    ntlm: Counter = field(default_factory=Counter)
    """(user, src, dst) -> of which NTLM."""
    events: int = 0

    def add(self, user: str, src: str, dst: str, auth_type: str) -> None:
        key = (user, src, dst)
        self.triples[key] += 1
        if auth_type == "NTLM":
            self.ntlm[key] += 1
        self.events += 1

    def host_stats(self) -> dict[str, dict]:
        """Per-host activity, the basis for roles and criticality."""
        in_users: dict[str, set] = defaultdict(set)
        out_users: dict[str, set] = defaultdict(set)
        in_logons: Counter = Counter()
        out_logons: Counter = Counter()
        in_ntlm: Counter = Counter()
        for (user, src, dst), count in self.triples.items():
            in_users[dst].add(user)
            out_users[src].add(user)
            in_logons[dst] += count
            out_logons[src] += count
            in_ntlm[dst] += self.ntlm.get((user, src, dst), 0)

        stats = {}
        for host in set(in_logons) | set(out_logons):
            n_in = len(in_users.get(host, ()))
            n_out = len(out_users.get(host, ()))
            stats[host] = {
                "in_users": n_in,
                "out_users": n_out,
                "in_logons": in_logons.get(host, 0),
                "out_logons": out_logons.get(host, 0),
                "ntlm_share": round(in_ntlm[host] / in_logons[host], 4) if in_logons[host] else 0.0,
                "role": "server" if n_in >= max(3, n_out) else "workstation",
            }
        return stats

    def user_reach(self) -> dict[str, set[str]]:
        """Every destination each user has logged on to."""
        reach: dict[str, set[str]] = defaultdict(set)
        for user, _src, dst in self.triples:
            reach[user].add(dst)
        return reach


def build_twin(
    aggregator: LanlAggregator,
    max_hosts: int = 150,
    crown_jewels: int = 3,
    extra_hosts: Iterable[str] = (),
    name: str = "lanl",
    max_credentials_per_host: int = 12,
    max_user_hosts: int = 12,
    admin_threshold: int = 10,
) -> dict:
    """Build a loader-shaped network definition from observed behaviour.

    Returns the same structure a YAML network file has, so the twin can be
    written out and every existing command works on it unchanged.

    ``max_hosts`` keeps the most active computers; the full 17,684-host network
    is far beyond what a deception budget of a handful of decoys is about, and
    the attack-graph analysis is quadratic in places.
    """
    stats = aggregator.host_stats()
    if not stats:
        raise ValueError("no remote user logons in the window; nothing to build a twin from")

    ranked = sorted(stats, key=lambda h: (stats[h]["in_logons"] + stats[h]["out_logons"], h),
                    reverse=True)
    chosen = set(ranked[:max_hosts]) | {h for h in extra_hosts if h in stats}

    servers = [h for h in chosen if stats[h]["role"] == "server"]
    jewels = set(sorted(servers, key=lambda h: (stats[h]["in_users"], h), reverse=True)[:crown_jewels])
    max_in = max((stats[h]["in_users"] for h in chosen), default=1) or 1

    reach = aggregator.user_reach()
    admins = {u for u, dsts in reach.items() if len(dsts) >= admin_threshold}

    # Credentials: what each user leaves cached on the host they log on from.
    by_src: dict[str, dict[str, dict]] = defaultdict(dict)
    pairs: Counter = Counter()
    user_hosts: dict[str, set[str]] = defaultdict(set)
    for (user, src, dst), count in aggregator.triples.items():
        if src not in chosen or dst not in chosen:
            continue
        pairs[(src, dst)] += count
        user_hosts[user].update((src, dst))
        entry = by_src[src].setdefault(user, {"grants": set(), "count": 0, "ntlm": 0})
        entry["grants"].add(dst)
        entry["count"] += count
        entry["ntlm"] += aggregator.ntlm.get((user, src, dst), 0)

    hosts = []
    for host_id in sorted(chosen):
        s = stats[host_id]
        is_jewel = host_id in jewels
        if is_jewel:
            exposure, criticality = "RESTRICTED", 0.95
        elif s["role"] == "server":
            exposure = "INTERNAL"
            criticality = 0.3 + 0.6 * math.log1p(s["in_users"]) / math.log1p(max_in)
        else:
            exposure, criticality = "INTERNET", 0.2

        services = [{"name": "smb", "port": 445}]
        if s["role"] == "workstation" and not is_jewel:
            services.append(
                {"name": "user-session", "port": 0, "vulnerabilities": [dict(PHISHING_WEAKNESS)]}
            )

        cached = sorted(by_src.get(host_id, {}).items(),
                        key=lambda kv: (kv[1]["count"], kv[0]), reverse=True)
        credentials = []
        for user, entry in cached[:max_credentials_per_host]:
            ntlm_share = entry["ntlm"] / entry["count"] if entry["count"] else 0.0
            credentials.append({
                "id": f"{host_id}:cred:{user}",
                "username": user,
                "kind": "ntlm-hash" if ntlm_share > 0.5 else "kerberos-ticket",
                # Pass-the-hash makes a cached NTLM secret far easier to replay.
                "strength": 0.3 if ntlm_share > 0.5 else 0.6,
                "privilege": "ADMIN" if user in admins else "USER",
                "grants_access": sorted(entry["grants"]),
            })

        hosts.append({
            "id": host_id,
            "name": host_id,
            "os": "windows",
            "exposure": exposure,
            "criticality": round(min(1.0, criticality), 4),
            "crown_jewel": is_jewel,
            "patch_level": 0.5,
            "tags": [s["role"], f"in_users={s['in_users']}", f"out_users={s['out_users']}"],
            "services": services,
            "credentials": credentials,
        })

    users = [
        {
            "id": f"user:{user}",
            "username": user,
            "role": "admin" if user in admins else "employee",
            "privilege": "ADMIN" if user in admins else "USER",
            "logs_into": sorted(hs),
        }
        # Accounts spread over many hosts (service and admin accounts) would add
        # a trusted-session edge between every pair of them; their credentials
        # already carry that reach, so they are left out of the session vector.
        for user, hs in sorted(user_hosts.items())
        if 2 <= len(hs) <= max_user_hosts
    ]

    connections = [
        {"from": src, "to": dst, "protocol": "tcp", "ports": [445], "filtered": 0.0}
        for (src, dst) in sorted(pairs)
    ]

    return {"name": name, "hosts": hosts, "users": users, "connections": connections}


# -- the adapter -----------------------------------------------------------


class LanlAssetDiscovery:
    """Adapter: LANL authentication logs behind the ``AssetDiscovery`` protocol.

    Anything that accepts an asset-discovery source can take this instead of a
    YAML inventory. It reads the raw logs every time, which for the full
    7.2 GB file takes a while - :func:`prepare` does it once and writes the
    twin out as YAML, which is what you normally want.
    """

    def __init__(
        self,
        auth_path: str | Path,
        redteam_path: str | Path | None = None,
        start: int = 0,
        until: int | None = None,
        max_hosts: int = 150,
        crown_jewels: int = 3,
    ) -> None:
        self.auth_path = Path(auth_path)
        self.redteam_path = Path(redteam_path) if redteam_path else None
        self.start = start
        self.until = until
        self.max_hosts = max_hosts
        self.crown_jewels = crown_jewels

    def discover(self) -> NetworkModel:
        excluded: set[tuple[str, str, str]] = set()
        if self.redteam_path is not None:
            excluded = {e.triple for e in read_redteam(self.redteam_path, self.start, self.until)}
        aggregator = LanlAggregator()
        for event in read_auth(self.auth_path, self.start, self.until):
            if not (event.success and event.is_lateral_logon):
                continue
            if (event.user, event.src, event.dst) in excluded:
                continue
            aggregator.add(event.user, event.src, event.dst, event.auth_type)
        raw = build_twin(aggregator, max_hosts=self.max_hosts, crown_jewels=self.crown_jewels)
        return build_model(raw, default_name="lanl")


# -- one-pass preparation --------------------------------------------------


@dataclass(slots=True)
class PrepareSummary:
    """What :func:`prepare` read and wrote."""

    out_dir: str
    lines_read: int
    lateral_logons: int
    window: tuple[int, int | None]
    redteam_events: int
    redteam_matched: int
    positive_rows: int
    negative_rows: int
    negative_rate: float
    twin_hosts: int
    twin_connections: int
    redteam_targets: int
    redteam_targets_in_twin: int
    seconds: float

    def as_dict(self) -> dict:
        data = asdict(self)
        data["window"] = list(self.window)
        return data


def prepare(
    auth_path: str | Path,
    redteam_path: str | Path,
    out_dir: str | Path,
    *,
    start: int = 0,
    until: int | None = 31 * SECONDS_PER_DAY,
    negative_rate: float = 0.01,
    max_hosts: int = 150,
    crown_jewels: int = 3,
    include_redteam_hosts: bool = False,
    seed: int = 7,
    max_lines: int | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> PrepareSummary:
    """Stream the raw LANL files once and write everything the system needs.

    ``until`` defaults to day 31, which covers every red-team event while
    reading about half of the 7.2 GB file. ``include_redteam_hosts`` adds the
    red team's targets to the twin even if they are not among the busiest
    ``max_hosts`` - useful for evaluating placement against them, but it is
    selection on the label, so it is off by default and recorded in
    ``meta.json`` when used.
    """
    if not 0.0 < negative_rate <= 1.0:
        raise ValueError(f"negative_rate must be in (0, 1], got {negative_rate}")
    began = _time.perf_counter()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    redteam = read_redteam(redteam_path, start, until)
    labels = {e.key for e in redteam}
    attacker_triples = {e.triple for e in redteam}

    featurizer = AuthFeaturizer()
    aggregator = LanlAggregator()
    rng = random.Random(seed)
    intern = sys.intern
    lines = lateral = positives = negatives = 0
    matched: set[tuple[int, str, str, str]] = set()

    with gzip.open(out / "auth_features.csv.gz", "wt", newline="", encoding="utf-8") as raw_out:
        writer = csv.writer(raw_out)
        writer.writerow(["time", "user", "src", "dst", *AUTH_FEATURES, "label", "weight"])

        with open_text(auth_path) as handle:
            for line in handle:
                lines += 1
                if progress is not None and lines % 1_000_000 == 0:
                    progress(lines, lateral)
                if max_lines is not None and lines > max_lines:
                    break

                parts = line.rstrip("\r\n").split(",")
                if len(parts) != 9:
                    continue
                # Cheap rejections first: almost every line is a machine account
                # or a local logon, and this loop runs a billion times.
                src_user = parts[1]
                if not src_user.startswith("U") or parts[7] != "LogOn":
                    continue
                src, dst = parts[3], parts[4]
                if src == dst or src == "?" or dst == "?":
                    continue
                user = src_user.split("@", 1)[0]
                if not _is_human(user):
                    continue
                try:
                    when = int(parts[0])
                except ValueError:
                    continue
                if when < start:
                    continue
                if until is not None and when >= until:
                    break

                user, src, dst = intern(user), intern(src), intern(dst)
                if parts[8] != "Success":
                    featurizer.observe_failure(user)
                    continue

                lateral += 1
                vector = featurizer.step(user, src, dst, parts[5], parts[6], when)
                key = (when, user, src, dst)
                is_attack = key in labels
                if is_attack:
                    matched.add(key)
                    positives += 1
                    writer.writerow([when, user, src, dst, *_fmt(vector), 1, 1.0])
                elif rng.random() < negative_rate:
                    negatives += 1
                    writer.writerow([when, user, src, dst, *_fmt(vector), 0,
                                     round(1.0 / negative_rate, 6)])

                if (user, src, dst) not in attacker_triples:
                    aggregator.add(user, src, dst, parts[5])

    targets = {e.dst for e in redteam}
    raw = build_twin(
        aggregator, max_hosts=max_hosts, crown_jewels=crown_jewels,
        extra_hosts=targets if include_redteam_hosts else (),
    )
    twin_hosts = {h["id"] for h in raw["hosts"]}

    (out / "network.yaml").write_text(
        "# Digital twin built from the LANL authentication logs by `dgraph lanl prepare`.\n"
        "# Normal behaviour only: every (user, src, dst) the red team used is excluded.\n"
        + yaml.safe_dump(raw, sort_keys=False),
        encoding="utf-8",
    )

    with (out / "redteam.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["time", "user", "src", "dst", "in_twin"])
        for e in redteam:
            writer.writerow([e.time, e.user, e.src, e.dst, int(e.dst in twin_hosts)])

    stats = aggregator.host_stats()
    with (out / "hosts.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        columns = ["in_users", "out_users", "in_logons", "out_logons", "ntlm_share", "role"]
        writer.writerow(["host", *columns, "in_twin"])
        for host in sorted(stats):
            writer.writerow([host, *(stats[host][c] for c in columns), int(host in twin_hosts)])

    summary = PrepareSummary(
        out_dir=str(out),
        lines_read=lines,
        lateral_logons=lateral,
        window=(start, until),
        redteam_events=len(redteam),
        redteam_matched=len(matched),
        positive_rows=positives,
        negative_rows=negatives,
        negative_rate=negative_rate,
        twin_hosts=len(twin_hosts),
        twin_connections=len(raw["connections"]),
        redteam_targets=len(targets),
        redteam_targets_in_twin=len(targets & twin_hosts),
        seconds=round(_time.perf_counter() - began, 1),
    )
    meta = {
        "dataset": "LANL Comprehensive, Multi-Source Cyber-Security Events",
        "citation": "A. D. Kent, 'Cybersecurity Data Sources for Dynamic Network Research', "
        "in Dynamic Networks in Cybersecurity, 2015.",
        "url": "https://csr.lanl.gov/data/cyber1/",
        "auth_file": str(auth_path),
        "redteam_file": str(redteam_path),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "features": list(AUTH_FEATURES),
        "max_hosts": max_hosts,
        "crown_jewels": crown_jewels,
        "include_redteam_hosts": include_redteam_hosts,
        "seed": seed,
        "summary": summary.as_dict(),
    }
    (out / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return summary


def _fmt(vector: list[float]) -> list:
    return [round(v, 5) for v in vector]
