"""A tiny dataset in the LANL file format, for tests.

The real files are 7 GB and need a download form, so the tests run against
this instead. It is *not* a stand-in for the real data in any result - it
exists to exercise the parser, the streaming pass, the twin builder and the
models end to end.

Shape: 40 workstations (C1-C40), 8 servers (C100-C107), 2 domain controllers
(C200, C201), 60 users each with a home workstation. Normal users log on from
home to the DCs and to two favourite servers, mostly with Kerberos. From day 2
the "red team" works from C999, replaying stolen accounts over NTLM to hosts
those accounts never used.
"""

from __future__ import annotations

import gzip
import random
from pathlib import Path

DAY = 86_400
WORKSTATIONS = [f"C{i}" for i in range(1, 41)]
SERVERS = [f"C{i}" for i in range(100, 108)]
DCS = ["C200", "C201"]
ATTACKER = "C999"


def write_fixture(directory: Path, days: int = 6, seed: int = 11) -> tuple[Path, Path]:
    """Write ``auth.txt.gz`` and ``redteam.txt.gz`` into ``directory``."""
    rng = random.Random(seed)
    directory.mkdir(parents=True, exist_ok=True)
    users = [f"U{i}" for i in range(1, 61)]
    home = {u: WORKSTATIONS[i % len(WORKSTATIONS)] for i, u in enumerate(users)}
    favourites = {u: rng.sample(SERVERS, 2) for u in users}

    lines: list[tuple[int, str]] = []

    def auth(t, user, src, dst, auth_type="Kerberos", logon="Network", orient="LogOn",
             ok="Success"):
        dom = "DOM1"
        lines.append((t, f"{t},{user}@{dom},{user}@{dom},{src},{dst},{auth_type},{logon},"
                         f"{orient},{ok}"))

    for day in range(days):
        base = day * DAY
        for user in users:
            for _ in range(3):
                t = base + rng.randint(8 * 3600, 18 * 3600)
                auth(t, user, home[user], rng.choice(DCS))
            for server in favourites[user]:
                t = base + rng.randint(8 * 3600, 18 * 3600)
                auth(t, user, home[user], server,
                     auth_type="NTLM" if rng.random() < 0.1 else "Kerberos")
            if rng.random() < 0.05:  # the occasional new server, so novelty is not a giveaway
                t = base + rng.randint(8 * 3600, 18 * 3600)
                auth(t, user, home[user], rng.choice(SERVERS))
            if rng.random() < 0.05:
                t = base + rng.randint(0, DAY - 1)
                auth(t, user, home[user], rng.choice(DCS), ok="Fail")
            # Local interactive logon: filtered out (src == dst).
            t = base + rng.randint(7 * 3600, 9 * 3600)
            auth(t, user, home[user], home[user], logon="Interactive")
        for ws in WORKSTATIONS:
            # Machine accounts: filtered out (not U<n>).
            t = base + rng.randint(0, DAY - 1)
            lines.append((t, f"{t},{ws}$@DOM1,{ws}$@DOM1,{ws},{rng.choice(DCS)},"
                             "Kerberos,Network,LogOn,Success"))

    redteam: list[tuple[int, str, str, str]] = []
    stolen = users[:15]
    targets = SERVERS[:5] + WORKSTATIONS[:6]
    for day in range(1, min(days, 5)):
        for _ in range(12):
            t = day * DAY + rng.randint(0, DAY - 1)
            user = rng.choice(stolen)
            dst = rng.choice(targets)
            auth(t, user, ATTACKER, dst, auth_type="NTLM")
            redteam.append((t, user, ATTACKER, dst))

    lines.sort(key=lambda item: item[0])
    auth_path = directory / "auth.txt.gz"
    with gzip.open(auth_path, "wt", encoding="ascii") as handle:
        handle.write("\n".join(text for _, text in lines) + "\n")

    redteam.sort()
    redteam_path = directory / "redteam.txt.gz"
    with gzip.open(redteam_path, "wt", encoding="ascii") as handle:
        handle.write("\n".join(f"{t},{u}@DOM1,{s},{d}" for t, u, s, d in redteam) + "\n")
    return auth_path, redteam_path
