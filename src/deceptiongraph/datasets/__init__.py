"""Adapters from public security datasets onto the network model.

Currently one: the LANL "Comprehensive, Multi-Source Cyber-Security Events"
dataset, which gives real enterprise authentication logs and labelled red-team
activity. See :mod:`deceptiongraph.datasets.lanl`.
"""

from .lanl import (
    AUTH_FEATURES,
    AuthEvent,
    AuthFeaturizer,
    LanlAggregator,
    LanlAssetDiscovery,
    PrepareSummary,
    RedTeamEvent,
    build_twin,
    load_redteam_csv,
    parse_auth_line,
    prepare,
    read_auth,
    read_redteam,
)

__all__ = [
    "AUTH_FEATURES",
    "AuthEvent",
    "AuthFeaturizer",
    "LanlAggregator",
    "LanlAssetDiscovery",
    "PrepareSummary",
    "RedTeamEvent",
    "build_twin",
    "load_redteam_csv",
    "parse_auth_line",
    "prepare",
    "read_auth",
    "read_redteam",
]
