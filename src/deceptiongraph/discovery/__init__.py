"""Asset discovery from real inventories: nmap scans and CMDB exports.

Both are Adapters behind the ``AssetDiscovery`` protocol in
:mod:`deceptiongraph.graph.loader`: anything that takes a YAML inventory can
take one of these instead, and both can write their result out as YAML so every
command works on it unchanged.

These *import* inventories; they do not scan. Run nmap yourself, on a network
you are authorised to scan, and hand the XML to :class:`NmapAssetDiscovery`.
Scanning live networks is outside this project's scope, and a tool that
quietly does it for you is a liability.
"""

from .cmdb import CmdbAssetDiscovery
from .nmap import NmapAssetDiscovery, ZonePolicy

__all__ = ["CmdbAssetDiscovery", "NmapAssetDiscovery", "ZonePolicy"]
