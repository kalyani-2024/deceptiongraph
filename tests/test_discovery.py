"""nmap and CMDB importers."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from deceptiongraph.discovery import CmdbAssetDiscovery, NmapAssetDiscovery, ZonePolicy
from deceptiongraph.discovery.nmap import parse_nmap_xml
from deceptiongraph.facade import SecurityFacade
from deceptiongraph.graph.loader import load_network

DATA = Path(__file__).resolve().parents[1] / "data" / "discovery"
SCAN = DATA / "lab-scan.xml"
ZONES = DATA / "lab-zones.yaml"


class TestNmapParsing:
    def test_only_live_hosts_and_open_ports(self):
        hosts = parse_nmap_xml(SCAN)
        assert len(hosts) == 7  # the eighth is down
        www = next(h for h in hosts if h.id == "www")
        assert www.ip == "10.10.1.10" and www.os == "Linux 5.4"
        assert www.ports == {443, 22}

    def test_vulners_cves_are_read_and_exploitdb_ignored(self):
        www = next(h for h in parse_nmap_xml(SCAN) if h.id == "www")
        https = next(s for s in www.services if s["port"] == 443)
        cves = [v["cve"] for v in https["vulnerabilities"]]
        assert cves == ["CVE-2021-23017", "CVE-2023-44487"]  # worst first, EDB dropped
        assert https["vulnerabilities"][0]["exploitability"] == 0.9  # public exploit
        assert https["vulnerabilities"][1]["exploitability"] == 0.4
        assert https["version"] == "nginx 1.18.0"

    def test_bad_xml_is_a_clear_error(self, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("<nmaprun><host>", encoding="utf-8")
        with pytest.raises(ValueError, match="not valid nmap XML"):
            parse_nmap_xml(bad)
        other = tmp_path / "other.xml"
        other.write_text("<html/>", encoding="utf-8")
        with pytest.raises(ValueError, match="expected <nmaprun>"):
            parse_nmap_xml(other)

    def test_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            parse_nmap_xml(tmp_path / "nope.xml")


class TestZonePolicy:
    def test_most_specific_subnet_wins(self, tmp_path):
        policy_file = tmp_path / "zones.yaml"
        policy_file.write_text(yaml.safe_dump({"zones": [
            {"cidr": "10.0.0.0/8", "exposure": "INTERNAL"},
            {"cidr": "10.9.0.0/16", "exposure": "RESTRICTED"},
        ]}), encoding="utf-8")
        policy = ZonePolicy.load(policy_file)
        assert policy.exposure_of("10.9.1.1") == "RESTRICTED"
        assert policy.exposure_of("10.1.1.1") == "INTERNAL"
        assert policy.exposure_of("192.168.1.1") == "INTERNAL"  # default
        assert policy.exposure_of("not-an-ip") == "INTERNAL"

    def test_deny_removes_a_default_flow(self, tmp_path):
        policy_file = tmp_path / "zones.yaml"
        policy_file.write_text(yaml.safe_dump({"deny": [{"from": "dmz", "to": "internal"}]}),
                               encoding="utf-8")
        assert ("DMZ", "INTERNAL") not in ZonePolicy.load(policy_file).flows


class TestNmapDiscovery:
    @pytest.fixture
    def model(self):
        return NmapAssetDiscovery(SCAN, ZONES).discover()

    def test_zones_crown_jewels_and_accounts_come_from_the_policy(self, model):
        assert model.name == "lab"
        assert set(model.entry_points) == {"www", "vpn"}
        assert set(model.crown_jewels) == {"dc01", "db01"}
        assert model.hosts["dc01"].patch_level == 0.3
        assert model.hosts["app01"].credentials[0].grants_access == ("db01",)
        assert "user:anna" in model.users

    def test_criticality_is_guessed_from_services_and_tagged(self, model):
        assert "role=directory" in model.hosts["dc01"].tags
        assert "role=database" in model.hosts["db01"].tags
        assert model.hosts["files01"].criticality > model.hosts["www"].criticality

    def test_flows_follow_the_policy(self, model):
        pairs = {(c.source, c.target): c.filtered for c in model.connections}
        assert pairs[("www", "vpn")] == 0.0          # same zone
        assert pairs[("www", "app01")] == 0.4        # INTERNET -> INTERNAL
        assert pairs[("app01", "db01")] == 0.5       # INTERNAL -> RESTRICTED
        assert ("db01", "www") not in pairs           # no RESTRICTED -> INTERNET flow

    def test_the_imported_network_analyses(self, model):
        security = SecurityFacade(model)
        paths = security.analyse_network().crown_jewel_paths
        assert set(paths) == {"dc01", "db01"}
        assert len(security.deploy_deception(budget=2).assets) == 2

    def test_without_a_policy_the_most_valuable_hosts_become_crown_jewels(self):
        model = NmapAssetDiscovery(SCAN).discover()
        assert "dc01" in model.crown_jewels
        assert not model.entry_points  # everything INTERNAL by default


class TestCmdb:
    def test_import(self):
        model = CmdbAssetDiscovery(DATA / "cmdb").discover()
        assert len(model.hosts) == 6
        assert model.crown_jewels == ("payroll-db",)
        assert set(model.entry_points) == {"portal", "mail"}
        erp = model.hosts["erp"]
        assert erp.services[0].vulnerabilities[0].cve_id == "CVE-2020-6287"
        assert erp.services[0].vulnerabilities[0].cvss == 10.0
        assert model.hosts["jump"].credentials[0].grants_access == ("erp", "hr-app", "payroll-db")
        assert "owner=finance" in erp.tags

    def test_messy_headers_are_tolerated(self, tmp_path):
        (tmp_path / "hosts.csv").write_text(
            "﻿ ID , Name ,Exposure,Crown_Jewel\nh1,Host one,internet,\nh2,Host two,,yes\n",
            encoding="utf-8")
        model = CmdbAssetDiscovery(tmp_path).discover()
        assert model.hosts["h1"].exposure.value == "INTERNET"
        assert model.crown_jewels == ("h2",)

    def test_errors_name_the_file_and_line(self, tmp_path):
        (tmp_path / "hosts.csv").write_text("id,criticality\nh1,high\n", encoding="utf-8")
        with pytest.raises(ValueError, match=r"hosts.csv:2: expected a number"):
            CmdbAssetDiscovery(tmp_path).discover()

    def test_unknown_host_in_services(self, tmp_path):
        (tmp_path / "hosts.csv").write_text("id\nh1\n", encoding="utf-8")
        (tmp_path / "services.csv").write_text("host_id,name,port\nghost,ssh,22\n",
                                               encoding="utf-8")
        with pytest.raises(ValueError, match=r"services.csv:2: unknown host 'ghost'"):
            CmdbAssetDiscovery(tmp_path).discover()

    def test_hosts_csv_is_required(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="hosts.csv"):
            CmdbAssetDiscovery(tmp_path).discover()


def test_cli_imports_write_loadable_networks(tmp_path):
    from typer.testing import CliRunner

    from deceptiongraph.cli.main import app

    runner = CliRunner()
    out = tmp_path / "lab.yaml"
    result = runner.invoke(app, ["import", "nmap", str(SCAN), "-z", str(ZONES), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert set(load_network(out).crown_jewels) == {"dc01", "db01"}

    out = tmp_path / "cmdb.yaml"
    result = runner.invoke(app, ["import", "cmdb", str(DATA / "cmdb"), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert len(load_network(out).hosts) == 6

    result = runner.invoke(app, ["import", "nmap", str(SCAN), "-o", str(tmp_path / "x.yaml")])
    assert result.exit_code == 0 and "no --zones policy" in result.output
