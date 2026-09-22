from __future__ import annotations

import pytest

from deceptiongraph.domain.composite import CompositeComponent, HostComponent
from deceptiongraph.domain.entities import Credential, Host, Service, Vulnerability
from deceptiongraph.domain.enums import NodeType, Privilege


def vuln(cvss: float = 10.0, exploitability: float = 1.0, **kwargs) -> Vulnerability:
    return Vulnerability(cve_id=kwargs.pop("cve_id", "CVE-T-1"), cvss=cvss,
                         exploitability=exploitability, **kwargs)


class TestPrivilege:
    def test_is_ordered(self):
        assert Privilege.NONE < Privilege.USER < Privilege.ADMIN < Privilege.ROOT

    def test_max_picks_highest(self):
        highest = max([Privilege.USER, Privilege.ROOT, Privilege.SERVICE], key=lambda p: p.level)
        assert highest is Privilege.ROOT


class TestVulnerability:
    def test_exploit_probability_combines_severity_and_exploitability(self):
        assert vuln(cvss=8.0, exploitability=0.5).exploit_probability == pytest.approx(0.4)

    @pytest.mark.parametrize("cvss", [-1.0, 10.1])
    def test_rejects_out_of_range_cvss(self, cvss):
        with pytest.raises(ValueError, match="cvss"):
            vuln(cvss=cvss)

    def test_rejects_out_of_range_exploitability(self):
        with pytest.raises(ValueError, match="exploitability"):
            vuln(exploitability=1.5)


class TestService:
    def test_combines_vulnerabilities_with_noisy_or(self):
        service = Service(
            id="s", name="http", port=80,
            vulnerabilities=(vuln(cvss=10.0, exploitability=0.5, cve_id="a"),
                             vuln(cvss=10.0, exploitability=0.5, cve_id="b")),
        )
        # 1 - (1-0.5)(1-0.5)
        assert service.exploit_probability == pytest.approx(0.75)

    def test_clean_service_is_not_exploitable(self):
        assert Service(id="s", name="ssh", port=22).exploit_probability == 0.0


class TestHost:
    def test_attack_surface_is_damped_by_patch_level(self):
        services = (Service(id="s", name="http", port=80, vulnerabilities=(vuln(),)),)
        unpatched = Host(id="h", name="H", patch_level=0.0, services=list(services))
        patched = Host(id="h", name="H", patch_level=1.0, services=list(services))

        assert unpatched.attack_surface == pytest.approx(1.0)
        assert patched.attack_surface == pytest.approx(0.3)

    def test_host_without_services_has_no_surface(self):
        assert Host(id="h", name="H").attack_surface == 0.0

    def test_rejects_out_of_range_criticality(self):
        with pytest.raises(ValueError, match="criticality"):
            Host(id="h", name="H", criticality=2.0)

    def test_vulnerabilities_flattens_across_services(self):
        host = Host(
            id="h", name="H",
            services=[
                Service(id="s1", name="a", port=1, vulnerabilities=(vuln(cve_id="a"),)),
                Service(id="s2", name="b", port=2, vulnerabilities=(vuln(cve_id="b"),)),
            ],
        )
        assert {v.cve_id for v in host.vulnerabilities} == {"a", "b"}


class TestCredential:
    def test_weak_credential_is_easily_reused(self):
        assert Credential(id="c", username="u", strength=0.0).reuse_probability == 1.0

    def test_hardened_credential_is_not(self):
        assert Credential(id="c", username="u", strength=1.0).reuse_probability == 0.0


class TestComposite:
    def _host(self, host_id: str, criticality: float, patched: float) -> Host:
        return Host(
            id=host_id, name=host_id.upper(), criticality=criticality, patch_level=patched,
            services=[Service(id=f"{host_id}:s", name="http", port=80, vulnerabilities=(vuln(),))],
        )

    def test_leaf_risk_blends_surface_and_criticality(self):
        score = HostComponent(self._host("web", 0.2, 0.0)).calculate_risk()
        assert score.component_type is NodeType.HOST
        assert score.value == pytest.approx(0.68)
        assert score.breakdown["attack_surface"] == pytest.approx(1.0)

    def test_credentials_raise_leaf_risk(self):
        host = self._host("web", 0.2, 0.0)
        host.credentials.append(Credential(id="c", username="svc", strength=0.0))
        # 0.68 + (1 - 0.68) * 0.25 * 1.0
        assert HostComponent(host).calculate_risk().value == pytest.approx(0.76)

    def test_crown_jewel_gets_a_premium(self):
        plain = self._host("db", 1.0, 1.0)
        jewel = self._host("db", 1.0, 1.0)
        jewel.is_crown_jewel = True
        assert HostComponent(jewel).calculate_risk().value > HostComponent(plain).calculate_risk().value

    def test_same_call_works_on_a_group(self):
        subnet = CompositeComponent("subnet:a", "A", NodeType.SUBNET)
        subnet.add(HostComponent(self._host("web", 0.2, 0.0)))   # 0.68
        subnet.add(HostComponent(self._host("bak", 0.2, 1.0)))   # 0.3 * 0.68

        score = subnet.calculate_risk()
        worst, mean = 0.68, (0.68 + 0.204) / 2
        assert score.value == pytest.approx(0.7 * worst + 0.3 * mean, abs=1e-4)
        assert len(score.children) == 2

    def test_empty_group_has_no_risk(self):
        assert CompositeComponent("x", "X", NodeType.SUBNET).calculate_risk().value == 0.0

    def test_nesting_walks_and_finds_and_collects_hosts(self):
        org = CompositeComponent("org", "Org", NodeType.ORGANISATION)
        dept = CompositeComponent("dept", "Dept", NodeType.DEPARTMENT)
        subnet = CompositeComponent("subnet", "Subnet", NodeType.SUBNET)
        subnet.add(HostComponent(self._host("web", 0.5, 0.5)))
        org.add(dept.add(subnet))

        assert [h.id for h in org.hosts()] == ["web"]
        assert org.find("subnet") is subnet
        assert org.find("nope") is None
        assert len(list(org.walk())) == 4

    def test_remove_drops_a_child(self):
        org = CompositeComponent("org", "Org", NodeType.ORGANISATION)
        org.add(HostComponent(self._host("web", 0.5, 0.5)))
        org.remove("web")
        assert org.children == ()
