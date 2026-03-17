"""Tests for Config.from_yaml_clients() and load_all_configs()."""
from __future__ import annotations

import os
import textwrap
import pytest

from monitor.config import Config, load_all_configs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_yaml(tmp_path, content: str) -> str:
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(content))
    return str(p)


# ---------------------------------------------------------------------------
# from_yaml_clients()
# ---------------------------------------------------------------------------

class TestFromYamlClients:
    def test_basic_two_clients(self, tmp_path):
        path = _write_yaml(tmp_path, """
            database_url: sqlite:///test.db
            nmap_ports: top-100
            clients:
              acme:
                targets:
                  - 203.0.113.1
                  - api.acme.com
              globex:
                targets:
                  - 198.51.100.0/28
        """)
        configs = Config.from_yaml_clients(path)
        assert len(configs) == 2

        acme = next(c for c in configs if c.client_id == "acme")
        assert acme.targets == ["203.0.113.1", "api.acme.com"]
        assert acme.database_url == "sqlite:///test.db"
        assert acme.nmap_ports == "top-100"

        globex = next(c for c in configs if c.client_id == "globex")
        assert globex.targets == ["198.51.100.0/28"]
        assert globex.database_url == "sqlite:///test.db"

    def test_client_id_comes_from_yaml_key(self, tmp_path):
        path = _write_yaml(tmp_path, """
            clients:
              my-client:
                targets: [1.2.3.4]
        """)
        configs = Config.from_yaml_clients(path)
        assert configs[0].client_id == "my-client"

    def test_per_client_override(self, tmp_path):
        path = _write_yaml(tmp_path, """
            nmap_ports: top-1000
            clients:
              fast:
                targets: [10.0.0.1]
                nmap_ports: top-100
              full:
                targets: [10.0.0.2]
        """)
        configs = Config.from_yaml_clients(path)
        fast = next(c for c in configs if c.client_id == "fast")
        full = next(c for c in configs if c.client_id == "full")
        assert fast.nmap_ports == "top-100"   # per-client override
        assert full.nmap_ports == "top-1000"  # inherits global default

    def test_missing_clients_section_raises(self, tmp_path):
        path = _write_yaml(tmp_path, """
            targets: [1.2.3.4]
        """)
        with pytest.raises(ValueError, match="No 'clients' section"):
            Config.from_yaml_clients(path)

    def test_client_without_targets_raises(self, tmp_path):
        path = _write_yaml(tmp_path, """
            clients:
              bad:
                nmap_ports: top-100
        """)
        with pytest.raises(ValueError, match="no targets"):
            Config.from_yaml_clients(path)

    def test_env_overrides_global_defaults(self, tmp_path, monkeypatch):
        path = _write_yaml(tmp_path, """
            database_url: sqlite:///original.db
            clients:
              acme:
                targets: [1.2.3.4]
        """)
        monkeypatch.setenv("DATABASE_URL", "postgresql://override/db")
        configs = Config.from_yaml_clients(path)
        assert configs[0].database_url == "postgresql://override/db"

    def test_env_does_not_override_per_client_value(self, tmp_path, monkeypatch):
        path = _write_yaml(tmp_path, """
            nmap_ports: top-1000
            clients:
              acme:
                targets: [1.2.3.4]
                nmap_ports: top-50
        """)
        monkeypatch.setenv("MONITOR_NMAP_PORTS", "top-200")
        configs = Config.from_yaml_clients(path)
        # per-client YAML wins over env
        assert configs[0].nmap_ports == "top-50"

    def test_defaults_applied_when_not_in_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, """
            clients:
              acme:
                targets: [1.2.3.4]
        """)
        configs = Config.from_yaml_clients(path)
        c = configs[0]
        # Check a few dataclass defaults are still in effect
        assert c.nmap_arguments == "-sV --open -T4 -Pn"
        assert c.banner_grab is True
        assert c.monitor_mode == "all"

    def test_single_client(self, tmp_path):
        path = _write_yaml(tmp_path, """
            clients:
              only:
                targets: [192.0.2.1]
        """)
        configs = Config.from_yaml_clients(path)
        assert len(configs) == 1
        assert configs[0].client_id == "only"


# ---------------------------------------------------------------------------
# from_env() guard
# ---------------------------------------------------------------------------

class TestFromEnvGuard:
    def test_raises_if_yaml_has_clients_section(self, tmp_path, monkeypatch):
        path = _write_yaml(tmp_path, """
            clients:
              acme:
                targets: [1.2.3.4]
        """)
        monkeypatch.setenv("CONFIG_FILE", path)
        with pytest.raises(ValueError, match="clients.*section"):
            Config.from_env()


# ---------------------------------------------------------------------------
# load_all_configs()
# ---------------------------------------------------------------------------

class TestLoadAllConfigs:
    def test_multi_client_yaml(self, tmp_path, monkeypatch):
        path = _write_yaml(tmp_path, """
            clients:
              a:
                targets: [1.1.1.1]
              b:
                targets: [2.2.2.2]
        """)
        monkeypatch.setenv("CONFIG_FILE", path)
        configs = load_all_configs()
        assert len(configs) == 2
        assert {c.client_id for c in configs} == {"a", "b"}

    def test_single_client_env_fallback(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CONFIG_FILE", raising=False)
        monkeypatch.setenv("MONITOR_TARGETS", "10.0.0.1")
        configs = load_all_configs()
        assert len(configs) == 1
        assert configs[0].targets == ["10.0.0.1"]

    def test_single_client_yaml_no_clients_key(self, tmp_path, monkeypatch):
        path = _write_yaml(tmp_path, """
            targets: [10.10.10.1]
        """)
        monkeypatch.setenv("CONFIG_FILE", path)
        configs = load_all_configs()
        assert len(configs) == 1
        assert configs[0].targets == ["10.10.10.1"]
