"""Tests for sentinel.config"""

from pathlib import Path

import yaml

from sentinel.config import CleanupConfig, SentinelConfig, load_config, _deep_merge


class TestDeepMerge:
    def test_flat_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self):
        base = {"x": {"a": 1, "b": 2}, "y": 10}
        override = {"x": {"b": 3, "c": 4}}
        result = _deep_merge(base, override)
        assert result == {"x": {"a": 1, "b": 3, "c": 4}, "y": 10}

    def test_base_unmodified(self):
        base = {"a": {"nested": 1}}
        override = {"a": {"nested": 2}}
        _deep_merge(base, override)
        assert base["a"]["nested"] == 1  # Original untouched


class TestLoadConfig:
    def test_loads_defaults_when_no_file(self, tmp_path: Path):
        # Point to a dir with no config.yaml
        config = load_config(tmp_path / "nonexistent.yaml")
        assert "cleanup" in config
        assert "security" in config
        assert "agent" in config
        assert "reporter" in config

    def test_loads_from_file(self, sample_config_yaml: Path):
        config = load_config(sample_config_yaml)
        assert config["cleanup"]["min_age_hours"] == 24
        assert config["agent"]["provider"] == "none"

    def test_local_override(self, tmp_path: Path):
        # Write base config
        base = {"sentinel": {"agent": {"provider": "gemini", "model": "base-model"}}}
        (tmp_path / "config.yaml").write_text(yaml.dump(base), encoding="utf-8")

        # Write local override
        local = {"sentinel": {"agent": {"model": "override-model"}}}
        (tmp_path / "config.local.yaml").write_text(yaml.dump(local), encoding="utf-8")

        config = load_config(tmp_path / "config.yaml")
        assert config["agent"]["provider"] == "gemini"  # From base
        assert config["agent"]["model"] == "override-model"  # From local


class TestSentinelConfig:
    def test_from_dict(self, sample_config: dict):
        sc = SentinelConfig.from_dict(sample_config)
        assert sc.cleanup.min_age_hours == 24
        assert sc.agent.provider == "none"
        assert isinstance(sc.cleanup, CleanupConfig)

    def test_defaults(self):
        sc = SentinelConfig()
        assert sc.cleanup.enabled is True
        assert sc.agent.fallback_to_template is True
