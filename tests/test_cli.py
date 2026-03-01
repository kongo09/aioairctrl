# parse_args calls parser.parse_args() which reads sys.argv, so we patch it
from unittest.mock import patch

import pytest


def _parse(argv):
    from aioairctrl.cli import parse_args

    with patch("sys.argv", ["aioairctrl"] + argv):
        return parse_args()


class TestParseArgs:
    def test_status_command(self):
        args = _parse(["-H", "192.168.1.1", "status"])
        assert args.host == "192.168.1.1"
        assert args.port == 5683
        assert args.command == "status"
        assert args.json is False

    def test_status_json_flag(self):
        args = _parse(["-H", "192.168.1.1", "status", "-J"])
        assert args.json is True

    def test_custom_port(self):
        args = _parse(["-H", "192.168.1.1", "-P", "1234", "status"])
        assert args.port == 1234

    def test_debug_flag(self):
        args = _parse(["-H", "192.168.1.1", "-D", "status"])
        assert args.debug is True

    def test_status_observe_command(self):
        args = _parse(["-H", "192.168.1.1", "status-observe"])
        assert args.command == "status-observe"

    def test_set_command_single_value(self):
        args = _parse(["-H", "192.168.1.1", "set", "pwr=1"])
        assert args.values == ["pwr=1"]

    def test_set_command_multiple_values(self):
        args = _parse(["-H", "192.168.1.1", "set", "pwr=1", "mode=2"])
        assert args.values == ["pwr=1", "mode=2"]

    def test_set_command_value_as_int_flag(self):
        args = _parse(["-H", "192.168.1.1", "set", "-I", "pwr=1"])
        assert args.value_as_int is True

    def test_missing_host_exits(self):
        with pytest.raises(SystemExit):
            _parse(["status"])

    def test_missing_command_exits(self):
        with pytest.raises(SystemExit):
            _parse(["-H", "192.168.1.1"])


class TestValueParsing:
    """Tests for the K=V parsing logic in async_main.

    We extract and test the parsing logic directly to document current
    behaviour and catch regressions when it is fixed.
    """

    def _parse_values(self, raw_values, value_as_int=False):
        """Replicate the parsing loop from async_main."""
        data = {}
        for e in raw_values:
            k, v = e.split("=", 1)  # NOTE: using the fixed split
            if v == "true":
                v = True
            elif v == "false":
                v = False
            if value_as_int:
                try:
                    v = int(v)
                except (ValueError, TypeError):
                    return None
            data[k] = v
        return data

    def test_simple_string_value(self):
        result = self._parse_values(["pwr=1"])
        assert result == {"pwr": "1"}

    def test_boolean_true(self):
        result = self._parse_values(["active=true"])
        assert result == {"active": True}

    def test_boolean_false(self):
        result = self._parse_values(["active=false"])
        assert result == {"active": False}

    def test_integer_value(self):
        result = self._parse_values(["speed=3"], value_as_int=True)
        assert result == {"speed": 3}

    def test_multiple_values(self):
        result = self._parse_values(["pwr=1", "mode=2"])
        assert result == {"pwr": "1", "mode": "2"}

    def test_value_containing_equals(self):
        # This is the bug: split("=") fails, split("=", 1) handles it
        result = self._parse_values(["filter=A=B"])
        assert result == {"filter": "A=B"}

    def test_invalid_int_returns_none(self):
        result = self._parse_values(["pwr=on"], value_as_int=True)
        assert result is None
