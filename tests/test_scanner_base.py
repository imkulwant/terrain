import pytest

from terrain.models import Item
from terrain.scanners.base import BaseScanner


class _ConcreteScanner(BaseScanner):
    name = "test"

    def scan(self) -> list[Item]:
        return []


def test_scan_returns_list():
    s = _ConcreteScanner()
    result = s.scan()
    assert result == []


def test_base_scanner_is_abstract():
    with pytest.raises(TypeError):
        BaseScanner()  # type: ignore[abstract]


def test_run_success():
    s = _ConcreteScanner()
    out, rc = s._run(["echo", "hello"])
    assert rc == 0
    assert out == "hello"


def test_run_missing_binary():
    s = _ConcreteScanner()
    out, rc = s._run(["__terrain_nonexistent_binary__"])
    assert rc == 127
    assert out == ""


def test_run_timeout():
    s = _ConcreteScanner()
    out, rc = s._run(["sleep", "60"], timeout=0.01)
    assert rc == 1
    assert out == ""


def test_run_shell_success():
    s = _ConcreteScanner()
    out, rc = s._run_shell("echo hello")
    assert rc == 0
    assert out == "hello"


def test_run_shell_pipeline():
    s = _ConcreteScanner()
    out, rc = s._run_shell("echo -e 'a\\nb\\nc' | wc -l")
    assert rc == 0
    assert out.strip() == "3"


def test_which_finds_existing():
    s = _ConcreteScanner()
    path = s._which("echo")
    assert path is not None
    assert "echo" in path


def test_which_missing():
    s = _ConcreteScanner()
    path = s._which("__terrain_no_such_binary__")
    assert path is None


def test_verbose_flag_default_false():
    s = _ConcreteScanner()
    assert s.verbose is False


def test_verbose_flag_settable():
    s = _ConcreteScanner()
    s.verbose = True
    assert s.verbose is True
