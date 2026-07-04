

from terrain.audit.secrets import (
    SECRET_PATTERNS,
    scan_file,
    scan_files,
)
from terrain.models import AuditSeverity


def test_detects_openai_key(tmp_path):
    f = tmp_path / "config"
    f.write_text("OPENAI_API_KEY=sk-" + "a" * 48 + "\n")
    flags = scan_file(f)
    assert len(flags) >= 1
    assert any(f.severity == AuditSeverity.critical for f in flags)
    assert any("OpenAI" in f.message for f in flags)


def test_detects_anthropic_key(tmp_path):
    f = tmp_path / "config"
    f.write_text("key=sk-ant-" + "a" * 80 + "\n")
    flags = scan_file(f)
    assert any("Anthropic" in f.message for f in flags)


def test_detects_github_token(tmp_path):
    f = tmp_path / "config"
    f.write_text("TOKEN=ghp_" + "A" * 36 + "\n")
    flags = scan_file(f)
    assert any("GitHub" in f.message for f in flags)


def test_detects_aws_access_key(tmp_path):
    f = tmp_path / "creds"
    f.write_text("aws_access_key_id = AKIA" + "A" * 16 + "\n")
    flags = scan_file(f)
    assert any("AWS" in f.message for f in flags)


def test_detects_generic_api_key(tmp_path):
    f = tmp_path / ".env"
    f.write_text("API_KEY=abcdefghijklmnopqrstuvwxyz123456\n")
    flags = scan_file(f)
    assert len(flags) >= 1


def test_no_false_positive_plain_text(tmp_path):
    f = tmp_path / "readme.txt"
    f.write_text("This is just a readme.\nNo secrets here.\nPATH=/usr/bin:/bin\n")
    flags = scan_file(f)
    assert flags == []


def test_one_flag_per_line(tmp_path):
    # A line matching multiple patterns should only produce one flag
    f = tmp_path / "config"
    # This line would match generic API key pattern
    f.write_text("api_key=sk-" + "x" * 48 + "\n")
    flags = scan_file(f)
    assert len(flags) == 1


def test_location_is_set(tmp_path):
    f = tmp_path / "secrets.env"
    f.write_text("API_KEY=" + "x" * 32 + "\n")
    flags = scan_file(f)
    assert len(flags) >= 1
    assert flags[0].location == str(f)


def test_scan_files_skips_missing():
    flags = scan_files(["/this/does/not/exist.env"])
    assert flags == []


def test_scan_files_multiple(tmp_path):
    f1 = tmp_path / "a.env"
    f2 = tmp_path / "b.env"
    f1.write_text("API_KEY=" + "x" * 32 + "\n")
    f2.write_text("nothing here\n")
    flags = scan_files([str(f1), str(f2)])
    assert len(flags) >= 1
    assert all(f.location == str(f1) for f in flags)


def test_permission_error_handled(tmp_path):
    f = tmp_path / "locked"
    f.write_text("API_KEY=" + "x" * 32)
    f.chmod(0o000)
    try:
        flags = scan_file(f)
        assert flags == []
    finally:
        f.chmod(0o644)


def test_secret_patterns_are_tuples():
    for pattern, label in SECRET_PATTERNS:
        assert isinstance(pattern, str)
        assert isinstance(label, str)
        assert len(label) > 0
