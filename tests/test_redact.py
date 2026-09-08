"""Tests for traust_engine._util.redact — write-time redaction."""

from traust_engine._util import redact as rd
from traust_engine.reporting import validate as vr


def test_vendor_tokens_redacted():
    t, hits = rd.redact_text("a AKIAIOSFODNN7EXAMPLE b ghp_" + "x" * 36 + " c glpat-" + "y" * 20)
    assert "AKIAIOSFODNN7EXAMPLE" not in t
    assert "...REDACTED" in t
    cats = {h["category"] for h in hits}
    assert {"aws-access-key", "github-token", "gitlab-token"} <= cats


def test_luhn_gate_blocks_non_cards():
    # 16 digits failing Luhn: untouched, no hit
    t, hits = rd.redact_text("build id 1234 5678 9012 3456 ok")
    assert "1234 5678 9012 3456" in t
    assert not any(h["category"] == "payment-card" for h in hits)
    # valid test PAN (4111...) is caught
    t2, hits2 = rd.redact_text("card 4111 1111 1111 1111 x")
    assert "4111 1111 1111 1111" not in t2
    assert any(h["category"] == "payment-card" for h in hits2)


def test_ssn_shape():
    t, _hits = rd.redact_text("ssn 123-45-6789 but not 000-12-3456")
    assert "123-45-6789" not in t
    assert "000-12-3456" in t  # invalid area number left alone


def test_pem_block_preserves_markers():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIsecretsecret\n-----END RSA PRIVATE KEY-----"
    t, hits = rd.redact_text(pem)
    assert "-----BEGIN RSA PRIVATE KEY-----" in t
    assert "MIIsecretsecret" not in t
    assert any(h["category"] == "pem-private-key" for h in hits)


def test_url_credentials():
    t, _ = rd.redact_text("https://svc:sup3rsecret@git.example/x.git")
    assert "sup3rsecret" not in t
    assert "svc:" in t  # username survives


def test_idempotent_no_rescan_hits():
    t, _ = rd.redact_text("key AKIAIOSFODNN7EXAMPLE end")
    assert rd.scan_text(t) == []


def test_high_confidence_set_sane():
    assert "aws-access-key" in rd.HIGH_CONFIDENCE
    assert "password-assignment" not in rd.HIGH_CONFIDENCE
    assert "payment-card" not in rd.HIGH_CONFIDENCE


def test_validate_report_strict_gates_secrets(tmp_path):
    report = {
        "metadata": {"repository": "https://github.com/o/r"},
        "findings": [{"id": "F1", "evidence": "token AKIAIOSFODNN7EXAMPLE"}],
    }
    result = vr.ValidationResult("x.json")
    vr.strict_checks(report, result)
    assert any("aws-access-key" in e for e in result.errors)
    # heuristic class only warns
    report2 = {
        "metadata": {"repository": "https://github.com/o/r"},
        "findings": [{"id": "F1", "evidence": 'password = "hunter2secret"'}],
    }
    result2 = vr.ValidationResult("x.json")
    vr.strict_checks(report2, result2)
    assert not any("password-assignment" in e for e in result2.errors)
    assert any("password-assignment" in w for w in result2.warnings)
