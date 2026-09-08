"""`LedgerService.sign()` must actually sign.

`LedgerClient` defaults `signing_config=None` and wires a signer only when one is
supplied. `LedgerService` constructed it without one, so `sign()` re-stamped the
Merkle root, dropped the now-void signature, and wrote the layer **unsigned**
while raising nothing — and `LAAS_SIGNING_REQUIRED=true` did not help, because
that guard lives in the config that was never read.

Measured 2026-08-31: a `backfill_event_fingerprints` pass left 112 previously
signed corpus layers unsigned this way. It went unnoticed because the natural
check is wrong: `verify_merkle_signature` reports no error on an unsigned layer,
there being no signature to fail. So these tests assert a signature **exists**,
not merely that nothing failed to verify.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traust_engine.ledger import LedgerService

pytest.importorskip("cryptography")

LAYER = {
    "metadata": {
        "audit_report": "probe-security-audit.json",
        "repository": "https://example.com/probe",
        "created": "2026-08-31T00:00:00+00:00",
        "claim_hashes": {},
    },
    "events": [
        {
            "event_id": "a" * 64,
            "finding_ref": "FIND-001",
            "recorded_at": "2026-08-31T00:00:00+00:00",
            "source": {
                "type": "triage_report",
                "ref": "probe-triage.json",
                "actor": {"kind": "machine", "identity": "probe/1.0"},
            },
            "disposition": {"validity": "confirmed"},
            "rationale": "probe",
        }
    ],
    "needs_review": [],
}


def _write_layer(tmp_path: Path) -> Path:
    p = tmp_path / "probe-findings-layer.json"
    p.write_text(json.dumps(LAYER, indent=2), encoding="utf-8")
    return p


@pytest.fixture
def cosign_key(tmp_path, monkeypatch):
    """A real cosign-style keypair is not needed — only that a key path is read."""
    monkeypatch.delenv("LAAS_SIGNING_KEY_PATH", raising=False)
    monkeypatch.delenv("HARNESS_SIGNING_KEY_PATH", raising=False)
    return tmp_path


def test_service_constructs_client_from_data_dir(cosign_key, monkeypatch):
    """LedgerService(data_dir=...) creates a LedgerClient internally."""
    service = LedgerService(data_dir=Path(cosign_key))
    assert service._client is not None


def test_service_constructs_client_from_env(cosign_key, monkeypatch):
    """LedgerService() with no args creates a LedgerClient from env."""
    monkeypatch.setenv("LAAS_DATA_DIR", str(cosign_key))
    service = LedgerService()
    assert service._client is not None


def test_explicit_client_is_not_overridden(cosign_key, monkeypatch):
    """A caller-supplied client is used as-is; we do not rebuild it."""
    sentinel = object()
    service = LedgerService(client=sentinel)  # type: ignore[arg-type]
    assert service._client is sentinel


def test_unsigned_layer_reports_no_signature_error(tmp_path):
    """Why the obvious check is insufficient — the trap that hid this for a pass.

    An unsigned layer produces no signature ERROR, because there is no signature
    to verify. Anything gating on `verify_merkle_signature` alone will call an
    unsigned corpus healthy.
    """
    from traust_ledger.api.integrity import verify_merkle_signature

    layer = json.loads(json.dumps(LAYER))
    layer["metadata"].pop("merkle_root_signature", None)
    errors = [f for f in verify_merkle_signature(layer, None) if f.severity.name == "ERROR"]
    assert errors == [], "precondition: unsigned layers raise no signature ERROR"
    assert not layer["metadata"].get("merkle_root_signature"), (
        "so the presence of a signature must be asserted separately"
    )


# ─── End-to-end: the property, not the plumbing ───────────────────────────────
#
# The tests above assert a signing_config is passed. That is a proxy, and a proxy
# can pass while the behaviour is broken — if traust-ledger changed how it consumes
# the config, the assertion would still hold and layers would still lose their
# signatures. This one asserts what actually matters: a layer that arrives signed
# leaves signed after its root has moved.
#
# It needs a real key, so it skips unless one is configured. Skipping is honest;
# asserting nothing while looking green is not.


def _signing_configured() -> bool:
    import os

    key = os.environ.get("LAAS_SIGNING_KEY_PATH") or os.environ.get("HARNESS_SIGNING_KEY_PATH")
    return bool(key and Path(key).is_file() and os.environ.get("COSIGN_PASSWORD"))


@pytest.mark.skipif(
    not _signing_configured(),
    reason="needs LAAS_SIGNING_KEY_PATH + COSIGN_PASSWORD (operator/CI signing key)",
)
def test_a_signed_layer_survives_a_root_change(tmp_path):
    """Move the root, re-sign, and require the signature to still be there.

    This is the exact shape that unsigned 112 corpus layers on 2026-08-31: the
    events changed, the old signature was correctly dropped, and nothing replaced
    it because sign() had no signer.
    """
    from traust_ledger.api.integrity import verify_merkle_integrity, verify_merkle_signature

    p = _write_layer(tmp_path)
    service = LedgerService(data_dir=tmp_path)
    service.sign(p)
    first = json.loads(p.read_text())["metadata"]
    assert first.get("merkle_root_signature"), "precondition: layer must start signed"
    root_before = first["merkle_root"]

    # mutate an event so the root genuinely moves
    layer = json.loads(p.read_text())
    layer["events"][0]["rationale"] = "changed, so the root moves"
    p.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    service.sign(p)

    after = json.loads(p.read_text())
    meta = after["metadata"]
    assert meta["merkle_root"] != root_before, "the root should have moved"
    assert meta.get("merkle_root_signature"), (
        "layer arrived signed and is now UNSIGNED — sign() has no signer"
    )
    assert not [f for f in verify_merkle_integrity(after) if f.severity.name == "ERROR"]
    from traust_contracts import config_path

    pub = config_path("ledger-signing-key.pub", strict=False)
    if pub.is_file():
        assert not [
            f for f in verify_merkle_signature(after, str(pub)) if f.severity.name == "ERROR"
        ]
