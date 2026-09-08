"""`LedgerService` resolves identity via LedgerClient's env chain.

Auth resolution (LAAS_TOKEN → stored creds → auto-mint) is handled
inside ``LedgerClient.__init__`` — ``LedgerService`` just forwards
``data_dir`` and lets the SDK do the work.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest
from traust_ledger.client import LedgerError

from traust_engine.ledger.service import LedgerService


def test_data_dir_delegates_to_ledger_client(monkeypatch, tmp_path):
    """LedgerService(data_dir=...) passes data_dir to LedgerClient."""
    calls = {}

    class FakeClient:
        def __init__(self, **kwargs):
            calls.update(kwargs)

    monkeypatch.setattr("traust_engine.ledger.service.LedgerClient", FakeClient)
    LedgerService(data_dir=Path(tmp_path))
    assert calls["data_dir"] == str(tmp_path)


def test_missing_token_names_the_remedy(monkeypatch, tmp_path):
    """Failure must say how to get a token, not merely that one is absent."""
    monkeypatch.delenv("LAAS_TOKEN", raising=False)
    monkeypatch.delenv("LEDGER_TOKEN", raising=False)
    monkeypatch.delenv("LEDGER_TOKEN_PATH", raising=False)
    monkeypatch.delenv("LEDGER_LOCAL_IDENTITY", raising=False)
    with (
        mock.patch("traust_ledger.auth.config._default_store", return_value=None),
        pytest.raises(LedgerError, match="authentication required"),
    ):
        LedgerService(data_dir=Path(tmp_path))
