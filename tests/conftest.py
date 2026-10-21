"""Shared fixtures."""

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail any test that reaches the network.

    A missing mock otherwise sends a real request to semgrep.dev -- with
    whatever token the test passes. Tests that exercise urllib patch urlopen
    themselves, which overrides this.
    """
    def refuse(request, *args, **kwargs):
        url = getattr(request, "full_url", request)
        raise AssertionError(f"test tried to reach the network: {url}")

    monkeypatch.setattr("urllib.request.urlopen", refuse)
