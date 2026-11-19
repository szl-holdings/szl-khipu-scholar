#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# (c) 2026 Lutar, Stephen P. - SZL Holdings - ORCID 0009-0001-0110-4173
"""The explorer renders receipt fields as text. Its decision logic is tested
with `node --test frontend/feed.test.js`; this guards the page itself."""
from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
SINKS = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function")


@pytest.mark.parametrize("name", ["index.html", "feed.js"])
def test_no_markup_sinks(name):
    text = (FRONTEND / name).read_text(encoding="utf-8")
    assert [s for s in SINKS if s in text] == []


def test_page_uses_the_tested_feed_logic():
    page = (FRONTEND / "index.html").read_text(encoding="utf-8")
    assert '<script src="feed.js"></script>' in page
    assert "KhipuFeed.resolveFeed(" in page
    assert "KhipuFeed.rowCells(" in page
    assert "fetch(api" not in page
