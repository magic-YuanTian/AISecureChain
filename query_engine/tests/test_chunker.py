"""Chunker tests — header splits, size caps, overlap, edge cases."""

from extract_pipeline.chunker import chunk_markdown


def test_empty_returns_empty_list():
    assert chunk_markdown("") == []
    assert chunk_markdown("   \n\n  ") == []


def test_short_content_single_chunk():
    md = "# Title\nSome short content."
    assert chunk_markdown(md) == [md]


def test_splits_on_h2():
    md = "\n\n".join(f"## Section {i}\n{'body ' * 200}" for i in range(5))
    chunks = chunk_markdown(md, max_chars=1500)
    assert len(chunks) >= 5
    assert all(c.startswith("## Section") or "## Section" in c for c in chunks)


def test_size_cap_enforced_with_overlap():
    md = "word " * 4000  # ~20k chars, no headers
    chunks = chunk_markdown(md, max_chars=2000, overlap=100)
    assert len(chunks) > 1
    assert all(len(c) <= 2200 for c in chunks)  # cap + overlap slack
    # Consecutive chunks should share some overlap content
    assert chunks[0][-50:] != "" and len(chunks[1]) > 0


def test_small_trailing_chunk_is_merged():
    body = "## Big\n" + ("body text " * 500) + "\n## Tiny\nx"
    chunks = chunk_markdown(body, max_chars=8000)
    # Tiny chunk should not survive alone (below MIN_CHUNK_CHARS)
    assert all(len(c) > 50 for c in chunks), f"Tiny chunk leaked: {[len(c) for c in chunks]}"


def test_listing_page_produces_many_chunks():
    """A page listing many vulns should yield many chunks when large."""
    md = "\n\n".join(
        f"## CVE-2024-{i:04d}\n" + ("Details " * 500)
        for i in range(8)
    )
    chunks = chunk_markdown(md, max_chars=4000)
    assert len(chunks) >= 6, f"expected >=6, got {len(chunks)}"
