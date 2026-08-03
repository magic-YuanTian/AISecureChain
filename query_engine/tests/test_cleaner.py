from extract_pipeline.cleaner import clean_markdown_boilerplate


def test_cleaner_removes_nav_promos_and_footer_noise():
    md = """[Dropbox.Tech](https://dropbox.tech/)
Menu
  * Topics

# Main Article
Intro paragraph.

Dropbox Dash: AI that understands your work
Dash knows your context, your team, and your work.
[Learn more →](https://dash.dropbox.com)

## Finding
OpenAI GPT-4 was affected by repeated-token data extraction.

* * *
// Tags
  * LLM

Related posts
[Other post](https://example.com)
"""

    cleaned = clean_markdown_boilerplate(md)

    assert cleaned.startswith("# Main Article")
    assert "## Finding" in cleaned
    assert "repeated-token data extraction" in cleaned
    assert "Menu" not in cleaned
    assert "Dropbox Dash" not in cleaned
    assert "Related posts" not in cleaned
    assert "// Tags" not in cleaned
