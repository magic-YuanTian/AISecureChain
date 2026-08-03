"""
MISP Explorer for AISecureChain Project
========================================
This script connects to a MISP instance and explores events,
with a focus on finding AI-related security events/vulnerabilities.

Usage:
    1. Copy .env.example to .env and fill in your MISP_URL and MISP_API_KEY
    2. pip install -r requirements.txt
    3. python explore_misp.py
"""

import json
import os
import sys
from datetime import datetime, timedelta

import requests
from dotenv import load_dotenv

load_dotenv()

MISP_URL = os.getenv("MISP_URL", "").rstrip("/")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "True").lower() in ("true", "1", "yes")

HEADERS = {
    "Authorization": MISP_API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json",
}

AI_KEYWORDS = [
    "AI", "artificial intelligence", "machine learning", "deep learning",
    "neural network", "LLM", "large language model", "GPT", "transformer",
    "NLP", "natural language processing", "computer vision",
    "adversarial", "model poisoning", "data poisoning",
    "prompt injection", "model extraction", "model inversion",
    "AI safety", "AI security", "ML security",
    "deepfake", "generative AI", "diffusion model",
    "reinforcement learning", "federated learning",
    "ChatGPT", "OpenAI", "Anthropic", "Claude", "Gemini", "Llama",
    "TensorFlow", "PyTorch", "Hugging Face",
]

OUTPUT_DIR = "output"


def check_config():
    """Verify that MISP configuration is set."""
    if not MISP_URL:
        print("[ERROR] MISP_URL is not set. Please configure your .env file.")
        print("        Copy .env.example to .env and fill in the values.")
        sys.exit(1)
    if not MISP_API_KEY:
        print("[ERROR] MISP_API_KEY is not set. Please configure your .env file.")
        print("        Log into MISP web UI -> My Profile -> Auth Keys -> + Add authentication key")
        sys.exit(1)
    print(f"[OK] MISP URL: {MISP_URL}")
    print(f"[OK] API Key: {MISP_API_KEY[:4]}...{MISP_API_KEY[-4:]}")


def api_get(endpoint):
    """Make a GET request to the MISP API."""
    url = f"{MISP_URL}{endpoint}"
    resp = requests.get(url, headers=HEADERS, verify=MISP_VERIFY_SSL)
    resp.raise_for_status()
    return resp.json()


def api_post(endpoint, data=None):
    """Make a POST request to the MISP API."""
    url = f"{MISP_URL}{endpoint}"
    resp = requests.post(url, headers=HEADERS, json=data or {}, verify=MISP_VERIFY_SSL)
    resp.raise_for_status()
    return resp.json()


def save_json(data, filename):
    """Save data as JSON to the output directory."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  -> Saved to {filepath}")


# ---------------------------------------------------------------------------
# 1. Connection Test
# ---------------------------------------------------------------------------
def test_connection():
    """Test connectivity by fetching MISP server version info."""
    print("\n" + "=" * 60)
    print("1. Testing Connection")
    print("=" * 60)
    try:
        result = api_get("/servers/getVersion.json")
        print(f"  MISP Version: {result.get('version', 'unknown')}")
        print(f"  PyMISP recommended version: {result.get('perm_sync', 'N/A')}")
        return True
    except requests.exceptions.ConnectionError:
        print(f"  [ERROR] Cannot connect to {MISP_URL}")
        print("  Please verify the MISP_URL in your .env file.")
        return False
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            print("  [ERROR] Authentication failed (403 Forbidden).")
            print("  Please verify your MISP_API_KEY in .env file.")
        else:
            print(f"  [ERROR] HTTP {e.response.status_code}: {e}")
        return False


# ---------------------------------------------------------------------------
# 2. Explore Tags
# ---------------------------------------------------------------------------
def explore_tags():
    """Fetch all tags and identify AI-related ones."""
    print("\n" + "=" * 60)
    print("2. Exploring Tags")
    print("=" * 60)

    result = api_get("/tags")
    all_tags = result.get("Tag", [])
    print(f"  Total tags in MISP: {len(all_tags)}")

    ai_tags = []
    for tag in all_tags:
        tag_name = tag.get("name", "").lower()
        for keyword in AI_KEYWORDS:
            if keyword.lower() in tag_name:
                ai_tags.append(tag)
                break

    print(f"  AI-related tags found: {len(ai_tags)}")
    if ai_tags:
        print("\n  AI-Related Tags:")
        for tag in ai_tags:
            count = tag.get("count", "?")
            print(f"    - {tag['name']}  (used {count} times, id={tag.get('id')})")

    save_json(all_tags, "all_tags.json")
    save_json(ai_tags, "ai_related_tags.json")
    return ai_tags


# ---------------------------------------------------------------------------
# 3. Search Tags via API
# ---------------------------------------------------------------------------
def search_tags_api(search_term):
    """Use the /tags/search endpoint to find tags matching a term."""
    print(f"\n  Searching tags for: '{search_term}'")
    try:
        result = api_get(f"/tags/search/{search_term}")
        if result:
            for tag_entry in result[:10]:
                if isinstance(tag_entry, dict):
                    print(f"    - {tag_entry.get('name', tag_entry)}")
                else:
                    print(f"    - {tag_entry}")
        else:
            print(f"    No tags found for '{search_term}'")
        return result
    except Exception as e:
        print(f"    Error searching tags: {e}")
        return []


# ---------------------------------------------------------------------------
# 4. Search Events with restSearch
# ---------------------------------------------------------------------------
def search_events_by_tag(tags, limit=50):
    """Search events that match given tags using /events/restSearch."""
    print("\n" + "=" * 60)
    print(f"4. Searching Events by Tags: {tags}")
    print("=" * 60)

    payload = {
        "tags": tags,
        "limit": limit,
        "page": 1,
        "metadata": True,
    }

    result = api_post("/events/restSearch", payload)
    events = result.get("response", [])
    print(f"  Events found: {len(events)}")

    for i, event_wrapper in enumerate(events[:20]):
        event = event_wrapper.get("Event", event_wrapper)
        eid = event.get("id", "?")
        info = event.get("info", "N/A")
        date = event.get("date", "?")
        tag_names = [t.get("name", "") for t in event.get("Tag", [])]
        print(f"  [{eid}] {date} | {info[:80]}")
        if tag_names:
            print(f"         Tags: {', '.join(tag_names[:5])}")

    save_json(result, f"events_by_tag_{'_'.join(tags)}.json")
    return events


def search_events_fulltext(keyword, limit=50):
    """Full-text search events using the 'searchall' parameter."""
    print("\n" + "=" * 60)
    print(f"5. Full-text Search: '{keyword}'")
    print("=" * 60)

    payload = {
        "searchall": keyword,
        "limit": limit,
        "page": 1,
    }

    result = api_post("/events/restSearch", payload)
    events = result.get("response", [])
    print(f"  Events found: {len(events)}")

    for i, event_wrapper in enumerate(events[:20]):
        event = event_wrapper.get("Event", event_wrapper)
        eid = event.get("id", "?")
        info = event.get("info", "N/A")
        date = event.get("date", "?")
        print(f"  [{eid}] {date} | {info[:80]}")

    safe_keyword = keyword.replace(" ", "_").replace("/", "_")
    save_json(result, f"events_fulltext_{safe_keyword}.json")
    return events


# ---------------------------------------------------------------------------
# 6. Search Events by Event Info Text
# ---------------------------------------------------------------------------
def search_events_by_info(keyword, limit=100):
    """Search events where event info text matches the keyword."""
    print("\n" + "=" * 60)
    print(f"6. Searching Events by Info Text: '{keyword}'")
    print("=" * 60)

    payload = {
        "eventinfo": keyword,
        "limit": limit,
        "page": 1,
    }

    result = api_post("/events/index", payload)
    events = result if isinstance(result, list) else result.get("response", [])
    print(f"  Events found: {len(events)}")

    for i, event_wrapper in enumerate(events[:20]):
        event = event_wrapper.get("Event", event_wrapper)
        eid = event.get("id", "?")
        info = event.get("info", "N/A")
        date = event.get("date", "?")
        print(f"  [{eid}] {date} | {info[:80]}")

    safe_keyword = keyword.replace(" ", "_").replace("/", "_")
    save_json(events, f"events_info_{safe_keyword}.json")
    return events


# ---------------------------------------------------------------------------
# 7. Get Recent Events
# ---------------------------------------------------------------------------
def get_recent_events(days=30, limit=50):
    """Get events from the last N days."""
    print("\n" + "=" * 60)
    print(f"7. Recent Events (last {days} days)")
    print("=" * 60)

    date_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

    payload = {
        "from": date_from,
        "limit": limit,
        "page": 1,
        "metadata": True,
    }

    result = api_post("/events/restSearch", payload)
    events = result.get("response", [])
    print(f"  Events since {date_from}: {len(events)}")

    for i, event_wrapper in enumerate(events[:10]):
        event = event_wrapper.get("Event", event_wrapper)
        eid = event.get("id", "?")
        info = event.get("info", "N/A")
        date = event.get("date", "?")
        tag_names = [t.get("name", "") for t in event.get("Tag", [])]
        print(f"  [{eid}] {date} | {info[:80]}")
        if tag_names:
            print(f"         Tags: {', '.join(tag_names[:5])}")

    save_json(result, f"recent_events_{days}d.json")
    return events


# ---------------------------------------------------------------------------
# 8. Explore Galaxies (for AI-related categories)
# ---------------------------------------------------------------------------
def explore_galaxies():
    """Fetch galaxies and look for AI-related ones."""
    print("\n" + "=" * 60)
    print("8. Exploring Galaxies")
    print("=" * 60)

    result = api_get("/galaxies")
    galaxies = result if isinstance(result, list) else result.get("response", [])
    print(f"  Total galaxies: {len(galaxies)}")

    ai_galaxies = []
    for galaxy_wrapper in galaxies:
        galaxy = galaxy_wrapper.get("Galaxy", galaxy_wrapper)
        name = galaxy.get("name", "").lower()
        desc = galaxy.get("description", "").lower()
        for keyword in AI_KEYWORDS:
            if keyword.lower() in name or keyword.lower() in desc:
                ai_galaxies.append(galaxy)
                break

    print(f"  AI-related galaxies: {len(ai_galaxies)}")
    for g in ai_galaxies:
        print(f"    - {g.get('name')}: {g.get('description', '')[:80]}")

    save_json(galaxies, "all_galaxies.json")
    save_json(ai_galaxies, "ai_related_galaxies.json")
    return ai_galaxies


# ---------------------------------------------------------------------------
# 9. Comprehensive AI Event Search
# ---------------------------------------------------------------------------
def comprehensive_ai_search():
    """Run a comprehensive search for AI-related events across multiple strategies."""
    print("\n" + "=" * 60)
    print("9. COMPREHENSIVE AI SECURITY EVENT SEARCH")
    print("=" * 60)

    all_ai_events = {}

    search_terms = [
        "AI", "artificial intelligence", "machine learning",
        "deep learning", "LLM", "neural network", "GPT",
        "adversarial", "prompt injection", "deepfake",
        "model poisoning", "ChatGPT", "OpenAI",
    ]

    for term in search_terms:
        print(f"\n  --- Searching: '{term}' ---")
        try:
            payload = {
                "searchall": term,
                "limit": 100,
                "page": 1,
                "metadata": True,
            }
            result = api_post("/events/restSearch", payload)
            events = result.get("response", [])
            print(f"  Found {len(events)} events")

            for event_wrapper in events:
                event = event_wrapper.get("Event", event_wrapper)
                eid = event.get("id")
                if eid and eid not in all_ai_events:
                    all_ai_events[eid] = {
                        "id": eid,
                        "info": event.get("info", ""),
                        "date": event.get("date", ""),
                        "tags": [t.get("name", "") for t in event.get("Tag", [])],
                        "org": event.get("Orgc", {}).get("name", ""),
                        "threat_level_id": event.get("threat_level_id", ""),
                        "matched_term": term,
                    }
        except Exception as e:
            print(f"  Error: {e}")

    print(f"\n  ========================================")
    print(f"  TOTAL UNIQUE AI-RELATED EVENTS: {len(all_ai_events)}")
    print(f"  ========================================")

    sorted_events = sorted(all_ai_events.values(), key=lambda x: x.get("date", ""), reverse=True)
    for ev in sorted_events[:30]:
        print(f"  [{ev['id']}] {ev['date']} | {ev['info'][:70]}")
        print(f"         Org: {ev['org']} | Matched: '{ev['matched_term']}'")
        if ev["tags"]:
            print(f"         Tags: {', '.join(ev['tags'][:5])}")

    save_json(sorted_events, "comprehensive_ai_events.json")
    return sorted_events


# ---------------------------------------------------------------------------
# 10. Get Event Details
# ---------------------------------------------------------------------------
def get_event_details(event_id):
    """Fetch full details of a specific event."""
    print(f"\n  Fetching details for event {event_id}...")
    result = api_get(f"/events/view/{event_id}")
    event = result.get("Event", result)

    print(f"  ID: {event.get('id')}")
    print(f"  Info: {event.get('info')}")
    print(f"  Date: {event.get('date')}")
    print(f"  Org: {event.get('Orgc', {}).get('name', 'N/A')}")

    tags = event.get("Tag", [])
    if tags:
        print(f"  Tags: {', '.join(t.get('name', '') for t in tags)}")

    attributes = event.get("Attribute", [])
    print(f"  Attributes: {len(attributes)}")
    for attr in attributes[:10]:
        print(f"    - [{attr.get('type')}] {attr.get('value', '')[:80]}")

    objects = event.get("Object", [])
    print(f"  Objects: {len(objects)}")
    for obj in objects[:5]:
        print(f"    - {obj.get('name')}: {obj.get('description', '')[:60]}")

    save_json(result, f"event_{event_id}_details.json")
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("  AISecureChain - MISP Explorer")
    print("  Finding AI-related security events")
    print("=" * 60)

    check_config()

    if not test_connection():
        sys.exit(1)

    print("\n\nWhat would you like to do?")
    print("  1. Quick overview (tags + recent events)")
    print("  2. Search AI-related tags")
    print("  3. Full-text search for a keyword")
    print("  4. Comprehensive AI security event search")
    print("  5. View specific event details")
    print("  6. Run ALL explorations")
    print("  0. Exit")

    choice = input("\nEnter your choice (0-6): ").strip()

    if choice == "1":
        explore_tags()
        get_recent_events(days=30)

    elif choice == "2":
        ai_tags = explore_tags()
        for term in ["AI", "machine learning", "adversarial", "LLM"]:
            search_tags_api(term)

    elif choice == "3":
        keyword = input("Enter search keyword: ").strip()
        if keyword:
            search_events_fulltext(keyword)

    elif choice == "4":
        comprehensive_ai_search()

    elif choice == "5":
        event_id = input("Enter event ID: ").strip()
        if event_id:
            get_event_details(event_id)

    elif choice == "6":
        explore_tags()
        for term in ["AI", "machine learning", "adversarial", "LLM", "neural", "deepfake"]:
            search_tags_api(term)
        explore_galaxies()
        get_recent_events(days=90)
        search_events_by_tag(["AI"], limit=100)
        comprehensive_ai_search()

    else:
        print("Goodbye!")


if __name__ == "__main__":
    main()
