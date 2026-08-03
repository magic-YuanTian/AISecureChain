"""
Quick MISP Connection Test
===========================
Use this script to test your API connection before running the full explorer.

Steps:
    1. Copy .env.example to .env
    2. Fill in MISP_URL and MISP_API_KEY
    3. Run: python quick_test.py
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

MISP_URL = os.getenv("MISP_URL", "").rstrip("/")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")
VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "True").lower() in ("true", "1", "yes")

HEADERS = {
    "Authorization": MISP_API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json",
}


def main():
    print("MISP Quick Connection Test")
    print("-" * 40)

    if not MISP_URL or not MISP_API_KEY:
        print("[FAIL] Please set MISP_URL and MISP_API_KEY in your .env file.")
        print()
        print("Steps to get your API key:")
        print("  1. Log into your MISP instance web UI")
        print("  2. Go to: My Profile -> Auth Keys")
        print("  3. Click: + Add authentication key")
        print("  4. Copy the key and paste it into .env as MISP_API_KEY")
        return

    print(f"URL:     {MISP_URL}")
    print(f"API Key: {MISP_API_KEY[:4]}...{MISP_API_KEY[-4:]}")
    print(f"SSL:     {'Enabled' if VERIFY_SSL else 'Disabled'}")
    print()

    # Test 1: Server version
    print("[Test 1] Fetching server version...")
    try:
        r = requests.get(
            f"{MISP_URL}/servers/getVersion.json",
            headers=HEADERS,
            verify=VERIFY_SSL,
        )
        if r.status_code == 200:
            data = r.json()
            print(f"  [OK] MISP Version: {data.get('version', 'unknown')}")
        elif r.status_code == 403:
            print("  [FAIL] 403 Forbidden - Check your API key")
        else:
            print(f"  [FAIL] HTTP {r.status_code}")
    except requests.exceptions.SSLError:
        print("  [FAIL] SSL Error - Try setting MISP_VERIFY_SSL=False in .env")
    except requests.exceptions.ConnectionError:
        print(f"  [FAIL] Cannot connect to {MISP_URL}")
        print("  Check the URL and your network connection.")
        return

    # Test 2: Fetch first page of events
    print("\n[Test 2] Fetching first 5 events...")
    try:
        r = requests.post(
            f"{MISP_URL}/events/restSearch",
            headers=HEADERS,
            json={"limit": 5, "page": 1, "metadata": True},
            verify=VERIFY_SSL,
        )
        if r.status_code == 200:
            data = r.json()
            events = data.get("response", [])
            print(f"  [OK] Got {len(events)} events")
            for ev in events:
                event = ev.get("Event", ev)
                print(f"    - [{event.get('id')}] {event.get('info', 'N/A')[:60]}")
        else:
            print(f"  [FAIL] HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"  [FAIL] {e}")

    # Test 3: Count total tags
    print("\n[Test 3] Counting tags...")
    try:
        r = requests.get(
            f"{MISP_URL}/tags",
            headers=HEADERS,
            verify=VERIFY_SSL,
        )
        if r.status_code == 200:
            data = r.json()
            tags = data.get("Tag", [])
            print(f"  [OK] Total tags: {len(tags)}")
            ai_count = sum(
                1
                for t in tags
                if any(kw.lower() in t.get("name", "").lower() for kw in ["ai", "machine learning", "llm"])
            )
            print(f"  [OK] Tags containing 'AI/ML/LLM': {ai_count}")
        else:
            print(f"  [FAIL] HTTP {r.status_code}")
    except Exception as e:
        print(f"  [FAIL] {e}")

    print("\n" + "-" * 40)
    print("Connection test complete!")
    print("If all tests passed, run: python explore_misp.py")


if __name__ == "__main__":
    main()
