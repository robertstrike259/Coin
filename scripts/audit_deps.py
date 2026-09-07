"""Weekly freshness audit: compare pinned third-party versions against
upstream latest stable releases. Informational only: prints a table and
always exits 0 (never fail a build over an upstream release)."""
import json
import sys
import urllib.request

PINNED = {
    "bitcoin-core/secp256k1": "v0.8.0",
    "nlohmann/json": "v3.12.0",
    "doctest/doctest": "v2.5.3",
    "P-H-C/phc-winner-argon2": "20190702",
}
# Asio publishes tags, not releases; compare against this known-good tag list.
ASIO_PINNED = "asio-1-38-2"


def latest_release(repo):
    url = "https://api.github.com/repos/%s/releases/latest" % repo
    req = urllib.request.Request(url, headers={"User-Agent": "coin-dep-audit"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r).get("tag_name", "?")
    except Exception as e:  # network/API trouble must not fail CI
        return "lookup-failed(%s)" % e


def latest_tag(repo):
    url = "https://api.github.com/repos/%s/tags?per_page=5" % repo
    req = urllib.request.Request(url, headers={"User-Agent": "coin-dep-audit"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            tags = json.load(r)
            return tags[0]["name"] if tags else "?"
    except Exception as e:
        return "lookup-failed(%s)" % e


def main():
    rows = []
    stale = False
    for repo, pin in PINNED.items():
        latest = latest_release(repo)
        ok = latest in (pin, "lookup-failed") or latest.startswith("lookup-failed")
        stale = stale or (not latest.startswith("lookup-failed") and latest != pin)
        rows.append((repo, pin, latest, "OK" if latest == pin else ("UNKNOWN" if latest.startswith("lookup") else "STALE")))
    latest_asio = latest_tag("chriskohlhoff/asio")
    rows.append(("chriskohlhoff/asio", ASIO_PINNED, latest_asio,
                 "OK" if latest_asio == ASIO_PINNED else ("UNKNOWN" if latest_asio.startswith("lookup") else "STALE")))
    stale = stale or (not latest_asio.startswith("lookup") and latest_asio != ASIO_PINNED)
    print("| repo | pinned | upstream latest | status |")
    print("|---|---|---|---|")
    for repo, pin, latest, status in rows:
        print("| %s | %s | %s | %s |" % (repo, pin, latest, status))
    if stale:
        print("ACTION: upstream has newer stable releases; file a task to re-pin per DEPENDENCIES.md")
    else:
        print("All pins current (or upstream unreachable).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
