#!/usr/bin/env python3
"""
Policy audit for dotnet/Microsoft repos using FabricBot/GitOps.ResourceManagement.

Hypothesis: any rule with action `approvePullRequest` (or `enableAutoMerge`) gated on
`isActivitySender.user: <name>` resolves <name> as a string against pull_request.user.login.
If <name> is a GitHub User-type account (rather than a Bot-type), the rule's authority is
bound to a mutable username -- a long-tail namespace-reclamation risk.

This tool:
  1. Pulls .github/policies/resourceManagement.yml from each target repo.
  2. Walks the rule tree and extracts (repo, rule_index, username, action_set) tuples
     for every rule whose actions include approvePullRequest or enableAutoMerge.
  3. Calls the GitHub API to classify each username as User or Bot.
  4. Prints a table; User-type rows are flagged.

Usage:
  python policy-audit.py [--repo OWNER/NAME ...]
  defaults to a hard-coded list of major dotnet repos.
"""
import argparse, json, subprocess, sys
import yaml

DEFAULT_REPOS = [
    "dotnet/aspnetcore",
    "dotnet/runtime",
    "dotnet/sdk",
    "dotnet/efcore",
    "dotnet/roslyn",
    "dotnet/maui",
    "dotnet/winforms",
    "dotnet/wpf",
]

ELEVATING_ACTIONS = {"approvePullRequest", "enableAutoMerge"}


def gh_api(path):
    r = subprocess.run(
        ["gh", "api", path],
        capture_output=True, text=True, check=False,
    )
    if r.returncode != 0:
        return None
    return json.loads(r.stdout)


def fetch_yaml(repo):
    data = gh_api(f"repos/{repo}/contents/.github/policies/resourceManagement.yml")
    if not data or "content" not in data:
        return None
    import base64
    return yaml.safe_load(base64.b64decode(data["content"]))


def extract_user_from_filters(filters):
    """Find the first isActivitySender.user value in a list of filter dicts."""
    if not isinstance(filters, list):
        return None
    for f in filters:
        if isinstance(f, dict) and "isActivitySender" in f:
            sender = f["isActivitySender"]
            if isinstance(sender, dict) and "user" in sender:
                return sender["user"]
    return None


def actions_in(actions):
    """Return the set of action keys used in the actions list."""
    if not isinstance(actions, list):
        return set()
    out = set()
    for a in actions:
        if isinstance(a, dict):
            out.update(a.keys())
        elif isinstance(a, str):
            out.add(a)
    return out


def walk_rules(doc, repo):
    """Yield (repo, location, user, action_keys) for every rule with elevating actions."""
    rm_cfg = (doc or {}).get("configuration", {}).get("resourceManagementConfiguration", {})
    sections = [
        ("eventResponderTasks", rm_cfg.get("eventResponderTasks", [])),
        ("scheduledSearches", rm_cfg.get("scheduledSearches", [])),
    ]
    for name, items in sections:
        for i, item in enumerate(items or []):
            then = item.get("then")
            actions = then if then is not None else item.get("actions")
            keys = actions_in(actions)
            if keys & ELEVATING_ACTIONS:
                if_filters = item.get("if") or item.get("filters") or []
                user = extract_user_from_filters(if_filters)
                yield (repo, f"{name}[{i}]", user, sorted(keys & ELEVATING_ACTIONS))


def classify_user(login):
    if login is None:
        return "(no isActivitySender)"
    info = gh_api(f"users/{login}")
    if info is None:
        return "UNKNOWN(404)"
    return info.get("type", "?")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", action="append", default=None)
    args = ap.parse_args()
    repos = args.repo or DEFAULT_REPOS

    rows = []
    for repo in repos:
        doc = fetch_yaml(repo)
        if doc is None:
            print(f"SKIP {repo}: no resourceManagement.yml", file=sys.stderr)
            continue
        for r in walk_rules(doc, repo):
            rows.append(r)

    if not rows:
        print("No elevating rules found.")
        return 0

    # Resolve all users.
    user_cache = {}
    for repo, loc, user, actions in rows:
        if user not in user_cache:
            user_cache[user] = classify_user(user)

    # Print table.
    print(f"{'Repo':<25} {'Location':<30} {'Action(s)':<35} {'User':<25} {'Type':<10}  Risk")
    print("-" * 140)
    for repo, loc, user, actions in rows:
        utype = user_cache[user]
        risk = "** USER-TYPE: namespace-reclamation surface **" if utype == "User" else \
               "ok (Bot)" if utype == "Bot" else \
               "(no user filter)" if user is None else \
               utype
        ulabel = user if user is not None else "(any)"
        print(f"{repo:<25} {loc:<30} {','.join(actions):<35} {ulabel:<25} {utype:<10}  {risk}")

    user_rows = [r for r in rows if user_cache[r[2]] == "User"]
    print()
    print(f"Total elevating rules:    {len(rows)}")
    print(f"User-type-gated rules:    {len(user_rows)}  <-- finding population")
    print(f"Bot-type-gated rules:     {sum(1 for r in rows if user_cache[r[2]] == 'Bot')}")
    print(f"Unfiltered rules:         {sum(1 for r in rows if r[2] is None)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
