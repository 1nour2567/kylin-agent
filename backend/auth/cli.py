"""CLI for managing Kylin Agent API keys.

Usage:
  python -m auth.cli add <user_id> [--role admin|operator|viewer]
  python -m auth.cli revoke <key_id>
  python -m auth.cli list
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth.key_store import KeyStore, ROLES


def cmd_add(store: KeyStore, args: list):
    if len(args) < 3:
        print("Usage: python -m auth.cli add <user_id> [--role admin|operator|viewer]")
        sys.exit(1)

    user_id = args[2]
    role = "operator"

    if len(args) >= 4 and args[3] == "--role":
        if len(args) < 5:
            print("Usage: python -m auth.cli add <user_id> [--role admin|operator|viewer]")
            sys.exit(1)
        role = args[4]
        if role not in ROLES:
            print(f"Invalid role: {role}. Must be one of {ROLES}")
            sys.exit(1)

    plain_key = store.create_key(user_id, role)
    entry = store.list_entries()[-1]

    print(f"Key created for {user_id}")
    print(f"  Key ID:  {entry['key_id']}")
    print(f"  Role:    {entry['role']}")
    print(f"  API Key: {plain_key}")
    print()
    print("  Usage:")
    print(f'    curl -H "Authorization: Bearer {plain_key}" http://localhost:8009/api/chat')
    print()
    print("  Save this key now. It will NOT be shown again.")


def cmd_revoke(store: KeyStore, args: list):
    if len(args) < 3:
        print("Usage: python -m auth.cli revoke <key_id>")
        sys.exit(1)

    key_id = args[2]
    if store.revoke(key_id):
        print(f"Key {key_id} revoked.")
    else:
        print(f"Key {key_id} not found.")


def cmd_list(store: KeyStore):
    entries = store.list_entries()
    if not entries:
        print("No keys configured.")
        return

    print(f"{'KEY ID':<16} {'USER':<20} {'ROLE':<12} {'CREATED':<20} {'LAST USED'}")
    print("-" * 90)
    for e in entries:
        last = e.get("last_used_at") or "-"
        print(f"{e['key_id']:<16} {e['user_id']:<20} {e['role']:<12} {e['created_at']:<20} {last}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m auth.cli <add|revoke|list> [...]")
        print()
        print("  add <user_id> [--role admin|operator|viewer]")
        print("  revoke <key_id>")
        print("  list")
        sys.exit(1)

    store = KeyStore()
    cmd = sys.argv[1]

    if cmd == "add":
        cmd_add(store, sys.argv)
    elif cmd == "revoke":
        cmd_revoke(store, sys.argv)
    elif cmd == "list":
        cmd_list(store)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
