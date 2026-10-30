#!/usr/bin/env python3
"""Synthetic authentication events for the demo and the benchmark. Nothing here touches a network.

Every address is from the documentation ranges (RFC 5737) that the bundled synthetic geo table maps,
and every user is @example.test. Event ids are derived from the seed, so running the generator twice
with the same arguments produces the same ids and the second ingest comes back as duplicates.
"""
import argparse
import datetime as dt
import json
import random
import uuid

HOME = "198.51.100.{}"      # Bengaluru, residential (synthetic table)
VPN = "203.0.113.{}"        # 203.0.113.128/25: New York, VPN exit; 203.0.113.0/25: Frankfurt hosting
CLOUD = "192.0.2.{}"        # Sao Paulo, hosting
AGENT = "SyntheticAgent/1.0"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", choices=["attack", "noise"], required=True)
    p.add_argument("--count", type=int, default=200, help="noise events")
    p.add_argument("--seed", default="demo")
    p.add_argument("--batch", type=int, default=200)
    p.add_argument("--tag", default="", help="suffix for attack user names, so a rerun meets fresh profiles")
    a = p.parse_args()
    rnd = random.Random(a.seed)
    base = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(minutes=20)
    events = []

    def ev(i, offset_s, user, ip, action, outcome):
        events.append({
            "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentinel-gen:{a.seed}:{a.scenario}:{i}")),
            "ts": (base + dt.timedelta(seconds=offset_s)).isoformat().replace("+00:00", "Z"),
            "user": user, "ip": ip, "action": action, "outcome": outcome, "user_agent": AGENT,
        })

    if a.scenario == "attack":
        n = 0
        # 1. password spraying: one hosting address fails against 25 different accounts in two minutes
        for k in range(25):
            ev(n, 60 + k * 4, f"user{k:02d}@example.test", VPN.format(10), "login", "failure"); n += 1
        # 2. account takeover: six failures then a success for one account, from a VPN exit it never used
        for k in range(6):
            ev(n, 300 + k * 5, f"priya{a.tag}@example.test", VPN.format(200), "login", "failure"); n += 1
        ev(n, 340, f"priya{a.tag}@example.test", VPN.format(200), "login", "success"); n += 1
        # 3. impossible travel: Bengaluru, then Frankfurt (hosting, not a VPN exit) ten minutes later
        ev(n, 400, f"ravi{a.tag}@example.test", HOME.format(20), "login", "success"); n += 1
        ev(n, 1000, f"ravi{a.tag}@example.test", VPN.format(50), "login", "success"); n += 1
        # 4. a login from an address on the tenant's block list
        ev(n, 600, f"meera{a.tag}@example.test", CLOUD.format(66), "login", "success"); n += 1
    else:
        users = [f"staff{k:03d}@example.test" for k in range(50)]
        for i in range(a.count):
            u = rnd.choice(users)
            ev(i, rnd.randint(0, 1100), u, HOME.format(1 + users.index(u) % 120), "login",
               "failure" if rnd.random() < 0.05 else "success")

    for k in range(0, len(events), a.batch):
        print(json.dumps({"events": events[k:k + a.batch]}))


if __name__ == "__main__":
    main()
