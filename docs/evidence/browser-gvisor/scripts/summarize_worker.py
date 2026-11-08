import json, sys
seen = []
for line in open(sys.argv[1]):
    try: e = json.loads(line)
    except ValueError: continue
    t, d = e.get("type"), e.get("data", {})
    if t == "navigation" and d.get("status") is not None:
        seen.append(f"HTTP {d['status']} {d.get('url', '')[:55]}")
    elif t == "request_failed":
        seen.append(f"{d.get('error')} {d.get('url', '')[:55]}")
    elif t == "worker_finished":
        seen.append("worker " + str(d.get("status")))
    if "LD-HOST-CANARY" in line or "LD-NEIGHBOUR-CANARY" in line:
        seen.append("!!! CANARY CONTENT REACHED THE BROWSER")
print("; ".join(seen))
