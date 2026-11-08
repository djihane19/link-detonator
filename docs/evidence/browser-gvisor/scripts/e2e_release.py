"""End-to-end scans through the candidate app's API. For each scan: what the event log
records, teardown on the host, and the receipt checked by the standalone verifier CLI
(screenshots downloaded and checked against it, digest saved at scan time)."""
import collections, json, os, subprocess, sys, tempfile, time, urllib.request

BASE = sys.argv[1]
VERIFIER = "/opt/link-detonator-candidate/tools/verify_receipt.py"

def call(path, body=None):
    req = urllib.request.Request(BASE + path, data=None if body is None else json.dumps(body).encode(), headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, r.read()

def teardown():
    labelled = subprocess.run(["docker", "ps", "-aq", "--filter", "label=link-detonator=1"], capture_output=True, text=True).stdout.split()
    sandboxes = subprocess.run(["pgrep", "-x", "runsc-sandbox"], capture_output=True, text=True).stdout.split()
    gofers = subprocess.run(["pgrep", "-x", "runsc-gofer"], capture_output=True, text=True).stdout.split()
    return f"containers={len(labelled)} runsc-sandbox={len(sandboxes)} runsc-gofer={len(gofers)}"

for fixture in sys.argv[2:]:
    t0 = time.time()
    sid = json.loads(call("/api/scans", {"fixture": fixture})[1])["id"]
    while json.loads(call(f"/api/scans/{sid}")[1]).get("status") in ("queued", "running"):
        time.sleep(1)
    scan = json.loads(call(f"/api/scans/{sid}")[1])
    wall = time.time() - t0
    receipt = json.loads(call(f"/api/scans/{sid}/receipt.json")[1])
    events = receipt["events"]
    by = {e["type"]: e["data"] for e in events}
    created, removed, exit_ = by.get("sandbox_created", {}), by.get("sandbox_removed", {}), by.get("sandbox_exit", {})
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "receipt.json")
        open(path, "w").write(json.dumps(receipt))
        shots = os.path.join(d, "shots"); os.mkdir(shots)
        for a in receipt["artifacts"]:
            open(os.path.join(shots, f"{a['seq']}.jpg"), "wb").write(call(f"/api/scans/{sid}/screenshots/{a['seq']}.jpg")[1])
        ok = subprocess.run([sys.executable, "-I", VERIFIER, path, "--digest", receipt["final_digest"], "--screenshots", shots], capture_output=True, text=True)
        tampered = dict(receipt); tampered["events"] = [dict(e) for e in events]
        tampered["events"][-1] = {**tampered["events"][-1], "ts": tampered["events"][-1]["ts"] + 1}
        open(path, "w").write(json.dumps(tampered))
        bad = subprocess.run([sys.executable, "-I", VERIFIER, path, "--digest", receipt["final_digest"]], capture_output=True, text=True)
    print(f"== {fixture}  scan={sid}  status={scan.get('status')}  wall={wall:.1f}s")
    print(f"   sandbox: runtime={created.get('runtime')} chromium_sandbox={created.get('policy', {}).get('chromium_sandbox')} resolver={created.get('policy', {}).get('resolver')}")
    print(f"   exit: {json.dumps(exit_)[:160]}")
    print(f"   worker: {by.get('worker_finished', {}).get('status')}  verdict: {by.get('verdict', {}).get('status')} {by.get('verdict', {}).get('classification')}")
    print(f"   events: {dict(sorted(collections.Counter(e['type'] for e in events).items()))}")
    print(f"   blocked: {dict(collections.Counter(e['data'].get('error') for e in events if e['type'] == 'request_failed'))}")
    print(f"   removal verified by host: {removed.get('verified')}   host teardown now: {teardown()}")
    print(f"   receipt CLI: exit {ok.returncode} {ok.stdout.strip().splitlines()[0] if ok.stdout else ok.stderr[:100]}")
    print(f"   receipt CLI on a 1-field edit: exit {bad.returncode} {bad.stdout.strip().splitlines()[0] if bad.stdout else ''}")
