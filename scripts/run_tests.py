"""Detection-as-code test runner.
For every Sigma rule: run it against every test log with Chainsaw.
PASS = fires on the logs listed in tests/expected.yml and stays silent on all the others.
Then convert each rule to Splunk and Elastic queries and build an ATT&CK coverage layer."""
import json, subprocess, sys, pathlib, yaml
ROOT = pathlib.Path(__file__).resolve().parents[1]
CHAINSAW = sys.argv[1] if len(sys.argv) > 1 else "chainsaw"
MAPPING = sys.argv[2] if len(sys.argv) > 2 else "mappings/sigma-event-logs-all.yml"
rules = sorted((ROOT / "rules").rglob("*.yml"))
logs = sorted((ROOT / "tests/logs").glob("*.evtx"))
expected = yaml.safe_load(open(ROOT / "tests/expected.yml"))

def hits(rule, log):
    out = subprocess.run([CHAINSAW, "hunt", str(log), "-s", str(rule), "--mapping", MAPPING, "--json", "-q"],
                         capture_output=True, text=True).stdout.strip()
    return len(json.loads(out)) if out else 0

results, failed = [], 0
for r in rules:
    want = set(expected.get(r.stem, []))
    if not want:
        print(f"FAIL  {r.stem}: no attack log proves this rule works"); failed += 1; continue
    for log in logs:
        n = hits(r, log)
        should = log.name in want
        ok = (n > 0) == should
        kind = "true positive" if should and ok else "missed attack" if should else "quiet" if ok else "FALSE POSITIVE"
        results.append({"rule": r.stem, "log": log.name, "hits": n, "expected": should, "pass": ok, "result": kind})
        if not ok: failed += 1
        print(f"{'PASS' if ok else 'FAIL'}  {r.stem:34} {log.name:30} hits={n:<3} {kind}")

# Convert to SIEM queries
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline
queries, layer = {}, {}
for r in rules:
    col = SigmaCollection.from_yaml(r.read_text())
    rule = col.rules[0]
    pipe = sysmon_pipeline() + windows_logsource_pipeline()
    queries[r.stem] = {"title": rule.title, "level": str(rule.level),
        "splunk": SplunkBackend(pipe).convert(col)[0],
        "elastic": LuceneBackend(pipe).convert(col)[0]}
    for t in rule.tags:
        if t.namespace == "attack" and t.name.startswith("t"):
            layer.setdefault(t.name.upper(), []).append(rule.title)
nav = {"name": "Detection coverage", "domain": "enterprise-attack", "versions": {"layer": "4.5", "navigator": "4.9"},
       "techniques": [{"techniqueID": k, "score": len(v), "color": "#4f8cff", "comment": "; ".join(v)} for k, v in layer.items()]}
out = ROOT / "build"; out.mkdir(exist_ok=True)
json.dump(results, open(out / "test_results.json", "w"), indent=1)
json.dump(queries, open(out / "queries.json", "w"), indent=1)
json.dump(nav, open(out / "attack_layer.json", "w"), indent=1)
print(f"\n{len(rules)} rules, {len(logs)} logs, {len(results)} checks, {failed} failed")
sys.exit(1 if failed else 0)
