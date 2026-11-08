"""SOC-in-a-repo triage bot.

Issue opened -> get the log -> run the Sigma rules (detection)
-> pull indicators out of the matching events -> enrich them (SOAR)
-> apply the response playbook -> write an incident report.

Outputs (in out/): report.md, labels.txt, close.txt ("yes"/"no").
The issue body is untrusted input: it is only parsed, never executed.
"""
import ipaddress, json, os, pathlib, re, subprocess, sys, time, urllib.parse, urllib.request, zipfile
from collections import defaultdict
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHAINSAW = os.environ.get("CHAINSAW", "chainsaw/chainsaw")
MAPPING = os.environ.get("MAPPING", "chainsaw/mappings/sigma-event-logs-all.yml")
OUT = ROOT / "out"; OUT.mkdir(exist_ok=True)
WORK = ROOT / ".work"; WORK.mkdir(exist_ok=True)
MAX_BYTES = 20 * 1024 * 1024

SAMPLES = {
    "Mimikatz stealing passwords from LSASS": "Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx",
    "LSASS memory dump with comsvcs.dll": "Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx",
    "PsExec lateral movement with Meterpreter": "Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx",
    "Security event log cleared": "Defense Evasion/DE_1102_security_log_cleared.evtx",
    "Clean activity (should find nothing)": "Execution/sysmon_lolbin_bohops_vshadow_exec.evtx",
}
PLAYBOOK = yaml.safe_load(open(ROOT / "playbooks/response.yml"))
ORDER = PLAYBOOK["severity_order"]


def finish(report, labels, close):
    (OUT / "report.md").write_text(report)
    (OUT / "labels.txt").write_text(",".join(labels))
    (OUT / "close.txt").write_text("yes" if close else "no")
    print(report)
    sys.exit(0)


# ---------- 1. read the issue ----------
def issue_body():
    if os.environ.get("ISSUE_BODY"):
        return os.environ["ISSUE_BODY"]
    p = os.environ.get("GITHUB_EVENT_PATH")
    if p and pathlib.Path(p).exists():
        return json.load(open(p)).get("issue", {}).get("body") or ""
    return ""


def form_field(body, label):
    m = re.search(r"###\s*" + re.escape(label) + r"\s*\n+(.*?)(?=\n###|\Z)", body, re.S)
    return (m.group(1).strip() if m else "")


def get_log(body):
    choice = form_field(body, "Sample attack")
    if choice in SAMPLES:
        src = ROOT / ".samples"
        if not src.exists():
            subprocess.run(["git", "clone", "--depth", "1", "-q",
                            "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES", str(src)], check=True)
        return src / SAMPLES[choice], choice
    if choice.startswith("My own log"):
        links = re.findall(r"https://github\.com/user-attachments/files/\d+/[\w.\-]+", form_field(body, "Your own log (optional)"))
        if not links:
            return None, "No attachment found. Drag a zipped .evtx file into the issue."
        req = urllib.request.Request(links[0], headers={"User-Agent": "soc-in-a-repo"})
        data = urllib.request.urlopen(req, timeout=60).read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            return None, "Attachment is larger than 20 MB."
        z = WORK / "upload.zip"; z.write_bytes(data)
        try:
            with zipfile.ZipFile(z) as zf:
                evtx = [n for n in zf.namelist() if n.lower().endswith(".evtx") and not n.startswith("/") and ".." not in n]
                if not evtx:
                    return None, "The zip has no .evtx file in it."
                info = zf.getinfo(evtx[0])
                if info.file_size > MAX_BYTES:
                    return None, "The .evtx inside the zip is larger than 20 MB."
                target = WORK / "upload.evtx"; target.write_bytes(zf.read(info))
                return target, "Your uploaded log"
        except zipfile.BadZipFile:
            return None, "The attachment is not a valid zip file."
    return None, "Pick a sample attack from the dropdown."


# ---------- 2. detection ----------
def hunt(log):
    r = subprocess.run([CHAINSAW, "hunt", str(log), "-s", str(ROOT / "rules"), "--mapping", MAPPING, "--json", "-q"],
                       capture_output=True, text=True, timeout=600)
    out = r.stdout.strip()
    return json.loads(out) if out else []


def techniques(tags):
    return [t.split(".", 1)[1].upper() for t in tags if re.match(r"attack\.t\d{4}", t)]


# ---------- 3. indicators ----------
IP_FIELDS = ("SourceIp", "DestinationIp", "IpAddress")
USER_FIELDS = ("User", "TargetUserName", "SubjectUserName")
PROC_FIELDS = ("Image", "SourceImage", "ParentImage")


def all_events(log):
    r = subprocess.run([CHAINSAW, "dump", str(log), "--json", "-q"], capture_output=True, text=True, timeout=600)
    return json.loads(r.stdout) if r.stdout.strip() else []


def ev_data(doc):
    ev = doc.get("Event", {})
    d = ev.get("EventData") or {}
    return d if isinstance(d, dict) else {}


def indicators(hits, log):
    iocs = {"ip": set(), "hash": {}, "domain": set(), "user": set(), "process": set()}
    procs = set()
    for h in hits:
        d = ev_data(h["document"]["data"])
        for f in PROC_FIELDS:
            if d.get(f): procs.add(str(d[f]))
        for f in USER_FIELDS:
            if d.get(f) and str(d[f]) not in ("-", ""): iocs["user"].add(str(d[f]))
        for f in IP_FIELDS:
            if d.get(f): iocs["ip"].add(str(d[f]))
    # widen to the same processes elsewhere in the log: their hashes, network and DNS activity
    for e in all_events(log):
        d = ev_data(e)
        img = str(d.get("Image", ""))
        if img and img in procs:
            m = re.search(r"SHA256=([0-9A-Fa-f]{64})", str(d.get("Hashes", "")))
            if m: iocs["hash"][m.group(1).lower()] = img
            for f in IP_FIELDS:
                if d.get(f): iocs["ip"].add(str(d[f]))
            for f in ("QueryName", "DestinationHostname"):
                if d.get(f): iocs["domain"].add(str(d[f]))
    iocs["process"] = procs
    return iocs


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)
    except ValueError:
        return False


def defang(s):
    return s.replace(".", "[.]").replace("http", "hxxp")


# ---------- 4. enrichment (free tiers) ----------
VT = os.environ.get("VT_API_KEY", "")
ABUSEIPDB = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSECH = os.environ.get("ABUSECH_AUTH_KEY", "")


def call(url, headers, data=None):
    try:
        req = urllib.request.Request(url, data=data, headers={"User-Agent": "soc-in-a-repo", **headers})
        return json.load(urllib.request.urlopen(req, timeout=20))
    except Exception as e:
        return {"_error": str(e)[:80]}


def vt(kind, value):
    if not VT: return None
    r = call(f"https://www.virustotal.com/api/v3/{kind}/{urllib.parse.quote(value)}", {"x-apikey": VT})
    time.sleep(16)  # free tier: 4 requests a minute
    if "_error" in r: return {"verdict": "not found" if "404" in r["_error"] else "lookup failed", "score": 0}
    s = r.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    bad = s.get("malicious", 0) + s.get("suspicious", 0)
    total = sum(s.values()) or 1
    return {"verdict": f"{bad}/{total} engines flag it", "score": min(100, int(bad / total * 300))}


def abuseipdb(ip):
    if not ABUSEIPDB: return None
    r = call(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90", {"Key": ABUSEIPDB, "Accept": "application/json"})
    if "_error" in r: return {"verdict": "lookup failed", "score": 0}
    c = r.get("data", {}).get("abuseConfidenceScore", 0)
    return {"verdict": f"abuse confidence {c}%", "score": c}


def malwarebazaar(sha256):
    if not ABUSECH: return None
    r = call("https://mb-api.abuse.ch/api/v1/", {"Auth-Key": ABUSECH}, urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode())
    if r.get("query_status") == "ok":
        sig = (r.get("data") or [{}])[0].get("signature") or "known malware"
        return {"verdict": f"known malware: {sig}", "score": 100}
    return {"verdict": "not in MalwareBazaar", "score": 0}


def threatfox(value):
    if not ABUSECH: return None
    r = call("https://threatfox-api.abuse.ch/api/v1/", {"Auth-Key": ABUSECH, "Content-Type": "application/json"},
             json.dumps({"query": "search_ioc", "search_term": value}).encode())
    if r.get("query_status") == "ok":
        mal = (r.get("data") or [{}])[0].get("malware_printable", "malware")
        return {"verdict": f"ThreatFox: {mal}", "score": 100}
    return {"verdict": "not in ThreatFox", "score": 0}


def enrich(iocs, budget=8):
    rows = []
    def add(kind, value, context, checks):
        nonlocal budget
        results = []
        for name, fn in checks:
            if budget <= 0:
                results.append((name, "skipped (daily lookup budget)", 0)); continue
            r = fn()
            if r is None:
                results.append((name, "skipped (no API key configured yet)", 0))
            else:
                budget -= 1; results.append((name, r["verdict"], r["score"]))
        rows.append({"kind": kind, "value": value, "context": context, "results": results,
                     "score": max([s for _, _, s in results] or [0])})
    for h, img in list(iocs["hash"].items())[:4]:
        add("file hash", h, pathlib.PureWindowsPath(img).name, [("VirusTotal", lambda h=h: vt("files", h)), ("MalwareBazaar", lambda h=h: malwarebazaar(h))])
    for ip in sorted(iocs["ip"]):
        if not is_public(ip):
            rows.append({"kind": "IP", "value": ip, "context": "internal address", "results": [("-", "internal, not sent to threat intel", 0)], "score": 0}); continue
        add("IP", ip, "", [("AbuseIPDB", lambda ip=ip: abuseipdb(ip)), ("VirusTotal", lambda ip=ip: vt("ip_addresses", ip)), ("ThreatFox", lambda ip=ip: threatfox(ip))])
    for dm in sorted(iocs["domain"])[:4]:
        add("domain", dm, "", [("VirusTotal", lambda dm=dm: vt("domains", dm)), ("ThreatFox", lambda dm=dm: threatfox(dm))])
    return rows


# ---------- 5. playbook + report ----------
def main():
    t0 = time.time()
    body = issue_body()
    log, source = get_log(body)
    if log is None:
        finish(f"## Could not start the investigation\n\n{source}\n", ["needs-info"], False)

    hits = hunt(log)
    if not hits:
        finish(f"## Incident report: no findings\n\n**Log:** {source}\n\nNone of the {len(list((ROOT/'rules').rglob('*.yml')))} detection rules matched. "
               "Verdict: **benign**, closing automatically.\n\n<sub>Detection by Sigma rules + Chainsaw. Playbook: playbooks/response.yml</sub>\n",
               ["verdict: benign", "severity: info"], True)

    by_rule = defaultdict(list)
    for h in hits: by_rule[h["name"]].append(h)
    techs, sev = {}, "info"
    for h in hits:
        for t in techniques(h.get("tags", [])):
            pb = PLAYBOOK["techniques"].get(t)
            if pb:
                techs[t] = pb
                if ORDER.index(pb["severity"]) > ORDER.index(sev): sev = pb["severity"]
        lvl = h.get("level", "low")
        if lvl in ORDER and ORDER.index(lvl) > ORDER.index(sev): sev = lvl

    iocs = indicators(hits, log)
    rows = enrich(iocs)
    intel_bad = [r for r in rows if r["score"] >= 50]
    if intel_bad and ORDER.index(sev) < ORDER.index("critical"):
        sev = ORDER[ORDER.index(sev) + 1]  # threat intel confirms: raise one level
    host = hits[0]["document"]["data"]["Event"]["System"].get("Computer", "unknown")

    L = []
    L.append(f"## Incident report: {sev.upper()}\n")
    L.append(f"| | |\n|---|---|\n| **Log** | {source} |\n| **Host** | `{host}` |\n| **Detections** | {len(hits)} events, {len(by_rule)} rule{'s' if len(by_rule) != 1 else ''} |\n"
             f"| **Severity** | **{sev}** |\n| **Routing** | {PLAYBOOK['routing'][sev]} |\n")
    L.append("### Timeline\n\n| Time (UTC) | Rule | Level | ATT&CK | Process |\n|---|---|---|---|---|")
    for h in sorted(hits, key=lambda x: x["timestamp"]):
        d = ev_data(h["document"]["data"])
        proc = pathlib.PureWindowsPath(str(d.get("Image") or d.get("SourceImage") or "-")).name
        L.append(f"| {h['timestamp'][:19].replace('T', ' ')} | {h['name']} | {h.get('level', '')} | {', '.join(techniques(h.get('tags', [])))} | `{proc}` |")
    L.append("")
    L.append("### What it means\n")
    for t, pb in techs.items():
        L.append(f"**{t} {pb['name']}** ({pb['tactic']})  \n{pb['why']}\n")
    L.append("### Indicators and threat intel\n")
    if rows:
        L.append("| Type | Indicator | Context | Checks |\n|---|---|---|---|")
        for r in rows:
            checks = "<br>".join(f"{n}: {v}" for n, v, _ in r["results"])
            L.append(f"| {r['kind']} | `{defang(r['value']) if r['kind'] in ('IP', 'domain') else r['value']}` | {r['context']} | {checks} |")
    else:
        L.append("No network or file indicators in the matching events.")
    if iocs["user"]: L.append(f"\n**Accounts involved:** {', '.join(f'`{u}`' for u in sorted(iocs['user']))}")
    if any(r["kind"] == "file hash" and r["score"] < 50 and any(not v.startswith("skipped") for _, v, _ in r["results"]) for r in rows):
        L.append("\n> Clean file hashes here usually mean *living off the land*: a legitimate Windows binary used for something malicious. The behaviour is the threat, not the file.")
    L.append("\n### Recommended response\n")
    n = 1
    for t, pb in techs.items():
        for step in pb["contain"]:
            L.append(f"{n}. {step}"); n += 1
    L.append(f"\n<sub>Detection: Sigma rules + Chainsaw. Enrichment: VirusTotal, AbuseIPDB, abuse.ch. Playbook: playbooks/response.yml. "
             f"Time to report: {int(time.time() - t0)}s.</sub>\n")
    labels = [f"severity: {sev}", "verdict: malicious" if sev in ("high", "critical") else "verdict: suspicious"] + [f"attack: {t}" for t in techs]
    finish("\n".join(L), labels, False)


if __name__ == "__main__":
    main()
