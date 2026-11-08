"""SOC-in-a-repo triage bot.

Two modes, chosen by the issue form:
  * Investigate a Windows log: detect (verified + SigmaHQ community rules) -> extract indicators
    -> enrich -> apply playbook -> incident report
  * Look up indicators: refang and classify IPs, domains, URLs and hashes -> enrich -> verdict table

Outputs (in out/): report.md, labels.txt, close.txt ("yes"/"no").
The issue body is untrusted input: it is only parsed, never executed.
"""
import base64, ipaddress, json, os, pathlib, re, shutil, subprocess, sys, time, urllib.parse, urllib.request, zipfile
from collections import defaultdict
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHAINSAW = os.environ.get("CHAINSAW", "chainsaw/chainsaw")
MAPPING = os.environ.get("MAPPING", "chainsaw/mappings/sigma-event-logs-all.yml")
COMMUNITY = pathlib.Path(os.environ.get("COMMUNITY_RULES", str(ROOT / ".sigmahq/rules/windows")))
OUT = ROOT / "out"; OUT.mkdir(exist_ok=True)
WORK = ROOT / ".work"; WORK.mkdir(exist_ok=True)
MAX_BYTES = 25 * 1024 * 1024
MAX_FILES = 10

SAMPLES = {
    "Mimikatz stealing passwords from LSASS": "Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx",
    "LSASS memory dump with comsvcs.dll": "Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx",
    "PsExec lateral movement with Meterpreter": "Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx",
    "Security event log cleared": "Defense Evasion/DE_1102_security_log_cleared.evtx",
    "Clean activity (should find nothing)": "Execution/sysmon_lolbin_bohops_vshadow_exec.evtx",
}
PLAYBOOK = yaml.safe_load(open(ROOT / "playbooks/response.yml"))
ORDER = PLAYBOOK["severity_order"]
LEVEL = {"informational": "info", "info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
VERIFIED_IDS = {yaml.safe_load(open(p)).get("id") for p in (ROOT / "rules").rglob("*.yml")}


def finish(report, labels, close):
    (OUT / "report.md").write_text(report)
    (OUT / "labels.txt").write_text(",".join(labels))
    (OUT / "close.txt").write_text("yes" if close else "no")
    print(report)
    sys.exit(0)


def worse(a, b):
    return a if ORDER.index(a) >= ORDER.index(b) else b


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
    v = m.group(1).strip() if m else ""
    return "" if v == "_No response_" else v


def get_logs(body):
    """Return (directory or file to scan, description) or (None, error)."""
    choice = form_field(body, "Sample attack")
    if choice in SAMPLES:
        src = ROOT / ".samples"
        if not src.exists():
            subprocess.run(["git", "clone", "--depth", "1", "-q",
                            "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES", str(src)], check=True)
        return src / SAMPLES[choice], choice
    if choice.startswith("My own log"):
        links = re.findall(r"https://github\.com/(?:user-attachments/files|[\w.-]+/[\w.-]+/files)/\d+/[\w.\-]+",
                           form_field(body, "Your own log (optional)"))
        if not links:
            return None, "No attachment found. Drag the zip made by `collect.ps1` (or any zip of `.evtx` files) into the issue."
        req = urllib.request.Request(links[0], headers={"User-Agent": "soc-in-a-repo"})
        if os.environ.get("GH_TOKEN"):
            req.add_header("Authorization", f"token {os.environ['GH_TOKEN']}")  # private repos
        data = urllib.request.urlopen(req, timeout=120).read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            return None, "The attachment is larger than 25 MB. Collect fewer days of logs and try again."
        z = WORK / "upload.zip"; z.write_bytes(data)
        dest = WORK / "logs"; shutil.rmtree(dest, ignore_errors=True); dest.mkdir()
        try:
            with zipfile.ZipFile(z) as zf:
                names = [i for i in zf.infolist() if i.filename.lower().endswith(".evtx")][:MAX_FILES]
                if not names:
                    return None, "The zip has no `.evtx` files in it."
                total = 0
                for i, info in enumerate(names):
                    total += info.file_size
                    if total > 200 * 1024 * 1024:
                        return None, "The logs inside the zip are larger than 200 MB uncompressed."
                    safe = re.sub(r"[^\w.\-]", "_", pathlib.PurePath(info.filename).name)  # no path traversal
                    (dest / f"{i:02d}_{safe}").write_bytes(zf.read(info))
                return dest, f"Your uploaded logs ({len(names)} file{'s' if len(names) != 1 else ''})"
        except zipfile.BadZipFile:
            return None, "The attachment is not a valid zip file."
    return None, "Pick a sample attack from the dropdown, or choose \"My own log\" and attach a zip."


# ---------- 2. detection ----------
def hunt(target, rules):
    if not pathlib.Path(rules).exists():
        return []
    r = subprocess.run([CHAINSAW, "hunt", str(target), "-s", str(rules), "--mapping", MAPPING, "--json", "-q"],
                       capture_output=True, text=True, timeout=900)
    out = r.stdout.strip()
    return json.loads(out) if out else []


def techniques(tags):
    return [t.split(".", 1)[1].upper() for t in tags or [] if re.match(r"attack\.t\d{4}", t)]


def tactics(tags):
    return [t.split(".", 1)[1] for t in tags or [] if re.match(r"attack\.[a-z]", t) and not re.match(r"attack\.[gs]\d{4}", t)]


# ---------- 3. indicators ----------
IP_FIELDS = ("SourceIp", "DestinationIp", "IpAddress")
USER_FIELDS = ("User", "TargetUserName", "SubjectUserName")
PROC_FIELDS = ("Image", "SourceImage", "ParentImage")


def all_events(target):
    r = subprocess.run([CHAINSAW, "dump", str(target), "--json", "-q"], capture_output=True, text=True, timeout=900)
    try:
        return json.loads(r.stdout) if r.stdout.strip() else []
    except json.JSONDecodeError:
        return []


def ev_data(doc):
    ev = doc.get("Event", {})
    d = ev.get("EventData") or {}
    return d if isinstance(d, dict) else {}


def indicators(hits, target):
    iocs = {"ip": set(), "hash": {}, "domain": set(), "user": set()}
    procs = set()
    for h in hits:
        d = ev_data(h["document"]["data"])
        for f in PROC_FIELDS:
            if d.get(f): procs.add(str(d[f]))
        for f in USER_FIELDS:
            if d.get(f) and str(d[f]) not in ("-", ""): iocs["user"].add(str(d[f]))
        for f in IP_FIELDS:
            if d.get(f): iocs["ip"].add(str(d[f]))
    for e in all_events(target):
        d = ev_data(e)
        img = str(d.get("Image", ""))
        if img and img in procs:
            m = re.search(r"SHA256=([0-9A-Fa-f]{64})", str(d.get("Hashes", "")))
            if m: iocs["hash"][m.group(1).lower()] = img
            for f in IP_FIELDS:
                if d.get(f): iocs["ip"].add(str(d[f]))
            for f in ("QueryName", "DestinationHostname"):
                if d.get(f): iocs["domain"].add(str(d[f]))
    return iocs


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)
    except ValueError:
        return False


def defang(s):
    return s.replace("http", "hxxp").replace(".", "[.]")


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
    ident = base64.urlsafe_b64encode(value.encode()).decode().strip("=") if kind == "urls" else urllib.parse.quote(value, safe="")
    for attempt in range(2):
        r = call(f"https://www.virustotal.com/api/v3/{kind}/{ident}", {"x-apikey": VT})
        time.sleep(16)  # free tier: 4 requests a minute
        if "429" not in r.get("_error", ""): break
        time.sleep(30)  # rate limited: wait and retry once
    if "_error" in r:
        if "404" in r["_error"]: return {"verdict": "not seen by VirusTotal", "score": 0}
        code = re.search(r"HTTP Error (\d+)", r["_error"])
        return {"verdict": f"lookup failed ({'HTTP ' + code.group(1) if code else 'network error'})", "score": 0}
    s = r.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    bad = s.get("malicious", 0) + s.get("suspicious", 0)
    total = sum(s.values()) or 1
    return {"verdict": f"{bad}/{total} engines flag it", "score": min(100, int(bad / total * 300))}


def abuseipdb(ip):
    if not ABUSEIPDB: return None
    r = call(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90", {"Key": ABUSEIPDB, "Accept": "application/json"})
    if "_error" in r: return {"verdict": "lookup failed", "score": 0}
    d = r.get("data", {})
    c = d.get("abuseConfidenceScore", 0)
    extra = ", ".join(x for x in (d.get("countryCode"), d.get("isp")) if x)
    return {"verdict": f"abuse confidence {c}%" + (f" ({extra})" if extra else ""), "score": c}


def malwarebazaar(h):
    if not ABUSECH: return None
    r = call("https://mb-api.abuse.ch/api/v1/", {"Auth-Key": ABUSECH}, urllib.parse.urlencode({"query": "get_info", "hash": h}).encode())
    if r.get("query_status") == "ok":
        sig = (r.get("data") or [{}])[0].get("signature") or "known malware"
        return {"verdict": f"known malware: {sig}", "score": 100}
    return {"verdict": "not in MalwareBazaar", "score": 0}


def threatfox(value):
    if not ABUSECH: return None
    r = call("https://threatfox-api.abuse.ch/api/v1/", {"Auth-Key": ABUSECH, "Content-Type": "application/json"},
             json.dumps({"query": "search_ioc", "search_term": value}).encode())
    # search_ioc is a substring search ("google.com" matches any URL on google.com), so keep exact matches only
    v = value.lower()
    rows = r.get("data") if r.get("query_status") == "ok" and isinstance(r.get("data"), list) else []
    exact = [d for d in rows if isinstance(d, dict) and
             (str(d.get("ioc", "")).lower() == v or str(d.get("ioc", "")).lower().startswith(v + ":"))]
    if exact:
        return {"verdict": f"ThreatFox: {exact[0].get('malware_printable', 'malware')}", "score": 100}
    return {"verdict": "not in ThreatFox", "score": 0}


def urlhaus(url):
    if not ABUSECH: return None
    r = call("https://urlhaus-api.abuse.ch/v1/url/", {"Auth-Key": ABUSECH}, urllib.parse.urlencode({"url": url}).encode())
    if r.get("query_status") == "ok":
        return {"verdict": f"URLhaus: {r.get('threat') or 'malware URL'} ({r.get('url_status', 'unknown')})", "score": 100}
    return {"verdict": "not in URLhaus", "score": 0}


CHECKS = {
    "IP": lambda v: [("AbuseIPDB", lambda: abuseipdb(v)), ("VirusTotal", lambda: vt("ip_addresses", v)), ("ThreatFox", lambda: threatfox(v))],
    "domain": lambda v: [("VirusTotal", lambda: vt("domains", v)), ("ThreatFox", lambda: threatfox(v))],
    "URL": lambda v: [("VirusTotal", lambda: vt("urls", v)), ("URLhaus", lambda: urlhaus(v))],
    "file hash": lambda v: [("VirusTotal", lambda: vt("files", v)), ("MalwareBazaar", lambda: malwarebazaar(v))],
}


class Enricher:
    def __init__(self, budget):
        self.budget = budget

    def check(self, kind, value, context=""):
        if kind == "IP" and not is_public(value):
            return {"kind": kind, "value": value, "context": context or "internal address",
                    "results": [("-", "internal, not sent to threat intel", 0)], "score": 0, "checked": False}
        results = []
        for name, fn in CHECKS[kind](value):
            if self.budget <= 0:
                results.append((name, "skipped (lookup budget for this case used up)", 0)); continue
            r = fn()
            if r is None:
                results.append((name, "skipped (no API key configured)", 0))
            else:
                self.budget -= 1; results.append((name, r["verdict"], r["score"]))
        return {"kind": kind, "value": value, "context": context, "results": results,
                "score": max([s for _, _, s in results] or [0]),
                "checked": any(not v.startswith("skipped") for _, v, _ in results)}


def verdict_of(row):
    if not row["checked"]: return "not checked"
    if row["score"] >= 50: return "**malicious**"
    if row["score"] >= 10: return "suspicious"
    return "no known bad"


def ioc_table(rows):
    L = ["| Type | Indicator | Context | Verdict | Checks |", "|---|---|---|---|---|"]
    for r in rows:
        shown = defang(r["value"]) if r["kind"] in ("IP", "domain", "URL") else r["value"]
        checks = "<br>".join(f"{n}: {v}" for n, v, _ in r["results"])
        L.append(f"| {r['kind']} | `{shown}` | {r['context']} | {verdict_of(r)} | {checks} |")
    return "\n".join(L)


# ---------- 5a. indicator lookup mode ----------
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`|]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
MAX_IOCS = 10


def refang(text):
    t = re.sub(r"h[xX]{2}p", "http", text)
    return t.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[:]", ":").replace("[://]", "://")


def parse_iocs(text):
    t = refang(text)
    found, seen = [], set()
    def add(kind, v):
        if v.lower() not in seen:
            seen.add(v.lower()); found.append((kind, v))
    for u in URL_RE.findall(t): add("URL", u.rstrip(".,;)]"))
    rest = URL_RE.sub(" ", t)
    for h in HASH_RE.findall(rest): add("file hash", h.lower())
    rest = HASH_RE.sub(" ", rest)
    for ip in IP_RE.findall(rest):
        try: ipaddress.ip_address(ip); add("IP", ip)
        except ValueError: pass
    rest = IP_RE.sub(" ", rest)
    for d in DOMAIN_RE.findall(rest):
        if not re.search(r"\.(exe|dll|ps1|bat|txt|log|evtx|zip|py|js)$", d, re.I): add("domain", d.lower())
    return found


def lookup_mode(body, t0):
    iocs = parse_iocs(form_field(body, "Indicators"))
    if not iocs:
        finish("## Could not start the lookup\n\nNo IPs, domains, URLs or hashes found. Paste one indicator per line; defanged values like `evil[.]com` are fine.\n",
               ["needs-info"], False)
    extra = len(iocs) - MAX_IOCS
    iocs = iocs[:MAX_IOCS]
    en = Enricher(budget=24)
    rows = [en.check(k, v) for k, v in iocs]
    bad = [r for r in rows if r["score"] >= 50]
    sus = [r for r in rows if 10 <= r["score"] < 50]
    checked = [r for r in rows if r["checked"]]
    overall = "malicious" if bad else "suspicious" if sus else "no known bad" if checked else "not checked"
    L = [f"## Indicator lookup: {overall.upper()}\n",
         f"{len(rows)} indicator{'s' if len(rows) != 1 else ''} found, {len(checked)} checked: **{len(bad)} malicious**, {len(sus)} suspicious, {len(checked) - len(bad) - len(sus)} with no known bad reputation.\n"]
    if extra > 0:
        L.append(f"> Only the first {MAX_IOCS} indicators were checked to stay inside the free API limits ({extra} skipped).\n")
    L.append(ioc_table(rows))
    L.append("\n### Recommended response\n")
    if bad:
        L += ["1. Block the malicious indicators at the proxy, firewall, DNS and EDR",
              "2. Search the SIEM for any host that contacted or ran them in the last 30 days",
              "3. For any hit, open a log investigation on that host",
              "4. Add confirmed indicators to your threat intel platform or blocklist"]
    elif not checked:
        L += ["1. Nothing could be checked: add the free API keys in Settings > Secrets and variables > Actions"]
    else:
        L += ["1. No reputation hits. That is not proof of safety: new infrastructure is often unknown for a few days",
              "2. If these came from a suspicious email or alert, keep the case open and re-check in 24 hours"]
    L.append(f"\n<sub>Defanged for safe sharing. Sources: VirusTotal, AbuseIPDB, MalwareBazaar, ThreatFox, URLhaus. Time to report: {int(time.time() - t0)}s.</sub>\n")
    labels = ["mode: indicator lookup", f"verdict: {overall}"]
    finish("\n".join(L), labels, bool(checked) and not bad and not sus)


# ---------- 5b. log investigation mode ----------
def playbook_for(tech, tacs):
    pb = PLAYBOOK["techniques"].get(tech)
    if pb: return pb
    for ta in tacs:
        g = PLAYBOOK.get("tactics", {}).get(ta)
        if g: return {**g, "name": tech, "generic": True}
    return None


def log_mode(body, t0):
    target, source = get_logs(body)
    if target is None:
        finish(f"## Could not start the investigation\n\n{source}\n", ["needs-info"], False)

    verified = hunt(target, ROOT / "rules")
    community = [h for h in hunt(target, COMMUNITY) if h.get("id") not in VERIFIED_IDS]
    hits = verified + community
    n_comm = len(list(COMMUNITY.rglob("*.yml"))) if COMMUNITY.exists() else 0
    if not hits:
        finish(f"## Incident report: no findings\n\n**Log:** {source}\n\nNone of the {len(VERIFIED_IDS)} verified rules or the {n_comm:,} SigmaHQ community rules matched. "
               "Verdict: **no detections**, closing automatically.\n\n> No findings means none of these rules matched. It is not proof the host is clean.\n\n"
               "<sub>Detection by Sigma rules + Chainsaw. Playbook: playbooks/response.yml</sub>\n",
               ["verdict: no detections", "severity: info"], True)

    sev = "info"
    techs = {}
    for h in verified:
        sev = worse(sev, LEVEL.get(h.get("level", "low"), "low"))
        for t in techniques(h.get("tags")):
            pb = playbook_for(t, tactics(h.get("tags")))
            if pb: techs[t] = pb; sev = worse(sev, pb["severity"])
    for h in community:
        lvl = LEVEL.get(h.get("level", "low"), "low")
        sev = worse(sev, "high" if lvl == "critical" else lvl)  # community alone tops out at high
        for t in techniques(h.get("tags")):
            pb = playbook_for(t, tactics(h.get("tags")))
            if pb and t not in techs: techs[t] = pb

    iocs = indicators(hits, target)
    en = Enricher(budget=8)
    rows = [en.check("file hash", h, pathlib.PureWindowsPath(img).name) for h, img in list(iocs["hash"].items())[:4]]
    rows += [en.check("IP", ip) for ip in sorted(iocs["ip"])[:6]]
    rows += [en.check("domain", d) for d in sorted(iocs["domain"])[:4]]
    if any(r["score"] >= 50 for r in rows) and sev != "critical":
        sev = ORDER[ORDER.index(sev) + 1]  # threat intel confirms: raise one level
    hosts = sorted({h["document"]["data"]["Event"]["System"].get("Computer", "unknown") for h in hits})

    L = [f"## Incident report: {sev.upper()}\n",
         f"| | |\n|---|---|\n| **Log** | {source} |\n| **Host** | {', '.join(f'`{x}`' for x in hosts[:5])} |\n"
         f"| **Detections** | {len(verified)} verified, {len(community)} community |\n"
         f"| **Severity** | **{sev}** |\n| **Routing** | {PLAYBOOK['routing'][sev]} |\n"]

    if verified:
        L.append("### Verified detections\n\nTested rules from this repo. High confidence.\n")
        L.append("| Time (UTC) | Rule | Level | ATT&CK | Process |\n|---|---|---|---|---|")
        for h in sorted(verified, key=lambda x: x["timestamp"])[:20]:
            d = ev_data(h["document"]["data"])
            proc = pathlib.PureWindowsPath(str(d.get("Image") or d.get("SourceImage") or "-")).name
            L.append(f"| {h['timestamp'][:19].replace('T', ' ')} | {h['name']} | {h.get('level', '')} | {', '.join(techniques(h.get('tags')))} | `{proc}` |")
        L.append("")
    if community:
        grouped = defaultdict(list)
        for h in community: grouped[(h["name"], h.get("level", ""))].append(h)
        L.append("### Community detections\n\nSigmaHQ rules. Broad coverage, needs analyst review.\n")
        L.append("| Rule | Level | ATT&CK | Hits | First seen (UTC) |\n|---|---|---|---|---|")
        order = sorted(grouped.items(), key=lambda kv: (-ORDER.index(LEVEL.get(kv[0][1], "low")), -len(kv[1])))
        for (name, lvl), hs in order[:15]:
            first = min(x["timestamp"] for x in hs)[:19].replace("T", " ")
            L.append(f"| {name} | {lvl} | {', '.join(sorted(set(sum((techniques(x.get('tags')) for x in hs), []))))} | {len(hs)} | {first} |")
        if len(order) > 15: L.append(f"\n{len(order) - 15} more community rules matched; see the workflow log for the full list.")
        L.append("")

    if techs:
        L.append("### What it means\n")
        generic = defaultdict(list)
        for t, pb in techs.items():
            if pb.get("generic"):
                generic[(pb.get("tactic", ""), pb["why"])].append(t)
            else:
                L.append(f"**{t} {pb['name']}** ({pb.get('tactic', '')})  \n{pb['why']}\n")
        for (tactic, why), ts in generic.items():
            L.append(f"**{tactic}: {', '.join(ts)}** (generic playbook for this tactic)  \n{why}\n")
    L.append("### Indicators and threat intel\n")
    L.append(ioc_table(rows) if rows else "No file or network indicators in the matching events.")
    if iocs["user"]: L.append(f"\n**Accounts involved:** {', '.join(f'`{u}`' for u in sorted(iocs['user'])[:10])}")
    if any(r["kind"] == "file hash" and r["checked"] and r["score"] < 10 for r in rows):
        L.append("\n> Note: the file hashes came back clean. That's normal when an attacker uses built-in Windows tools (living off the land), so don't close this on the hash result alone.")
    L.append("\n### Recommended response\n")
    steps, seen = [], set()
    for pb in techs.values():
        for s in pb["contain"]:
            if s not in seen: seen.add(s); steps.append(s)
    if not steps:
        steps = ["Review the community detections above and confirm whether the activity is expected on this host"]
    L += [f"{i}. {s}" for i, s in enumerate(steps[:10], 1)]
    L.append(f"\n<sub>Detection: {len(VERIFIED_IDS)} verified rules + {n_comm:,} SigmaHQ community rules via Chainsaw. "
             f"Enrichment: VirusTotal, AbuseIPDB, abuse.ch. Playbook: playbooks/response.yml. Time to report: {int(time.time() - t0)}s.</sub>\n")
    labels = [f"severity: {sev}", "verdict: malicious" if sev in ("high", "critical") else "verdict: suspicious"]
    labels += [f"attack: {t}" for t in list(techs)[:5]]
    finish("\n".join(L), labels, False)


def main():
    t0 = time.time()
    body = issue_body()
    if "### Indicators" in body and "### Sample attack" not in body:
        lookup_mode(body, t0)
    log_mode(body, t0)


if __name__ == "__main__":
    main()
