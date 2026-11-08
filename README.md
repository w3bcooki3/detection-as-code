# SOC in a repo

A working mini-SOC that runs entirely on GitHub, for free. Open an issue with a Windows log and a bot detects the attack, enriches what it finds with threat intel, applies a response playbook and posts an incident report.

![detections](https://github.com/w3bcooki3/detection-as-code/actions/workflows/detections.yml/badge.svg)

## Try it (about two minutes)

1. Go to **[New investigation](https://github.com/w3bcooki3/detection-as-code/issues/new?template=investigate.yml)**
2. Pick a sample attack, for example *Mimikatz stealing passwords from LSASS*
3. Submit. The bot replies with an incident report: timeline, ATT&CK techniques, enriched indicators, severity, routing and response steps

Sample attacks are real recordings from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES). You can also attach your own zipped `.evtx` from a lab. This repo is public, so never upload logs from a real company.

## Real use case: a password-theft alert at 2 AM

**The situation.** A SOC analyst on night shift gets an EDR alert from a laptop: `rundll32.exe` touched LSASS memory. The file is a signed Windows binary, so the antivirus says nothing. Is this an attack or noise?

**Manually,** the analyst would pull the logs, read the process command line, copy hashes into VirusTotal and MalwareBazaar one by one, look up the ATT&CK technique, decide the severity, find the right runbook and write up the ticket. That's 20 to 30 minutes, at 2 AM, while the attacker keeps moving.

**With this repo,** the analyst opens an investigation with the exported log. This is an excerpt of the real report the bot posted on [issue #3](https://github.com/w3bcooki3/detection-as-code/issues/3), 17 seconds later:

> **Incident report: CRITICAL**
>
> | | |
> |---|---|
> | Host | `MSEDGEWIN10` |
> | Detection | LSASS Memory Dump via comsvcs.dll MiniDump (T1003.001) |
> | Process | `rundll32.exe` |
> | Routing | escalate to incident response now |
>
> **Threat intel:** `rundll32.exe` hash, VirusTotal **0/75 engines flag it**, not in MalwareBazaar
>
> *Clean file hashes here usually mean living off the land: a legitimate Windows binary used for something malicious. The behaviour is the threat, not the file.*
>
> **Recommended response:** isolate the host with your EDR, reset passwords for every account that logged on (starting with admins), hunt for the same command line on other hosts, watch for new logons from these accounts for 72 hours.
>
> Labels added: `severity: critical` `verdict: malicious` `attack: T1003.001`

**Why it matters.** A hash lookup alone would have called this clean (0/75). The detection rule caught the *behaviour*, the playbook turned it into a critical case with clear next steps, and the analyst went straight to containment instead of research.

| | Manual triage | With the bot |
|---|---|---|
| Time to a verdict | 20 to 30 minutes | under a minute |
| Threat intel lookups | copy and paste, one site at a time | automatic, every indicator |
| Severity and routing | analyst judgment at 2 AM | consistent, from the playbook |
| Write-up | typed by hand | posted on the case, ready for handoff |

## What it can and can't do

### Capabilities

| Area | What it does today |
|---|---|
| Input | A Windows event log (`.evtx`): one of 5 built-in attack samples, or your own lab log uploaded as a zip |
| Log types | Sysmon (process creation, process access, network, DNS) and the Windows Security and System logs |
| Detection | 4 tested Sigma rules covering 3 ATT&CK techniques: LSASS credential dumping (T1003.001), hidden PowerShell (T1059.001), log clearing (T1070.001) |
| Indicator extraction | File hashes (SHA256), IP addresses, domains, accounts and process names from the matching events and the same processes elsewhere in the log |
| Enrichment | VirusTotal (files, IPs, domains), AbuseIPDB (IPs), MalwareBazaar (hashes), ThreatFox (IPs, domains) |
| Decision | Severity from the playbook and rule level, raised one step when threat intel confirms something malicious |
| Response | Routing (who handles it and how fast) plus containment steps per technique, from `playbooks/response.yml` |
| Case handling | Posts the report, labels severity, verdict and technique, auto-closes benign cases |
| Quality | Every rule is tested against real attack logs on every push, plus a smoke test of the bot |
| Speed and cost | A report in under a minute, on free GitHub Actions and free API tiers |

### Limitations

- **Windows only.** No Linux, macOS, cloud (AWS, Azure, Microsoft 365), firewall, proxy or DNS server logs yet.
- **Narrow coverage.** 4 rules for 3 techniques. Most attacks will come back as "no findings", which means "not covered", not "safe".
- **Not real time.** Someone has to export a log and open an issue. It does not connect to a SIEM or EDR or watch live events.
- **Recommends, does not act.** It never isolates hosts, disables accounts or blocks indicators. A human does that, by design.
- **Free API limits.** VirusTotal allows 4 lookups a minute, so the bot caps each case at 8 lookups and checks at most 4 hashes. Large logs get partial enrichment.
- **Indicators depend on the log.** If the log has no Sysmon process-creation events, there are no hashes to check (the Mimikatz sample is an example).
- **Simple severity logic.** No correlation across cases, no deduplication, no asset or user context such as "this is a domain controller".
- **Public by design.** Issues and uploads are visible to everyone, so it is for lab and sample data only, never real company logs.
- **Upload limits.** One zipped `.evtx`, 20 MB max, 25 investigations a day.

### Roadmap

- More rules: RDP brute force, new service installs, scheduled tasks, encoded PowerShell, shadow copy deletion
- Linux auth logs and Microsoft 365 sign-in logs
- A metrics page: cases per day, time to report, verdict mix
- Correlation: link cases that share a host, account or indicator
- Notifications to Slack or Teams for critical cases

## How it works

```mermaid
flowchart TD
  A["Issue opened<br/>sample attack or uploaded log"] --> B["Detection<br/>Sigma rules run by Chainsaw"]
  B -- "no rule fires" --> Z["Report: benign<br/>auto-close"]
  B -- "rules fire" --> C["Extract indicators<br/>hashes, IPs, domains, accounts"]
  C --> D["Enrichment<br/>VirusTotal, AbuseIPDB, MalwareBazaar, ThreatFox"]
  D --> E["Playbook<br/>severity, routing, response steps per ATT&CK technique"]
  E --> F["Incident report posted<br/>labels: severity, verdict, technique"]
  R["Rule change pushed"] --> T{"Test gate<br/>every rule x every attack log"}
  T -- "missed attack or false alarm" --> X["Build fails"]
  T -- "pass" --> B
```

Two loops:

- **Response loop.** Every issue is a case. Detection, enrichment, playbook and report run in GitHub Actions with no server.
- **Engineering loop.** Every rule must catch a real attack and stay silent on everything else before it can reach the bot. 4 rules x 8 logs = 32 checks on every push.

## Layout

| Path | What it is |
|---|---|
| `rules/` | Sigma detection rules, tagged with MITRE ATT&CK |
| `playbooks/response.yml` | Response playbook: severity, routing and containment steps per technique |
| `scripts/triage.py` | The bot: detect, extract indicators, enrich, apply playbook, write the report |
| `scripts/run_tests.py` | Test gate for the rules, plus Splunk and Elastic query conversion and an ATT&CK layer |
| `tests/expected.yml` | Which rule must fire on which attack log |
| `.github/workflows/triage.yml` | Runs the bot when an investigation issue is opened |
| `.github/workflows/detections.yml` | Runs the test gate and a smoke test of the bot on every push |

## Current detections

| Rule | ATT&CK | Playbook severity |
|---|---|---|
| LSASS memory dump via comsvcs.dll MiniDump | T1003.001 | critical |
| Suspicious process access to LSASS | T1003.001 | critical |
| Hidden PowerShell without profile | T1059.001 | high |
| Security event log cleared (1102) | T1070.001 | high |

## What the test gate caught

- **Blind rule.** The first log-cleared rule never fired. Event 1102 is written by the Eventlog provider, not Security-Auditing, so the log source was wrong.
- **Mislabelled sample.** The LSASS rule fired on a sample labelled "discovery". The hit was `D:\m.exe` (Meterpreter) opening LSASS with `0x1410`, a real credential theft. The rule was right and became a required catch.

## Guard rails

- At most 25 investigations a day, so nobody can burn the free API quotas
- Private IP addresses are never sent to threat intel services
- Uploaded files: zip only, one `.evtx`, 20 MB cap, no path traversal
- The issue body is parsed as data and never executed

## Setup for your own copy

Fork it, then add free API keys under **Settings > Secrets and variables > Actions**: `VT_API_KEY` (VirusTotal), `ABUSEIPDB_API_KEY` (AbuseIPDB), `ABUSECH_AUTH_KEY` (abuse.ch). Without keys the bot still detects and reports, and marks enrichment as skipped.
