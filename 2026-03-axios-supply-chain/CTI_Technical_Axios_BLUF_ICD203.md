# CTI Technical Report — Axios npm Supply Chain Attack

**Author:** Daniel A.  
**Date:** April 2, 2026  
**Classification:** TLP: WHITE — Unrestricted distribution  
**Methodology:** BLUF + ICD 203 (Analytic Standards)  
**Affected versions:** `axios@1.14.1` / `axios@0.30.4`  
**GHSA:** `GHSA-fw8c-xr5c-95f9` / `MAL-2026-2306`  
**Attributed actor:** UNC1069 / NICKEL GLADSTONE (DPRK nexus — BlueNoroff) — Confidence: MODERATE

---

## 1. Bottom Line Up Front (BLUF)

> On March 31, 2026, UNC1069 compromised `axios@1.14.1` and `@0.30.4` by deploying a cross-platform RAT via the malicious dependency `plain-crypto-js`. The potential impact is critical given the scale (~400M weekly downloads). **Verify presence of `plain-crypto-js` in `node_modules`, block `sfrclak[.]com:8000`, revoke all credentials, and rebuild affected hosts from clean snapshots.**

> *Analytic note (ICD 203 4.3): This document explicitly distinguishes between observed facts, analytical inferences, and probability estimates. Confidence levels reflect source quality and convergence, not absolute certainty. Attribution to UNC1069 is based exclusively on OSINT from first-tier sources; no SIGINT/HUMINT confirmation available.*

---

## 2. Key Judgments (ICD 203 4.1)

| Key Judgment | Confidence | Analytical Basis |
|---|---|---|
| UNC1069 is **almost certainly** responsible for the axios compromise, operating under directive of the North Korean regime with primary financial motivation. | MODERATE | OSINT convergence: Google GTIG + Sophos CTU. C2 patterns and forensic artifacts consistent with documented historical activity. No SIGINT confirmation. |
| The attack was **almost certainly not** opportunistic. The 18h pre-staging, multi-layer obfuscation, and simultaneous targeting of two release branches indicate a planned operation with dedicated resources. | HIGH | Observable fact: verifiable timestamps in npm publication records. Intentionality inference supported by StepSecurity technical analysis. |
| Credentials exfiltrated during the exposure window will **probably** be weaponized in secondary attacks within the next 4–8 weeks. | MODERATE | Historical BlueNoroff pattern: stolen credentials reused in attacks against exchanges and wallets. Temporal estimate based on documented prior behavior. |
| The npm ecosystem has a structural weakness in its implicit maintainer account trust model that will **almost certainly** remain exploitable in the short term. | HIGH | Technical fact: npm publication model does not require OIDC provenance by default. Alternative hypothesis discarded: no npm Inc. hardening announced. |
| Environments using pinned lockfiles or `--ignore-scripts` policies were **almost certainly** not affected. | HIGH | Technical fact verified by StepSecurity and Wiz. Direct evidence of protected environments documented in post-incident analysis. |

> **Estimative language (ICD 203):** *almost certainly* ≥85% | *probably* 55–84% | *possibly* 25–54% | *unlikely* ≤24%

---

## 3. Attack Timeline

| Timestamp (UTC) | Event |
|---|---|
| Mar 30, 05:57 | `plain-crypto-js@4.2.0` published — clean staging version |
| Mar 30, 23:59 | `plain-crypto-js@4.2.1` published with embedded malicious payload |
| Mar 31, 00:21 | `axios@1.14.1` published from compromised account (`jasonsaayman`) |
| Mar 31, 00:45 | First detection in Sophos customer telemetry |
| Mar 31, 01:00 | `axios@0.30.4` published; widespread impact |
| Mar 31, 03:29 | Malicious versions removed from npm registry |
| Mar 31, ~13:09 | BleepingComputer publishes IOCs and possible BlueNoroff connection |
| Apr 01, 2026 | Google GTIG confirms attribution to UNC1069 (North Korean nexus) |

---

## 4. Kill Chain — MITRE ATT&CK

```
[1] Resource Dev.     [2] Initial Access    [3] Execution         [4] Defense Evasion
TA0042                TA0001                TA0002                TA0005
T1586.003             T1195.002             T1059.006             T1140 + T1070.004
Compromise Account    Supply Chain          postinstall hook      XOR+B64 / Self-delete
jasonsaayman npm      axios@1.14.1          node setup.js         Deletes setup.js
     │                     │                     │                     │
     └─────────────────────┴─────────────────────┴─────────────────────┘
                                                                         │
     ┌───────────────────────────────────────────────────────────────────┘
     │
[5] C2                [6] Persistence       [7] Credential Access / Exfil
TA0011                TA0003                TA0006 / TA0010
T1071.001             T1547 / T1543         T1552 + T1041
HTTP beacon           Boot Autostart        SSH keys, cloud tokens
sfrclak[.]com:8000    macOS/Win/Linux       Exfil over C2
60s interval          OS-specific           Continuous
```

---

## 5. TTP Map (MITRE ATT&CK)

| Tactic | Technique | Observation | KC |
|---|---|---|---|
| Resource Dev. TA0042 | T1586.003 Compromise Account | npm account `jasonsaayman` compromised. Long-lived classic token obtained. | 1 |
| Resource Dev. TA0042 | T1608.001 Stage Capabilities | `plain-crypto-js@4.2.0` published 18h in advance as legitimate staging package. | 1 |
| Initial Access TA0001 | T1195.002 Compromise SW Supply Chain | `axios@1.14.1` and `@0.30.4` published with injected malicious dependency. | 2 |
| Execution TA0002 | T1059.006 Command & Scripting (Node.js) | `setup.js` executed automatically via npm postinstall hook. | 3 |
| Defense Evasion TA0005 | T1140 Deobfuscate/Decode | XOR cipher (key `OrDeR_7077`) + reversed Base64 with padding substitution. | 4 |
| Defense Evasion TA0005 | T1070.004 File Deletion | Self-deletion of `setup.js`. Replacement of `package.json` with clean version. | 4 |
| C2 TA0011 | T1071.001 Application Layer Protocol (HTTP) | HTTP beacon to `sfrclak[.]com:8000` every 60 seconds. | 5 |
| C2 TA0011 | T1105 Ingress Tool Transfer | Downloads OS-specific second-stage payload from C2. | 5 |
| Persistence TA0003 | T1547 / T1543 Boot/Logon Autostart | macOS: LaunchAgent \| Win: `PROGRAMDATA/wt.exe` \| Linux: systemd/cron. | 6 |
| Cred. Access TA0006 | T1552 Unsecured Credentials | Exfiltration of SSH keys, cloud tokens, npm tokens, GitHub tokens, API keys. | 7 |
| Exfiltration TA0010 | T1041 Exfil over C2 Channel | Credentials exfiltrated through established C2 channel. | 7 |

---

## 6. Indicators of Compromise (IOCs)

| Type | Indicator | Context |
|---|---|---|
| npm package | `axios@1.14.1` / `axios@0.30.4` | Trojanized versions — REMOVE |
| Malicious dep. | `plain-crypto-js@4.2.1` | RAT dropper — postinstall hook |
| C2 domain | `sfrclak[.]com:8000` | Beacon every 60s — **BLOCK** |
| C2 IP | `142.11.206[.]73` | Second-stage server — **BLOCK** |
| sha1 hash | `2553649f232204966871cea80a5d0d6adc700ca` | `axios@1.14.1` |
| sha1 hash | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` | `axios@0.30.4` |
| Actor email | `ifstap@proton[.]me` | Email of compromised `jasonsaayman` account |
| Actor email | `nrwise@proton[.]me` | Publisher of `plain-crypto-js` |
| FS artifact | `node_modules/plain-crypto-js/` | Presence = dropper executed |
| Satellite pkg | `@shadanai/openclaw` / `@qqbrowser/openclaw-qbot` | Alternative distribution of same RAT |
| GHSA | `GHSA-fw8c-xr5c-95f9` / `MAL-2026-2306` | Official advisory |

> ⚠️ The presence of the `node_modules/plain-crypto-js/` directory is sufficient evidence of compromise regardless of `npm audit` results. The malware self-deleted — `npm audit` will return clean even on compromised systems.

---

## 7. Incident Response Playbook

| # | Action | Procedure | Deadline | Priority |
|---|---|---|---|---|
| 1 | Detect affected versions | `grep -rE "1\.14\.1\|0\.30\.4" package-lock.json` | Immediate | CRITICAL |
| 2 | Detect forensic artifact | `find . -type d -name 'plain-crypto-js'` | Immediate | CRITICAL |
| 3 | Block C2 | Deny: `sfrclak[.]com` / `142.11.206[.]73:8000` | < 30 min | CRITICAL |
| 4 | Revoke credentials | Revoke SSH keys, npm/GitHub tokens, cloud credentials. Do not rotate in-place — revoke and reissue. | < 2h | CRITICAL |
| 5 | Rebuild affected environments | Do not clean — rebuild from verified clean snapshot. | < 4h | HIGH |
| 6 | Downgrade axios | `npm install axios@1.14.0` | < 1h | HIGH |
| 7 | Clear npm cache | `npm cache clean --force` / `yarn cache clean` / `pnpm store prune` | < 1h | HIGH |
| 8 | Review CI/CD logs | Search for `npm install` on Mar 31, 2026 between 00:00–03:30 UTC | < 4h | HIGH |
| 9 | Enable `--ignore-scripts` | `npm config set ignore-scripts true` or `.npmrc: ignore-scripts=true` | Short term | MEDIUM |
| 10 | Migrate npm tokens | Revoke classic tokens. Issue granular tokens + mandatory 2FA. | Short term | MEDIUM |

---

## 8. Alternative Hypotheses (ICD 203 4.6)

| Hypothesis | Assessment | Rationale |
|---|---|---|
| H1: North Korean actor (UNC1069/BlueNoroff) | **MOST LIKELY** | Convergence of two independent first-tier sources (Google GTIG, Sophos CTU). C2 patterns and forensic artifacts consistent with documented history. |
| H2: State actor (different geographic nexus) | **UNLIKELY** | No primary analytical source points to another actor. No divergent TTPs contradict North Korean attribution. |
| H3: Financially motivated criminal actor (non-state) | **POSSIBLE** | Financial motivation is compatible. However, operational sophistication (18h staging, triple payload, self-destruction) exceeds typical opportunistic criminal profile. |
| H4: Malicious insider (maintainer voluntarily complicit) | **UNLIKELY** | Account email change to attacker-controlled Proton Mail indicates forced compromise, not voluntary action by the maintainer. |
| H5: TeamPCP (actor behind parallel npm/PyPI attacks) | **POSSIBLE** | TeamPCP conducted similar attacks in the same timeframe. Google GTIG explicitly confirms the axios incident is separate from the TeamPCP campaign. |

---

## 9. Source Characterization (ICD 203 4.4)

*All sources are publicly available OSINT.*

| Ref | Source | Type | Quality | Primary use |
|---|---|---|---|---|
| [1] | StepSecurity | OSINT — Vendor CTI | HIGH | Primary technical analysis, timeline, dropper mechanism |
| [2] | Google GTIG | OSINT — Vendor CTI | HIGH | UNC1069 attribution, actor context |
| [3] | Sophos CTU | OSINT — Vendor CTI | HIGH | NICKEL GLADSTONE attribution, detection telemetry |
| [4] | Wiz Blog | OSINT — Vendor CTI | HIGH | Prevalence statistics, cloud environment impact |
| [5] | Snyk | OSINT — Vendor CTI | HIGH | Deobfuscation analysis, IR guidance, infection mechanism |
| [6] | SANS ISC | OSINT — Analytics | HIGH | IOC hashes, emergency briefing |
| [7] | The Hacker News | OSINT — Specialist media | MED-HIGH | Detailed timeline, satellite packages |
| [8] | BleepingComputer | OSINT — Specialist media | MED-HIGH | Attribution coverage, Mandiant statements |
| [9] | Tenable | OSINT — Vendor CTI | HIGH | Remediation guide, scope assessment |
| [10] | Axios.com | OSINT — General media | MEDIUM | North Korean attribution confirmation |

---

*Report produced following BLUF + ICD 203 Analytic Standards methodology.*  
*TLP: WHITE — Unrestricted distribution.*
