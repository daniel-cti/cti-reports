# CTI Executive Report — Axios npm Supply Chain Attack

**Author:** Daniel A.
**Date:** April 2, 2026  
**Classification:** TLP: WHITE — Unrestricted distribution  
**Methodology:** BLUF + ICD 203 (Analytic Standards)  
**Audience:** CISO, CTO, CEO, Board of Directors  
**Exposure window:** Mar 31, 2026 · 00:21 UTC – 03:29 UTC (~2 hours)  
**Attributed actor:** UNC1069 / BlueNoroff (DPRK nexus) — Confidence: MODERATE  
**For technical analysis:** See `CTI_Technical_Axios_BLUF_ICD203.md`

---

## 1. Bottom Line Up Front (BLUF)

> A North Korea-linked threat actor compromised axios, the most downloaded JavaScript library in the world (~400M weekly downloads), and installed malware on any development environment or CI/CD pipeline that updated the library during a two-hour window on March 31, 2026. The malware stole credentials (cloud keys, tokens, SSH keys) and opened persistent remote access. **Any organization that ran `npm install` during that period should assume exposure. Required action: environment audit, credential rotation, and assessment of notification obligations to affected parties.**

> *Methodological note (ICD 203): Judgments include explicit confidence levels (HIGH / MODERATE). Geopolitical attribution is based on OSINT analysis from Google GTIG and Sophos CTU; confidence level MODERATE (not confirmed by classified government sources).*

---

## 2. Key Judgments (ICD 203 4.1)

| Key Judgment | Confidence | Analytical Basis |
|---|---|---|
| The attack was a planned operation, **almost certainly not** opportunistic. The actor pre-staged infrastructure 18 hours before the attack. | HIGH | Direct, verifiable technical evidence in npm publication records. |
| Any system that ran `npm install` between 00:21 and 03:29 UTC on Mar 31, 2026 should be considered compromised **until proven otherwise**. | HIGH | The malware executes and exfiltrates within seconds. Absence of forensic evidence does not imply absence of compromise — the malware self-deleted. |
| The actor will **probably** use stolen credentials for secondary financial attacks in the coming weeks. | MODERATE | Documented historical pattern of the group. No secondary activity observable at the time of this report. |
| Organizations that distribute Node.js software **almost certainly** have a secondary exposure surface extending to their clients or end users. | HIGH | Verifiable technical fact: if a compromised build was distributed during the exposure window, the vector may have propagated downstream. |

> **Estimative language (ICD 203):** HIGH ≥85% confidence | MODERATE 55–84% | LOW ≤54%

---

## 3. What Happened — Context for Leadership

axios is an open-source software library that acts as an intermediary between JavaScript applications and internet servers. It is present in virtually every modern Node.js project, including web applications, backend services, and automated deployment pipelines.

The attack worked as follows: a threat actor stole the credentials of the library's principal maintainer and published a modified version containing a hidden malicious program. Any system that downloaded that version automatically installed the malware alongside the legitimate library.

**Analogy:** this is equivalent to someone compromising the credentials of the person responsible for a critical Windows update and distributing that update with embedded malware through Windows Update for two hours.

The malware required no action from the developer beyond running `npm install` — a routine command in any development environment or CI/CD pipeline. This makes it particularly relevant for organizations with automated dependency update processes.

---

## 4. Attack Chain

```
Account           Malicious          Execution         Evasion
compromise    →   axios publish  →   postinstall   →   self-destruction
(−18h)            (00:21 UTC)        hook              of malware
                                     (+2s)             (+5s)
                                          │
                                          ▼
                                     C2 beacon    →   Persistence   →  Exfiltration
                                     sfrclak.com      OS-specific       credentials
                                     (60s interval)   (immediate)       (continuous)
```

*Phases mapped to MITRE ATT&CK. Full detail in technical report.*

---

## 5. Impact Assessment

| Dimension | Impact | Risk | Timeline |
|---|---|---|---|
| Credential theft | SSH keys, cloud tokens (AWS/GCP/Azure), GitHub tokens, API keys exfiltrated within seconds of installation. | CRITICAL | Immediate |
| Persistent remote access | RAT installed with command execution capability and 60s beaconing. Attacker maintains access while the RAT is active. | CRITICAL | Immediate |
| CI/CD pipeline compromise | Any pipeline that ran `npm install` during the window exposed production secrets and deployment credentials. | HIGH | Immediate |
| Downstream propagation | Organizations distributing Node.js software may have propagated the vector to clients or users if compromised builds were delivered during the window. | HIGH | Short term |
| Extortion / ransomware risk | Stolen credentials can be monetized directly or sold. Mandiant estimates hundreds of thousands of compromised credentials in the ecosystem. | HIGH | Weeks |
| Reputation and compliance | Regulatory notification (GDPR Art. 33/34) may be required if exfiltration of personal data in affected environments is confirmed. | MEDIUM | 72h regulatory |

---

## 6. Is My Organization Exposed?

The exposure criteria are binary and verifiable within minutes:

| Question | If YES... | If NO... |
|---|---|---|
| Does the organization use Node.js with npm? | Continue verification. | Direct exposure very unlikely. |
| Did any environment run `npm install` on Mar 31 between 00:21–03:29 UTC? | Assume exposure. Initiate incident response. | Direct exposure very unlikely. Audit as precaution. |
| Do environments use pinned lockfiles (`npm ci`)? | Likely protected if pinned version predates `1.14.1`. | Higher risk of having installed the compromised version. |
| Do CI/CD pipelines use `npm install` without `--ignore-scripts`? | Elevated risk if executed during the affected window. | Risk significantly reduced. |
| Does the organization distribute Node.js software to third parties? | Assess whether builds from the exposure window were delivered. Consider proactive notification. | No downstream propagation risk. |

---

## 7. Recommended Actions

| Action | Description | Suggested Owner | Deadline |
|---|---|---|---|
| Exposure audit | Verify whether any environment installed `axios@1.14.1` or `@0.30.4` during the exposure window. | Security team / DevOps | < 2h |
| Credential rotation | Revoke and reissue all tokens and keys in affected environments. Do not rotate in-place — revoke and reissue. | Security / Cloud Ops | < 4h |
| Environment rebuild | Rebuild affected machines or runners from clean image. Do not clean — rebuild. | IT Ops / DevOps | < 4h |
| Downstream assessment | If the organization distributes software, determine whether builds from the window were delivered to clients. | Management / Legal | < 24h |
| Structural hardening | Implement hash-verified lockfiles, private npm registry, and mandatory 2FA on maintainer accounts. | CTO / DevOps Lead | < 2 weeks |

---

## 8. Strategic Context

This incident is not isolated. During the same timeframe, another actor (TeamPCP/UNC6780) attacked Python packages and widely used security tools (Trivy, Checkmarx, LiteLLM). Mandiant's CTO has estimated that credentials stolen in these combined attacks could amount to hundreds of thousands currently circulating in criminal markets.

The pattern of North Korean actors is consistent: stealing credentials and digital assets to fund the regime's weapons program. The sectors most frequently targeted in subsequent campaigns are cryptocurrency exchanges, financial platforms, and technology companies with access to high-value assets.

**Strategic implication:** software supply chain has consolidated as the preferred attack vector for state actors. A third-party dependency can become the entry point to critical production systems — with no traditional perimeter control detecting it. The structural response requires investment in dependency governance, pipeline security, and behavioral monitoring in build environments.

---

## 9. Methodological Note (ICD 203)

This report was produced following ICD 203 (Analytic Standards):

- Standardized estimative language with explicit probabilities in each key judgment.
- Clear separation between observed facts, analytical inferences, and forward-looking estimates.
- Confidence levels based on source quality and convergence, not subjective certainty.
- Alternative hypotheses documented in the technical report.
- All sources are publicly available OSINT; no classified government sources used.

For the complete technical analysis (MITRE ATT&CK TTPs, IOCs, IR playbook, alternative hypotheses): see `CTI_Technical_Axios_BLUF_ICD203.md`.

---

*Report produced following BLUF + ICD 203 Analytic Standards methodology.*  
*TLP: WHITE — Unrestricted distribution.*
