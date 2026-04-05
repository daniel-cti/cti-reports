# Axios npm Supply Chain Attack (March 2026)

**Date:** March 31, 2026  
**Author:** `Daniel A`  
**TLP:** WHITE — Unrestricted distribution  

---

## Summary

On March 31, 2026, a North Korea-linked threat actor (UNC1069 / BlueNoroff) compromised the npm account of the principal axios maintainer and published two malicious versions (`1.14.1` and `0.30.4`) that deployed a cross-platform RAT during dependency installation.

- **Exposure window:** 00:21 – 03:29 UTC (~2 hours)
- **Vector:** malicious dependency `plain-crypto-js@4.2.1` with `postinstall` hook
- **Capabilities:** credential exfiltration + persistent remote access (macOS, Windows, Linux)
- **C2:** `sfrclak[.]com:8000` / `142.11.206[.]73`
- **Safe versions:** `axios@1.14.0` / `axios@0.30.3`
- **GHSA:** `GHSA-fw8c-xr5c-95f9` / `MAL-2026-2306`

---

## Reports

| File | Audience | Description |
|---|---|---|
| [`CTI_Technical_Axios_BLUF_ICD203.md`](./CTI_Technical_Axios_BLUF_ICD203.md) | CTI Analysts / SOC | TTPs, IOCs, kill chain, IR playbook, alternative hypotheses |
| [`CTI_Executive_Axios_BLUF_ICD203_WHITE.md`](./CTI_Executive_Axios_BLUF_ICD203_WHITE.md) | CISO / Leadership | Business impact, required decisions, strategic context |

---

## Sources

| Ref | Source | URL |
|---|---|---|
| [1] | StepSecurity | https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan |
| [2] | Google GTIG | https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package |
| [3] | Sophos CTU | https://www.sophos.com/en-us/blog/axios-npm-package-compromised-to-deploy-malware |
| [4] | Wiz | https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack |
| [5] | Snyk | https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/ |
| [6] | SANS ISC | https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan |
| [7] | The Hacker News | https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html |
| [8] | BleepingComputer | https://www.bleepingcomputer.com/news/security/hackers-compromise-axios-npm-package-to-drop-cross-platform-malware/ |
| [9] | Tenable | https://www.tenable.com/blog/supply-chain-attack-on-axios-npm-package-scope-impact-and-remediations |
