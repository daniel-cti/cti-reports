# CTI Reports

**Author:** `Daniel A`

Repository of Cyber Threat Intelligence (CTI) reports produced following **BLUF + ICD 203 (Analytic Standards)** methodology.

Each incident includes a technical report (CTI analysts / SOC) and an executive report (CISO / leadership).

---

## Index

| Date | Incident | Actor | Type | Technical | Executive | TLP |
|---|---|---|---|---|---|---|
| 2026-03-31 | [Axios npm Supply Chain Attack](./2026-03-axios-supply-chain/) | UNC1069 / BlueNoroff (DPRK) | Supply Chain | [📄](./2026-03-axios-supply-chain/CTI_Technical_Axios_BLUF_ICD203.md) | [📄](./2026-03-axios-supply-chain/CTI_Executive_Axios_BLUF_ICD203_WHITE.md) | WHITE |

---

## Methodology

### BLUF (Bottom Line Up Front)
Every report opens with three mandatory answers before any analysis:
1. **What happened?**
2. **What does it mean?**
3. **What needs to be done right now?**

### ICD 203 (Analytic Standards)
Intelligence Community Directive 203 establishes analytic standards for finished intelligence. Applied here to CTI:

- **Calibrated estimative language** — probabilities expressed with standardized terms:

| Term | Probability |
|---|---|
| Almost certainly | ≥85% |
| Probably | 55–84% |
| Possibly | 25–54% |
| Unlikely | ≤24% |

- **Confidence levels** — HIGH / MODERATE / LOW based on source quality and convergence, not subjective certainty.
- **Alternative hypotheses** — documented and assessed in every report (ICD 203 4.6).
- **Source characterization** — type, quality, and limitations of every source (ICD 203 4.4).
- **Explicit separation** between observed facts, analytical inferences, and forward-looking estimates.

---

## TLP

Reports follow the [Traffic Light Protocol (TLP)](https://www.first.org/tlp/):

| Level | Color | Distribution |
|---|---|---|
| WHITE | 🟢 | No restrictions. Free distribution. |
| GREEN | 🟢 | Cybersecurity community. Do not publish outside the sector. |
| AMBER | 🟠 | Organization and affected clients under non-redistribution agreement. |
| AMBER+STRICT | 🟠 | Internal organization only. Do not share with clients. |
| RED | 🔴 | Named recipients only. Do not redistribute. |

Technical reports are generally **WHITE** (TTP/IOC analysis from public sources).  
Executive reports are generally **WHITE** when generic, **AMBER** when they contain internal exposure assessment.

---

## Repository Structure

```
YYYY-MM-incident-name/
├── README.md                         ← incident context, sources, TLP
├── CTI_Technical_*_BLUF_ICD203.md   ← TTPs, IOCs, kill chain, IR playbook
└── CTI_Executive_*_BLUF_ICD203.md   ← impact, decisions, strategic context
```

---

## Disclaimer

This repository contains threat intelligence analysis for informational and awareness purposes. Attribution to threat actors is based exclusively on publicly available OSINT sources and should be interpreted with the confidence level indicated in each judgment. No classified information has been used.
