# Compliance & Reporting API

Reference for Wazuh compliance checking and security reporting tools.

## Overview

- **Compliance Assessment**: SCA-based evaluation with framework-aware filtering (PCI-DSS, HIPAA, SOX, GDPR, NIST, ISO27001)
- **ISO 27001:2022**: dedicated tooling mapping Annex A controls to live Wazuh data
- **Security Reporting**: reports differentiated by type with alert summaries, vulnerability counts, top threats, and recommendations

---

## run_compliance_check

Validate against a compliance framework. Accepted `framework` values: `PCI-DSS`, `HIPAA`, `SOX`, `GDPR`, `NIST`, `ISO27001`.

See [Security Analysis API — run_compliance_check](security-analysis.md#run_compliance_check) for parameters and response shape.

---

## generate_security_report

See [Security Analysis API — generate_security_report](security-analysis.md#generate_security_report).

---

## ISO 27001:2022 tools

Five tools assess ISO 27001:2022 posture using live Wazuh data. Controls are mapped to the appropriate Wazuh source (SCA/CIS benchmarks, the vulnerability Indexer, alert rule groups, agent data) via an internal Annex A control map.

| Tool | Purpose |
|------|---------|
| `get_iso27001_dashboard` | Overall posture — scores per Annex A domain (A.5/A.6/A.7/A.8), failing controls, vulnerability summary |
| `get_iso27001_control_detail` | Drill into a specific control (e.g. `A.8.8`) and return the live Wazuh evidence behind its score |
| `get_iso27001_gap_analysis` | Prioritized gap list (critical/high/medium) with remediation hints |
| `get_iso27001_alerts` | Recent alerts mapped to ISO 27001 control domains |
| `get_sca_policy_checks` | Check-level SCA detail: pass/fail per check, rationale, and remediation |

**Control IDs.** `get_iso27001_control_detail` accepts a domain (`A.5`, `A.6`, `A.7`, `A.8`) or a specific control. Mapped controls include: `A.5.26`, `A.6.3`, `A.8.1`, `A.8.2`, `A.8.4`, `A.8.5`, `A.8.7`, `A.8.8`, `A.8.9`, `A.8.12`, `A.8.15`, `A.8.16`, `A.8.20`, `A.8.22`. An unknown control returns a validation error.

### Guided prompt

`iso27001_assessment` — a conversational walkthrough (dashboard overview → domain drill-down → gap analysis → recommendations). Arguments: `scope` (`full` | `technological` | `specific_control`), `control_id`, `agent_id`.

> ISO 27001 tooling contributed by [@andrzej-piotrowski-pl](https://github.com/andrzej-piotrowski-pl) (#74).
