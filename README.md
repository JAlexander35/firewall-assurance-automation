# SmartConsole Findings Generator

## Overview
SmartConsole Findings Generator is a Python-based automation tool designed to analyze CSV exports from Check Point SmartConsole and produce structured firewall policy findings. The tool supports firewall assurance, compliance assessments, and risk reporting by converting raw policy data into actionable findings aligned with assessment workflows.

This project is intended for use in controlled enterprise or government environments where auditability, traceability, and consistency are critical.

---

## Key Features
- Parses Check Point SmartConsole CSV exports
- Identifies potentially risky or non-compliant firewall rules
- Classifies findings by risk level (High / Medium / Low)
- Generates structured outputs suitable for assessment reports
- Supports repeatable and auditable analysis workflows

---

## Intended Use
This tool is designed to assist with:
- Firewall Assurance Program (FAP) activities
- Security control assessments
- Configuration reviews and change validation
- Compliance alignment and reporting support

It does **not** make live changes to firewall configurations and does **not** interface directly with management or enforcement planes.

---

## Input
- CSV exports generated from Check Point SmartConsole  
- Exports should represent firewall policy rules or related configuration data

> **Note:** Sample inputs included in this repository (if any) are sanitized and contain no real network, customer, or system data.

---

## Output
Depending on configuration, the tool may produce:
- Structured findings (CSV, JSON, or text)
- Risk categorizations
- Data suitable for integration into formal assessment or reporting templates

Generated outputs should be reviewed by qualified personnel before inclusion in official reports.

---

## Requirements
- Python 3.x
- Required Python packages listed in `requirements.txt`

Install dependencies:
```bash
pip install -r requirements.txt
