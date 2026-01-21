# Firewall Assurance Automation

## Overview
Firewall Assurance Automation is a Python-based tool designed to analyze CSV exports from Check Point SmartConsole and automatically generate standardized firewall policy findings. The tool supports firewall assurance, compliance assessments, and risk reporting by converting raw policy data into structured, review-ready outputs.

This project emphasizes repeatability, traceability, and analyst oversight, aligning with enterprise and DoD-style assessment workflows.

---

## Key Capabilities
- Ingests Check Point SmartConsole CSV policy exports
- Normalizes rule data for consistent analysis
- Automatically flags common firewall policy risks:
  - Overly broad source or destination definitions
  - Broad network subnets
  - Unrestricted services (ANY)
  - Allowed traffic without logging
- Assigns explainable risk levels (High / Medium / Low)
- Generates analyst-ready findings and remediation guidance
- Maps findings to compliance references (STIG / SRG / CIS / NIST)
- Produces a single Excel workbook suitable for assessment and reporting use

---

## Intended Use
This tool is intended to assist with:
- Firewall Assurance Program (FAP) activities
- Configuration and policy reviews
- Risk identification and prioritization
- Compliance alignment and reporting support

The tool **does not** make live changes to firewall configurations and **does not** connect directly to firewall management systems.

All outputs should be reviewed and validated by a qualified analyst prior to inclusion in formal reports.

---

## Requirements
- Python 3.9+
- Python packages:
  - `pandas`
  - `openpyxl`

Install dependencies:
```bash
pip install -r requirements.txt
