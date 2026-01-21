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

```

## Basic Usage
```bash
python src/smartconsole_findings_generator.py -i "<SmartConsole_Export>.csv"

```
By default, the script generates an Excel file named:
```php-template
<INPUT_FILENAME>_STANDARDIZED.xlsx
```
Example:
```bash
python src/smartconsole_findings_generator.py -i "Policy_Export.csv"
```

---

### Optional Parameters
- Specify output file:
```bash
-o "Findings_Output.xlsx"
```
- Provide a control mapping file (STIG / SRG / CIS / NIST):
```bash
-m mappings/control_mapping.csv
```
- Adjust what qualifies as a “broad” subnet (default: broader than /24):
```bash
--broad-threshold 24
```
- Override embedded compliance standards text:
```bash
--standards "NIST SP 800-53 Rev. 5; DoDI 8500.01; DoDI 8510.01"
```

---

## Output Structure

The generated Excel workbook includes:

### Firewall Rules & Findings
- Standardized rule fields
- Automated risk flags
- Risk level classification
- Human-readable findings and remediation guidance
- Evidence summaries for audit traceability
- Analyst workflow fields:
  - `Analyst_Status`
  - `Risk_Final`
  - `Analyst_Notes`

### Summary Tabs
- Risk level distribution
- Rule action breakdown
- ANY usage summary
- Logging gap summary
- VPN-constrained rule summary

### Run Metadata
- Script version
- Execution timestamp
- Input file path
- Input file SHA-256 hash
- Broad subnet threshold
- Standards referenced
- Mapping file used (if applicable)

---

## Data Handling & Security
- This repository intentionally excludes real firewall exports and operational data
- Example inputs (if provided) are synthetic and sanitized
- Users are responsible for ensuring compliance with organizational data handling policies

---

## Limitations
- Analysis is based solely on exported configuration data
- Risk scoring is heuristic and intended to support, not replace, analyst judgment
- Compliance mappings may require customization for specific environments

---

## Disclaimer
This tool is provided for assessment and analysis purposes only.  
It does not replace formal security reviews, accreditation decisions, or authoritative compliance determinations.

All example outputs were generated from a personal homelab environment using synthetic firewall rules and do not represent any production or operational system.

---

## Documentation
For detailed usage instructions and workflow guidance, see [USAGE.md](USAGE.md).

## Example Output

The following screenshots demonstrate example outputs generated using sanitized test data.

<img src="docs/images/xlsx Findings.png" width="1500">

<img src="docs/images/xlsx NIST Mappings.png" width="700">

