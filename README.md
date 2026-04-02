# WebGoat Security Review Comparison (VCG vs Claude Code)

Comparative security analysis of OWASP WebGoat using Visual Code Grepper (VCG) and Claude Code.
The target application used for analysis is OWASP WebGoat: https://github.com/WebGoat/WebGoat

---

## Overview

This project evaluates how two different approaches to code analysis perform when identifying security vulnerabilities:

- **Visual Code Grepper (VCG)** — traditional static analysis tool  
- **Claude Code** — AI-assisted code review workflow  

The goal is not just to find vulnerabilities, but to compare:
- **Detection quality**
- **False positive rates**
- **Clarity and usefulness of output**

This is not a raw scan dump. Findings are curated and analyzed for **realistic exploitability and signal quality**.

---

## Objectives

- Identify security vulnerabilities in a Java-based web application  
- Compare traditional SAST (VCG) vs AI-assisted analysis (Claude Code)  
- Evaluate **false positives vs high-confidence findings**  
- Produce structured, readable security reports  
- Demonstrate practical use of AI in a security workflow  

---

## Methodology

### 1. Scoped Folder-Based Analysis
- Selected specific vulnerable modules within WebGoat:
  - `sqlinjection`
  - `xxe`
  - `ssrf`
  - `jwt`
  - `deserialization`
  - `pathtraversal`
- Each folder was analyzed independently to keep findings focused and comparable  

---

### 2. VCG Scan (Baseline)

- Ran Visual Code Grepper scans on each target folder  
- Exported results as **XML**  
- Used Claude Code to:
  - Parse XML output  
  - Convert findings into structured markdown reports  

This step improved readability and made VCG output easier to compare directly with Claude findings.

---

### 3. Claude Code Analysis

- Used a customized **folder-based security review workflow**  
- Claude recursively analyzed target folders using file system tools  
- Focused on:
  - High-confidence vulnerabilities  
  - Realistic exploit paths  
  - Reduced noise vs traditional scan output  

---

### 4. Normalization of Output

To enable comparison:
- VCG XML → converted to markdown (`vcg-report.md`)
- Claude output → written directly as markdown (`claude-report-#.md`)

Both outputs were aligned to a consistent structure:
- File + line reference  
- Severity (if available)  
- Description  
- Exploit scenario (Claude only)  

---

### 5. Manual Validation

- Reviewed findings from both tools  
- Identified:
  - True positives  
  - False positives  
- Compared:
  - Coverage
  - Accuracy
  - Practical usefulness  

---

## Reproducing the Analysis

1. Clone the WebGoat repository:
   https://github.com/WebGoat/WebGoat

2. Run Visual Code Grepper (VCG) against selected modules:
   - sqlinjection
   - xxe
   - ssrf
   - jwt
   - deserialization
   - pathtraversal

3. Export results as XML

4. Use Claude Code to:
   - Convert XML output to markdown
   - Perform contextual security analysis

5. Compare results using the structure in `/analysis`

---

## Key Insights

This project highlights the differences between traditional static analysis and AI-assisted code review in a practical setting.

- **VCG** tends to:
  - Produce a higher volume of findings  
  - Include more false positives  
  - Require manual filtering to identify meaningful issues  

- **Claude Code** tends to:
  - Produce fewer, more focused findings  
  - Emphasize higher-confidence vulnerabilities  
  - Provide more contextual explanations and realistic exploit scenarios  

Overall, the comparison highlights how much filtering out noise matters in security analysis. While traditional tools offer broad coverage, AI-assisted approaches can improve the usability and clarity of results. However, both approaches still require human validation to determine true exploitability and risk.

---

## Tools Used

- Visual Code Grepper (VCG)  
- Claude Code (analysis + XML → markdown conversion)  
- VS Code  

---

## Repository Structure

- `/analysis`
  - `vcg-###.xml` → Raw VCG scan output  
  - `vcg-report-###.md` → Converted VCG findings (via Claude Code)  
  - `claude-report-#.md` → Claude-generated reports  
  - `final-report.md` → Comparison + conclusions  
- `README.md`

> WebGoat source code is not included in this repository. See: https://github.com/WebGoat/WebGoat

---

## Key Findings

See: `/analysis/final-report.md`

Includes:
- Side-by-side comparison of VCG vs Claude findings  
- False positive analysis  
- High-confidence vulnerabilities across modules  

---

## Attribution

This project is based on OWASP WebGoat:  
https://github.com/WebGoat/WebGoat  

Copyright (c) 2002–present Bruce Mayhew  
Copyright (c) 2014–present Nanne Baars  

Licensed under the GNU General Public License v2.0 or later (GPL-2.0-or-later).

---

## Additional Notes

- Claude Code was used **as a workflow tool**, not just for analysis:
  - Converting VCG XML output into readable markdown  
  - Structuring findings for comparison  
- Custom prompts were used to control:
  - Scope (folder-based scanning)  
  - Output format  
  - False positive filtering  

---

## Disclaimer

WebGoat is an intentionally vulnerable application designed for educational purposes.  

Do not deploy this code in a production environment.