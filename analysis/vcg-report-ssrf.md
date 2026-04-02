# VCG Scan Report — SSRF Lessons

**Prompt Used:**
```
Read ./analysis/vcg-ssrf.xml and convert the VCG scan results into a clean markdown report at ./analysis/vcg-report-ssrf.md.
```

**Source:** `vsg-ssrf.xml`
**Scan directory:** `WebGoat\src\main\java\org\owasp\webgoat\lessons\ssrf`
**Language:** Java
**Date exported:** 2026-03-31

---

## Summary

| Metric | Value |
|--------|-------|
| Total findings | 3 |
| Potential Issue | 3 |

### Severity Breakdown

| Severity | Priority | Count |
|----------|----------|-------|
| Potential Issue | 7 | 3 |

---

## Findings

---

### Findings 1–3: Public Class Not Declared as Final

**Severity:** Potential Issue | **Priority:** 7

The class is not declared as final as per OWASP recommendations. It is considered best practice to make classes final where possible and practical (i.e. it has no classes which inherit from it). Non-final classes can allow an attacker to extend a class in a malicious manner. Manually inspect the code to determine whether or not it is practical to make this class final.

| # | File | Line | Code |
|---|------|------|------|
| 1 | `SSRF.java` | 13 | `public class SSRF extends Lesson {` |
| 2 | `SSRFTask1.java` | 20 | `public class SSRFTask1 implements AssignmentEndpoint {` |
| 3 | `SSRFTask2.java` | 25 | `public class SSRFTask2 implements AssignmentEndpoint {` |
