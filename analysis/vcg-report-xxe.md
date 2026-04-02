# VCG Scan Report — XXE Lessons

**Prompt Used:**
```
Read ./analysis/vcg-xxe.xml and convert the VCG scan results into a clean markdown report at ./analysis/vcg-report-xxe.md.
```

**Source:** `vsg-xxe.xml`
**Scan directory:** `WebGoat\src\main\java\org\owasp\webgoat\lessons\xxe`
**Language:** Java
**Date exported:** 2026-03-31

---

## Summary

| Metric | Value |
|--------|-------|
| Total findings | 12 |
| Standard | 3 |
| Potential Issue | 9 |

### Severity Breakdown

| Severity | Priority | Count |
|----------|----------|-------|
| Standard | 4 | 3 |
| Potential Issue | 7 | 9 |

---

## Findings

---

### Findings 1–3: java.io.File

**Severity:** Standard | **Priority:** 4

This functionality acts as an entry point for external data and the code should be manually checked to ensure the data obtained is correctly validated and/or sanitised. Additionally, careful checks/sanitisation should be applied in any situation where the user may be able to control or affect the filename.

| # | File | Line | Code |
|---|------|------|------|
| 1 | `BlindSendFileAssignment.java` | 14 | `import java.io.File;` |
| 2 | `Ping.java` | 7 | `import java.io.File;` |
| 3 | `Ping.java` | 8 | `import java.io.FileNotFoundException;` |

> **Note — Finding 3:** The `java.io.File` rule fired on the `import java.io.FileNotFoundException` line. This appears to be the same scanner quirk observed in the path traversal scan, where the `java.io.File` pattern matches against import statements for other `java.io` types.

---

### Findings 4–12: Public Class Not Declared as Final

**Severity:** Potential Issue | **Priority:** 7

The class is not declared as final as per OWASP recommendations. It is considered best practice to make classes final where possible and practical (i.e. it has no classes which inherit from it). Non-final classes can allow an attacker to extend a class in a malicious manner. Manually inspect the code to determine whether or not it is practical to make this class final.

| # | File | Line | Code |
|---|------|------|------|
| 4 | `BlindSendFileAssignment.java` | 41 | `public class BlindSendFileAssignment implements AssignmentEndpoint, Initializable {` |
| 5 | `Comment.java` | 22 | `public class Comment {` |
| 6 | `CommentsCache.java` | 25 | `public class CommentsCache {` |
| 7 | `CommentsEndpoint.java` | 20 | `public class CommentsEndpoint {` |
| 8 | `ContentTypeAssignment.java` | 32 | `public class ContentTypeAssignment implements AssignmentEndpoint {` |
| 9 | `Ping.java` | 19 | `public class Ping {` |
| 10 | `SimpleXXE.java` | 35 | `public class SimpleXXE implements AssignmentEndpoint {` |
| 11 | `User.java` | 10 | `public class User {` |
| 12 | `XXE.java` | 12 | `public class XXE extends Lesson {` |
