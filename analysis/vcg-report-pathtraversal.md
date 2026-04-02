# VCG Scan Report — Path Traversal Lessons

**Prompt Used:**
```
Read ./analysis/vcg-pathtraversal.xml and convert the VCG scan results into a clean markdown report at ./analysis/vcg-report-pathtraversal.md.
```

**Source:** `vsg-pathtraversal.xml`
**Scan directory:** `WebGoat\src\main\java\org\owasp\webgoat\lessons\pathtraversal`
**Language:** Java
**Date exported:** 2026-03-31

---

## Summary

| Metric | Value |
|--------|-------|
| Total findings | 22 |
| Medium | 2 |
| Standard | 10 |
| Low | 3 |
| Potential Issue | 7 |

### Severity Breakdown

| Severity | Priority | Count |
|----------|----------|-------|
| Medium | 3 | 2 |
| Standard | 4 | 10 |
| Low | 5 | 3 |
| Potential Issue | 7 | 7 |

---

## Findings

---

### Findings 1–2: Failure To Release Resources In All Cases

**Severity:** Medium | **Priority:** 3

| # | File | Line | Description |
|---|------|------|-------------|
| 1 | `ProfileUploadRetrieval.java` | 64 | There appears to be no 'finally' block to release resources if an exception occurs, potentially resulting in DoS conditions from excessive resource consumption. |
| 2 | `ProfileUploadRetrieval.java` | 64 | There appears to be no release of resources in the 'finally' block, potentially resulting in DoS conditions from excessive resource consumption. |

> **Note:** Both findings point to line 64 with no associated code line in the XML. They represent two distinct scanner rules about resource release — one for the absence of a `finally` block, and one for the absence of a resource release within it.

---

### Findings 3–12: Standard — File and Stream Entry Points

**Severity:** Standard | **Priority:** 4

Each of the following flags a file or stream API as an unvalidated external data entry point. The shared description is: *This functionality/function acts as an entry point for external data and the code should be manually checked to ensure the data obtained is correctly validated and/or sanitised. Additionally, careful checks/sanitisation should be applied in any situation where the user may be able to control or affect the filename.*

| # | Rule | File | Line | Code |
|---|------|------|------|------|
| 3 | `java.io.File` | `ProfileUploadBase.java` | 11 | `import java.io.File;` |
| 4 | `FileInputStream` | `ProfileUploadBase.java` | 12 | `import java.io.FileInputStream;` |
| 5 | `java.io.File` | `ProfileUploadBase.java` | 12 | `import java.io.FileInputStream;` |
| 6 | `FileInputStream` | `ProfileUploadBase.java` | 112 | `try (var inputStream = new FileInputStream(profileDirectoryFiles[0])) {` |
| 7 | `getResourceAsStream` | `ProfileUploadBase.java` | 126 | `var inputStream = getClass().getResourceAsStream("/images/account.png");` |
| 8 | `java.io.File` | `ProfileUploadRetrieval.java` | 12 | `import java.io.File;` |
| 9 | `java.io.File` | `ProfileUploadRetrieval.java` | 13 | `import java.io.FileOutputStream;` |
| 10 | `java.io.FileOutputStream` | `ProfileUploadRetrieval.java` | 13 | `import java.io.FileOutputStream;` |
| 11 | `getParameter` | `ProfileUploadRetrieval.java` | 99 | `var id = request.getParameter("id");` |
| 12 | `java.io.File` | `ProfileZipSlip.java` | 12 | `import java.io.File;` |

> **Note — Findings 5 and 9:** The `java.io.File` rule fired on the `import java.io.FileInputStream` (line 12) and `import java.io.FileOutputStream` (line 13) lines respectively, in addition to a separate, correctly matched rule for those same imports. This appears to be a scanner quirk where the `java.io.File` pattern matches against those import statements.

---

### Findings 13–15: Operation on Primitive Data Type

**Severity:** Low | **Priority:** 5

The code appears to be carrying out a mathematical operation on a primitive data type. In some circumstances this can result in an overflow and unexpected behaviour. Check the code manually to determine the risk.

| # | File | Line | Code |
|---|------|------|------|
| 13 | `ProfileUploadRetrieval.java` | 60 | `for (int i = 1; i <= 10; i++) {` |
| 14 | `ProfileUploadRetrieval.java` | 62 | `new ClassPathResource("lessons/pathtraversal/images/cats/" + i + ".jpg")` |
| 15 | `ProfileUploadRetrieval.java` | 64 | `FileCopyUtils.copy(is, new FileOutputStream(new File(catPicturesDirectory, i + ".jpg")));` |

---

### Findings 16–22: Public Class Not Declared as Final

**Severity:** Potential Issue | **Priority:** 7

The class is not declared as final as per OWASP recommendations. It is considered best practice to make classes final where possible and practical (i.e. it has no classes which inherit from it). Non-final classes can allow an attacker to extend a class in a malicious manner. Manually inspect the code to determine whether or not it is practical to make this class final.

| # | File | Line | Code |
|---|------|------|------|
| 16 | `PathTraversal.java` | 12 | `public class PathTraversal extends Lesson {` |
| 17 | `ProfileUpload.java` | 28 | `public class ProfileUpload extends ProfileUploadBase {` |
| 18 | `ProfileUploadBase.java` | 32 | `public class ProfileUploadBase implements AssignmentEndpoint {` |
| 19 | `ProfileUploadFix.java` | 28 | `public class ProfileUploadFix extends ProfileUploadBase {` |
| 20 | `ProfileUploadRemoveUserInput.java` | 26 | `public class ProfileUploadRemoveUserInput extends ProfileUploadBase {` |
| 21 | `ProfileUploadRetrieval.java` | 50 | `public class ProfileUploadRetrieval implements AssignmentEndpoint {` |
| 22 | `ProfileZipSlip.java` | 45 | `public class ProfileZipSlip extends ProfileUploadBase {` |
