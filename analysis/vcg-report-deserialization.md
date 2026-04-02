# VCG Scan Report — Deserialization Lessons

**Prompt Used:**
```
Read ./analysis/vcg-deserialization.xml and convert the VCG scan results into a clean markdown report at ./analysis/vcg-report-deserialization.md.
```

**Source:** `vsg-deserialization.xml`
**Scan directory:** `WebGoat\src\main\java\org\owasp\webgoat\lessons\deserialization`
**Language:** Java
**Date exported:** 2026-03-31

---

## Summary

| Metric | Value |
|--------|-------|
| Total findings | 11 |
| Standard | 5 |
| Low | 3 |
| Potential Issue | 3 |

### Severity Breakdown

| Severity | Priority | Count |
|----------|----------|-------|
| Standard | 4 | 5 |
| Low | 5 | 3 |
| Potential Issue | 7 | 3 |

---

## Findings

---

### Findings 1–5: ObjectInputStream

**Severity:** Standard | **Priority:** 4

This function acts as an entry point for external data and the code should be manually checked to ensure the data obtained is correctly validated and/or sanitised. Additionally, careful checks/sanitisation should be applied in any situation where the user may be able to control or affect the filename.

| # | File | Line | Code |
|---|------|------|------|
| 1 | `InsecureDeserializationTask.java` | 13 | `import java.io.ObjectInputStream;` |
| 2 | `InsecureDeserializationTask.java` | 42 | `try (ObjectInputStream ois =` |
| 3 | `InsecureDeserializationTask.java` | 43 | `new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(b64token)))) {` |
| 4 | `SerializationHelper.java` | 11 | `import java.io.ObjectInputStream;` |
| 5 | `SerializationHelper.java` | 22 | `ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));` |

---

### Findings 6–8: Operation on Primitive Data Type

**Severity:** Low | **Priority:** 5

The code appears to be carrying out a mathematical operation on a primitive data type. In some circumstances this can result in an overflow and unexpected behaviour. Check the code manually to determine the risk.

| # | File | Line | Code |
|---|------|------|------|
| 6 | `SerializationHelper.java` | 48 | `for (int j = 0; j < bytes.length; j++) {` |
| 7 | `SerializationHelper.java` | 50 | `hexChars[j * 2] = hexArray[v >>> 4];` |
| 8 | `SerializationHelper.java` | 51 | `hexChars[j * 2 + 1] = hexArray[v & 0x0F];` |

---

### Findings 9–11: Public Class Not Declared as Final

**Severity:** Potential Issue | **Priority:** 7

The class is not declared as final as per OWASP recommendations. It is considered best practice to make classes final where possible and practical (i.e. it has no classes which inherit from it). Non-final classes can allow an attacker to extend a class in a malicious manner. Manually inspect the code to determine whether or not it is practical to make this class final.

| # | File | Line | Code |
|---|------|------|------|
| 9 | `InsecureDeserialization.java` | 13 | `public class InsecureDeserialization extends Lesson {` |
| 10 | `InsecureDeserializationTask.java` | 30 | `public class InsecureDeserializationTask implements AssignmentEndpoint {` |
| 11 | `SerializationHelper.java` | 16 | `public class SerializationHelper {` |
