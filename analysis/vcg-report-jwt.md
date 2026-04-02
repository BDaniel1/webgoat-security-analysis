# VCG Scan Report — JWT Lessons

**Prompt Used:**
```
Read ./analysis/vcg-jwt.xml and convert the VCG scan results into a clean markdown report at ./analysis/vcg-report-jwt.md.
```

**Source:** `vsg-jwt.xml`
**Scan directory:** `WebGoat\src\main\java\org\owasp\webgoat\lessons\jwt`
**Language:** Java
**Date exported:** 2026-03-31

---

## Summary

| Metric | Value |
|--------|-------|
| Total findings | 17 |
| High | 1 |
| Medium | 2 |
| Low | 4 |
| Potential Issue | 10 |

### Severity Breakdown

| Severity | Priority | Count |
|----------|----------|-------|
| High | 2 | 1 |
| Medium | 3 | 2 |
| Low | 5 | 4 |
| Potential Issue | 7 | 10 |

---

## Findings

---

### Finding 1

| Field | Value |
|-------|-------|
| **Title** | java.util.Random |
| **Severity** | High |
| **Priority** | 2 |
| **File** | `JWTSecretKeyEndpoint.java` |
| **Line** | 19 |
| **Code** | `import java.util.Random;` |

**Description:** This package is flawed and produces predictable values for any given seed which are easily reproducible once the starting seed is identified.

---

### Findings 2–3: Code Appears to Contain Hard-Coded Password

**Severity:** Medium | **Priority:** 3

The code may contain a hard-coded password which an attacker could obtain from the source or by dis-assembling the executable. Please manually review the code.

| # | File | Line | Code |
|---|------|------|------|
| 2 | `JWTRefreshEndpoint.java` | 45 | `public static final String PASSWORD = "bm5nhSkxCXZkKRy4";` |
| 3 | `JWTRefreshEndpoint.java` | 46 | `private static final String JWT_PASSWORD = "bm5n3SkxCX4kKRy4";` |

---

### Findings 4–7: Operation on Primitive Data Type

**Severity:** Low | **Priority:** 5

The code appears to be carrying out a mathematical operation on a primitive data type. In some circumstances this can result in an overflow and unexpected behaviour. Check the code manually to determine the risk.

| # | File | Line | Code |
|---|------|------|------|
| 4 | `JWTQuiz.java` | 32 | `for (int i = 0; i < solutions.length; i++) {` |
| 5 | `JWTQuiz.java` | 35 | `correctAnswers++;` |
| 6 | `JWTVotesEndpoint.java` | 170 | `ofNullable(votes.get(title)).ifPresent(v -> v.incrementNumberOfVotes(totalVotes));` |
| 7 | `votes/Vote.java` | 59 | `return Math.round(((double) numberOfVotes / (double) totalVotes) * 4);` |

---

### Findings 8–17: Public Class Not Declared as Final

**Severity:** Potential Issue | **Priority:** 7

The class is not declared as final as per OWASP recommendations. It is considered best practice to make classes final where possible and practical (i.e. it has no classes which inherit from it). Non-final classes can allow an attacker to extend a class in a malicious manner. Manually inspect the code to determine whether or not it is practical to make this class final.

| # | File | Line | Code |
|---|------|------|------|
| 8 | `JWT.java` | 12 | `public class JWT extends Lesson {` |
| 9 | `JWTDecodeEndpoint.java` | 18 | `public class JWTDecodeEndpoint implements AssignmentEndpoint {` |
| 10 | `JWTQuiz.java` | 19 | `public class JWTQuiz implements AssignmentEndpoint {` |
| 11 | `JWTRefreshEndpoint.java` | 43 | `public class JWTRefreshEndpoint implements AssignmentEndpoint {` |
| 12 | `JWTSecretKeyEndpoint.java` | 32 | `public class JWTSecretKeyEndpoint implements AssignmentEndpoint {` |
| 13 | `JWTVotesEndpoint.java` | 53 | `public class JWTVotesEndpoint implements AssignmentEndpoint {` |
| 14 | `claimmisuse/JWTHeaderJKUEndpoint.java` | 38 | `public class JWTHeaderJKUEndpoint implements AssignmentEndpoint {` |
| 15 | `claimmisuse/JWTHeaderKIDEndpoint.java` | 41 | `public class JWTHeaderKIDEndpoint implements AssignmentEndpoint {` |
| 16 | `votes/Views.java` | 7 | `public class Views {` |
| 17 | `votes/Vote.java` | 11 | `public class Vote {` |
