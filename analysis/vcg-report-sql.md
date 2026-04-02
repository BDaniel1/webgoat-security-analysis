# VCG Scan Report — SQL Injection Lessons

**Prompt Used:** 
```
Read ./analysis/vcg-sqlinjection.xml and convert the VCG scan results into a clean markdown report at ./analysis/vcg-report-sql.md.
```

**Source:** `vsg-sqlinjection.xml`
**Scan directory:** `WebGoat\src\main\java\org\owasp\webgoat\lessons\sqlinjection`
**Language:** Java
**Date exported:** 2026-03-31

---

## Summary

| Metric | Value |
|--------|-------|
| Total findings | 36 |
| Critical | 1 |
| Medium | 1 |
| Standard | 1 |
| Low | 9 |
| Potential Issue | 24 |

### Severity Breakdown

| Severity | Priority | Count |
|----------|----------|-------|
| Critical | 1 | 1 |
| Medium | 3 | 1 |
| Standard | 4 | 1 |
| Low | 5 | 9 |
| Potential Issue | 7 | 24 |

---

## Findings

---

### Finding 1

| Field | Value |
|-------|-------|
| **Title** | Potential SQL Injection |
| **Severity** | Critical |
| **Priority** | 1 |
| **File** | `advanced/SqlInjectionLesson10.java` |
| **Line** | 56 |
| **Code** | `ResultSet results = statement.executeQuery(query);` |

**Description:** The application appears to allow SQL injection via a pre-prepared dynamic SQL statement. No validator plug-ins were located in the application's XML files.

---

### Finding 2

| Field | Value |
|-------|-------|
| **Title** | Code Appears to Contain Hard-Coded Password |
| **Severity** | Medium |
| **Priority** | 3 |
| **File** | `advanced/SqlInjectionLesson6b.java` |
| **Line** | 42 |
| **Code** | `String password = "dave";` |

**Description:** The code may contain a hard-coded password which an attacker could obtain from the source or by dis-assembling the executable. Please manually review the code.

---

### Finding 3

| Field | Value |
|-------|-------|
| **Title** | Class Contains Inner Class |
| **Severity** | Standard |
| **Priority** | 4 |
| **File** | `mitigation/Servers.java` |
| **Line** | 29 |
| **Code** | `private class Server {` |

**Description:** When translated into bytecode, any inner classes are rebuilt within the JVM as external classes within the same package. As a result, any class in the package can access these inner classes. The enclosing class's private fields become protected fields, accessible by the now external 'inner class'.

---

### Findings 4–12: Operation on Primitive Data Type

**Severity:** Low | **Priority:** 5

The code appears to be carrying out a mathematical operation on a primitive data type. In some circumstances this can result in an overflow and unexpected behaviour. Check the code manually to determine the risk.

| # | File | Line | Code |
|---|------|------|------|
| 4 | `advanced/SqlInjectionQuiz.java` | 49 | `for (int i = 0; i < solutions.length; i++) {` |
| 5 | `advanced/SqlInjectionQuiz.java` | 52 | `correctAnswers++;` |
| 6 | `introduction/SqlInjectionLesson5a.java` | 96 | `for (int i = 1; i < (numColumns + 1); i++) {` |
| 7 | `introduction/SqlInjectionLesson5a.java` | 106 | `for (int i = 1; i < (numColumns + 1); i++) {` |
| 8 | `introduction/SqlInjectionLesson8.java` | 109 | `for (int i = 1; i < (numColumns + 1); i++) {` |
| 9 | `introduction/SqlInjectionLesson8.java` | 110 | `table.append("<th>" + resultsMetaData.getColumnName(i) + "</th>");` |
| 10 | `introduction/SqlInjectionLesson8.java` | 117 | `for (int i = 1; i < (numColumns + 1); i++) {` |
| 11 | `introduction/SqlInjectionLesson8.java` | 118 | `table.append("<td>" + results.getString(i) + "</td>");` |
| 12 | `mitigation/SqlInjectionLesson10a.java` | 48 | `position++;` |

---

### Findings 13–36: Public Class Not Declared as Final

**Severity:** Potential Issue | **Priority:** 7

The class is not declared as final as per OWASP recommendations. It is considered best practice to make classes final where possible and practical (i.e. it has no classes which inherit from it). Non-final classes can allow an attacker to extend a class in a malicious manner. Manually inspect the code to determine whether or not it is practical to make this class final.

| # | File | Line | Code |
|---|------|------|------|
| 13 | `advanced/SqlInjectionAdvanced.java` | 12 | `public class SqlInjectionAdvanced extends Lesson {` |
| 14 | `advanced/SqlInjectionChallenge.java` | 34 | `public class SqlInjectionChallenge implements AssignmentEndpoint {` |
| 15 | `advanced/SqlInjectionChallengeLogin.java` | 19 | `public class SqlInjectionChallengeLogin implements AssignmentEndpoint {` |
| 16 | `advanced/SqlInjectionLesson6a.java` | 34 | `public class SqlInjectionLesson6a implements AssignmentEndpoint {` |
| 17 | `advanced/SqlInjectionLesson6b.java` | 24 | `public class SqlInjectionLesson6b implements AssignmentEndpoint {` |
| 18 | `advanced/SqlInjectionQuiz.java` | 25 | `public class SqlInjectionQuiz implements AssignmentEndpoint {` |
| 19 | `introduction/SqlInjection.java` | 12 | `public class SqlInjection extends Lesson {` |
| 20 | `introduction/SqlInjectionLesson10.java` | 33 | `public class SqlInjectionLesson10 implements AssignmentEndpoint {` |
| 21 | `introduction/SqlInjectionLesson2.java` | 32 | `public class SqlInjectionLesson2 implements AssignmentEndpoint {` |
| 22 | `introduction/SqlInjectionLesson3.java` | 27 | `public class SqlInjectionLesson3 implements AssignmentEndpoint {` |
| 23 | `introduction/SqlInjectionLesson4.java` | 28 | `public class SqlInjectionLesson4 implements AssignmentEndpoint {` |
| 24 | `introduction/SqlInjectionLesson5.java` | 31 | `public class SqlInjectionLesson5 implements AssignmentEndpoint {` |
| 25 | `introduction/SqlInjectionLesson5a.java` | 22 | `public class SqlInjectionLesson5a implements AssignmentEndpoint {` |
| 26 | `introduction/SqlInjectionLesson5b.java` | 29 | `public class SqlInjectionLesson5b implements AssignmentEndpoint {` |
| 27 | `introduction/SqlInjectionLesson8.java` | 33 | `public class SqlInjectionLesson8 implements AssignmentEndpoint {` |
| 28 | `introduction/SqlInjectionLesson9.java` | 34 | `public class SqlInjectionLesson9 implements AssignmentEndpoint {` |
| 29 | `mitigation/Servers.java` | 23 | `public class Servers {` |
| 30 | `mitigation/SqlInjectionLesson10a.java` | 23 | `public class SqlInjectionLesson10a implements AssignmentEndpoint {` |
| 31 | `mitigation/SqlInjectionLesson10b.java` | 40 | `public class SqlInjectionLesson10b implements AssignmentEndpoint {` |
| 32 | `mitigation/SqlInjectionLesson10b.java` | 107 | `"import java.sql.*; public class TestClass { static String DBUSER; static String DBPW;"` |
| 33 | `mitigation/SqlInjectionLesson13.java` | 33 | `public class SqlInjectionLesson13 implements AssignmentEndpoint {` |
| 34 | `mitigation/SqlInjectionMitigations.java` | 12 | `public class SqlInjectionMitigations extends Lesson {` |
| 35 | `mitigation/SqlOnlyInputValidation.java` | 21 | `public class SqlOnlyInputValidation implements AssignmentEndpoint {` |
| 36 | `mitigation/SqlOnlyInputValidationOnKeywords.java` | 25 | `public class SqlOnlyInputValidationOnKeywords implements AssignmentEndpoint {` |

> **Note — Finding 32:** The flagged code at `SqlInjectionLesson10b.java:107` is a Java string literal containing sample code used for the lesson exercise, not an actual class declaration. This appears to be a false positive triggered by the scanner matching the `public class` pattern inside a string value.
