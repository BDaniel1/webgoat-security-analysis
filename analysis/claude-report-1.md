# Security Review Report — claude-report-1.md

**Prompt Used:** 
```
read .claude\commands\security-review.md and perform a security review on the following folders inside the \src\main\java\org\owasp\webgoat\lessons folder: sqlinjection, xxe, & ssrf.
```

**Date:** 2026-03-31
**Scope:** `lessons/sqlinjection`, `lessons/xxe`, `lessons/ssrf`
**Reviewer:** Claude (senior security engineer mode)

---

## Summary

| # | Severity | Category | File | Confidence |
|---|----------|----------|------|------------|
| 1 | HIGH | XXE / File Disclosure | `CommentsCache.java:68` | 10/10 |
| 2 | HIGH | SQL Injection (Full Query Control) | `SqlInjectionLesson2.java:49` | 10/10 |
| 3 | HIGH | SQL Injection (Full Query Control — DDL) | `SqlInjectionLesson3.java:47` | 10/10 |
| 4 | HIGH | SQL Injection (Full Query Control — DDL) | `SqlInjectionLesson4.java:46` | 10/10 |
| 5 | HIGH | SQL Injection (String Concatenation) | `SqlInjectionLesson5a.java:48` | 10/10 |
| 6 | HIGH | SQL Injection (Partial Parameterization Bypass) | `SqlInjectionLesson5b.java:45` | 10/10 |
| 7 | HIGH | SQL Injection (UNION-capable) | `SqlInjectionLesson6a.java:54` | 10/10 |
| 8 | HIGH | SQL Injection (Multi-field Concatenation) | `SqlInjectionLesson8.java:50` | 10/10 |
| 9 | HIGH | SQL Injection (DML via execute()) | `SqlInjectionLesson9.java:51` | 10/10 |
| 10 | HIGH | SQL Injection (LIKE clause) | `SqlInjectionLesson10.java:49` | 10/10 |
| 11 | HIGH | SQL Injection (Existence Check) | `SqlInjectionChallenge.java:55` | 9/10 |
| 12 | MEDIUM | SSRF (Intentional Outbound Request) | `SSRFTask2.java:36` | 8/10 |

---

## Findings

---

### Vuln 1: XXE — `CommentsCache.java:68`

* **Severity:** HIGH
* **Category:** XXE Injection / File Disclosure
* **Confidence:** 10/10

**Description:**
`CommentsCache.parseXml()` accepts a `securityEnabled` boolean, but every caller in scope passes `false`. When `securityEnabled=false`, the `XMLInputFactory` is configured with **no external entity restrictions**. The XML parser will resolve external entity declarations, allowing attackers to read local files or trigger outbound HTTP requests.

```java
// CommentsCache.java:68
protected Comment parseXml(String xml, boolean securityEnabled)
    throws XMLStreamException, JAXBException {
  var xif = XMLInputFactory.newInstance();
  // TODO fix me disabled for now.
  if (securityEnabled) {                              // always false in all callers
    xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    xif.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
  }
  ...
}
```

**Callers that pass `false` (all exploitable):**
- [`SimpleXXE.java:54`](WebGoat/src/main/java/org/owasp/webgoat/lessons/xxe/SimpleXXE.java#L54) — `POST /xxe/simple`
- [`BlindSendFileAssignment.java:79`](WebGoat/src/main/java/org/owasp/webgoat/lessons/xxe/BlindSendFileAssignment.java#L79) — `POST /xxe/blind`
- [`ContentTypeAssignment.java:60`](WebGoat/src/main/java/org/owasp/webgoat/lessons/xxe/ContentTypeAssignment.java#L60) — `POST /xxe/content-type`

**Exploit Scenario:**
An attacker posts the following XML to any of the three endpoints:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<comment><text>&xxe;</text></comment>
```
The parser resolves the entity and embeds `/etc/passwd` content in the `Comment` object, which is returned in the response. For the blind variant (`/xxe/blind`), a SSRF-via-XXE exfiltration DTD can route the file contents to an attacker-controlled server.

**Recommendation:**
Remove the `securityEnabled` flag and always apply the protective properties unconditionally:
```java
xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
xif.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
```

---

### Vuln 2: SQL Injection (Full Query Control) — `SqlInjectionLesson2.java:49`

* **Severity:** HIGH
* **Category:** SQL Injection
* **Confidence:** 10/10

**Description:**
The endpoint at `POST /SqlInjection/attack2` accepts a raw SQL query string from the user and executes it directly via `Statement.executeQuery()`. There is zero input filtering or parameterization.

```java
// SqlInjectionLesson2.java:48
Statement statement = connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY);
ResultSet results = statement.executeQuery(query);  // `query` is the raw user param
```

**Exploit Scenario:**
An attacker submits `SELECT * FROM user_system_data` (or any other table) to dump all data in the database, bypassing the intended query context entirely.

**Recommendation:** Replace with a parameterized `PreparedStatement` with a fixed query template; do not allow callers to supply arbitrary SQL.

---

### Vuln 3: SQL Injection (Full DDL Control) — `SqlInjectionLesson3.java:47`

* **Severity:** HIGH
* **Category:** SQL Injection
* **Confidence:** 10/10

**Description:**
`POST /SqlInjection/attack3` passes an arbitrary user-supplied string to `Statement.executeUpdate()`. This allows DML and DDL operations (UPDATE, DELETE, DROP, CREATE, GRANT) without restriction.

```java
// SqlInjectionLesson3.java:47
statement.executeUpdate(query);
```

**Exploit Scenario:**
An attacker sends `DROP TABLE employees` or `UPDATE employees SET salary = 0 WHERE 1=1` to destroy or corrupt data. Depending on DB permissions, `CREATE USER attacker PASSWORD 'owned'` is also viable.

**Recommendation:** Use a parameterized statement with a fixed query template; do not execute arbitrary user-supplied SQL via `executeUpdate`.

---

### Vuln 4: SQL Injection (Full DDL Control) — `SqlInjectionLesson4.java:46`

* **Severity:** HIGH
* **Category:** SQL Injection
* **Confidence:** 10/10

**Description:**
Identical pattern to Vuln 3. `POST /SqlInjection/attack4` passes user-controlled `query` directly to `executeUpdate()`.

```java
// SqlInjectionLesson4.java:46
statement.executeUpdate(query);
connection.commit();
```

**Exploit Scenario:**
Same as Vuln 3. The `connection.commit()` call additionally ensures any destructive DDL is committed immediately.

**Recommendation:** Same as Vuln 3.

---

### Vuln 5: SQL Injection (String Concatenation) — `SqlInjectionLesson5a.java:48`

* **Severity:** HIGH
* **Category:** SQL Injection
* **Confidence:** 10/10

**Description:**
`POST /SqlInjection/assignment5a` accepts three separate user inputs (`account`, `operator`, `injection`) that are concatenated into an unparameterized SQL query.

```java
// SqlInjectionLesson5a.java:41
return injectableQuery(account + " " + operator + " " + injection);
...
// line 48
query = "SELECT * FROM user_data WHERE first_name = 'John' and last_name = '" + accountName + "'";
```

**Exploit Scenario:**
Attacker supplies `injection = "' OR '1'='1"` to return all rows, or uses a UNION clause to exfiltrate data from other tables (`user_system_data`).

**Recommendation:** Use a `PreparedStatement` with `?` placeholders for all user-supplied values.

---

### Vuln 6: SQL Injection (Partial Parameterization Bypass) — `SqlInjectionLesson5b.java:45`

* **Severity:** HIGH
* **Category:** SQL Injection
* **Confidence:** 10/10

**Description:**
`POST /SqlInjection/assignment5b` uses a `PreparedStatement` for the `login_count` parameter but concatenates the `userid` (accountName) parameter directly into the query string. This false sense of security is a common mistake — parameterizing one field while leaving another injectable.

```java
// SqlInjectionLesson5b.java:45
String queryString = "SELECT * From user_data WHERE Login_Count = ? and userid= " + accountName;
```

**Exploit Scenario:**
An attacker submits `userid = "1 OR 1=1"` to return all employee records regardless of login count.

**Recommendation:** Parameterize **both** fields: `WHERE Login_Count = ? AND userid = ?`

---

### Vuln 7: SQL Injection (UNION-capable) — `SqlInjectionLesson6a.java:54`

* **Severity:** HIGH
* **Category:** SQL Injection
* **Confidence:** 10/10

**Description:**
`POST /SqlInjectionAdvanced/attack6a` concatenates user input directly into the `WHERE` clause. The code even hints at the intended exploit in a comment on line 46.

```java
// SqlInjectionLesson6a.java:54
query = "SELECT * FROM user_data WHERE last_name = '" + accountName + "'";
```

**Exploit Scenario:**
`accountName = "Smith' UNION SELECT userid,user_name,password,cookie,cookie,cookie,userid FROM user_system_data --"` dumps credential data from the `user_system_data` table.

**Recommendation:** Use a `PreparedStatement` with a `?` placeholder for `last_name`.

---

### Vuln 8: SQL Injection (Multi-field Concatenation) — `SqlInjectionLesson8.java:50`

* **Severity:** HIGH
* **Category:** SQL Injection
* **Confidence:** 10/10

**Description:**
`POST /SqlInjection/attack8` concatenates both `name` and `auth_tan` directly into the query. Neither field is parameterized.

```java
// SqlInjectionLesson8.java:50
String query = "SELECT * FROM employees WHERE last_name = '"
    + name + "' AND auth_tan = '" + auth_tan + "'";
```

**Exploit Scenario:**
Attacker sets `auth_tan = "' OR '1'='1"` to bypass the authentication check and return all employee rows. Combined with the multi-row success condition, this trivially solves the lesson — demonstrating a real bypass of a WHERE-clause guard.

**Recommendation:** Use a `PreparedStatement` with `?` for both `last_name` and `auth_tan`.

---

### Vuln 9: SQL Injection (DML via execute()) — `SqlInjectionLesson9.java:51`

* **Severity:** HIGH
* **Category:** SQL Injection
* **Confidence:** 10/10

**Description:**
`POST /SqlInjection/attack9` uses the same concatenated query pattern as Vuln 8, but executes it via `statement.execute()` (not `executeQuery`), enabling DML statements in addition to SELECT.

```java
// SqlInjectionLesson9.java:51
String queryInjection = "SELECT * FROM employees WHERE last_name = '"
    + name + "' AND auth_tan = '" + auth_tan + "'";
...
statement.execute(queryInjection);  // line 65 — permits UPDATE/INSERT
```

**Exploit Scenario:**
Attacker sends `auth_tan = "3SL99A'; UPDATE employees SET salary=999999 WHERE auth_tan='3SL99A"` to issue an unauthorized UPDATE. The `execute()` call supports multi-statement injection (database-dependent), making this more dangerous than a read-only query.

**Recommendation:** Use a `PreparedStatement` with `?` for both parameters. Do not use `execute()` for SELECT-only workloads.

---

### Vuln 10: SQL Injection (LIKE Clause) — `SqlInjectionLesson10.java:49`

* **Severity:** HIGH
* **Category:** SQL Injection
* **Confidence:** 10/10

**Description:**
`POST /SqlInjection/attack10` concatenates `action_string` directly into a LIKE clause. User input is not escaped or parameterized.

```java
// SqlInjectionLesson10.java:49
String query = "SELECT * FROM access_log WHERE action LIKE '%" + action + "%'";
```

**Exploit Scenario:**
An attacker terminates the LIKE clause and appends a `DROP TABLE access_log` or a UNION select to exfiltrate data: `action = "' UNION SELECT table_name,2,3 FROM INFORMATION_SCHEMA.TABLES --"`.

**Recommendation:** Use `PreparedStatement`: `WHERE action LIKE ?` and pass `"%" + action + "%"` as the bound value.

---

### Vuln 11: SQL Injection (Existence Check) — `SqlInjectionChallenge.java:55`

* **Severity:** HIGH
* **Category:** SQL Injection
* **Confidence:** 9/10

**Description:**
`PUT /SqlInjectionAdvanced/register` performs a username existence check using a concatenated `Statement` before a parameterized `PreparedStatement` INSERT. The INSERT is safe, but the preceding SELECT is injectable.

```java
// SqlInjectionChallenge.java:54
String checkUserQuery =
    "select userid from sql_challenge_users where userid = '" + username + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(checkUserQuery);
```

**Exploit Scenario:**
An attacker submits `username = "' OR '1'='1"`. The `resultSet.next()` call returns `true` (a row matched), so the server responds with a "user exists" error — preventing registration of any new user. More critically, the injectable SELECT can be extended to a UNION to read data from other tables: `' UNION SELECT password FROM sql_challenge_users WHERE userid='tom' --`. The 250-character limit on username still allows this payload.

**Recommendation:** Replace the `Statement` existence check with a `PreparedStatement`:
```java
PreparedStatement check = connection.prepareStatement(
    "SELECT userid FROM sql_challenge_users WHERE userid = ?");
check.setString(1, username);
```

---

### Vuln 12: SSRF (Intentional Outbound Request) — `SSRFTask2.java:36`

* **Severity:** MEDIUM
* **Category:** SSRF
* **Confidence:** 8/10

**Description:**
`POST /SSRF/task2` accepts a `url` parameter and, when it exactly matches `http://ifconfig.pro`, opens an `InputStream` to that URL and returns the response content to the caller.

```java
// SSRFTask2.java:34
if (url.matches("http://ifconfig\\.pro")) {
    try (InputStream in = new URL(url).openStream()) {
        html = new String(in.readAllBytes(), StandardCharsets.UTF_8)...
    }
}
```

While the regex restricts the accepted value to a single hardcoded external hostname, the server is making an outbound HTTP request to a third-party site on behalf of the user. In a real deployment, this request originates from the server's IP and could be used to probe internal network resources if the allowlist were ever loosened (even slightly — e.g., `http://ifconfig.pro.attacker.com` would not match, but subpath variations could). More concretely, the server's response includes the full HTTP body from `ifconfig.pro`, which reflects the server's public IP address back to the user.

**Exploit Scenario:**
The immediate risk is server IP disclosure via the `ifconfig.pro` response. If an operator copies this pattern elsewhere without the strict regex, it becomes a full open SSRF. As written, the strict `matches()` constraint limits exploit surface, but the fundamental architecture (server fetching a user-specified URL) is unsafe by design.

**Recommendation:** If the intent is purely educational, document the risk explicitly. For production code following this pattern: use an explicit URL allowlist by comparing against a constant rather than a regex, disable HTTP redirects, and never pass user-controlled URL strings to `new URL(...).openStream()`.

---

## SSRF Findings — Not Reported

**`SSRFTask1.java`** — No actual outbound HTTP request is made. The URL parameter is matched against two hardcoded image paths and only used to set a static `src` attribute in HTML. Not exploitable as SSRF.

---

## Findings Not Reported

The following were considered and excluded:

- **`SqlInjectionLesson8.java:138` (log method)** — Single quotes are replaced with double quotes before insertion. HSQLDB treats double quotes as identifier delimiters, not string literals, making this harder to exploit without further evidence of a concrete payload. Confidence below threshold.
- **Stack trace disclosure** (`SimpleXXE.java:60`, `ContentTypeAssignment.java:66`) — `ExceptionUtils.getStackTrace(e)` is returned in error responses. Excluded per LOW severity rule (minor web issue).
- **`SSRFTask1.java`** — No live HTTP requests; URL values control only static HTML output.
