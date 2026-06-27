# Security Advisory: Eclipse Angus Activation — Arbitrary Class Instantiation, Deserialization RCE, SSRF, Mailcap Injection

## Summary

Eclipse Angus Activation (Jakarta Activation implementation) contains 2 CRITICAL and 3 HIGH-severity vulnerabilities forming a complete kill chain: crafted mailcap file → arbitrary class loading with static initializer execution → class instantiation → optional ObjectInputStream deserialization of attacker-controlled data. Additionally, URLDataSource enables SSRF with no protocol/host filtering. Mailcap loaded from 5+ untrusted sources automatically.

**Verified against:** angus-activation v2.1.0-SNAPSHOT + jakarta.activation-api v2.2.0-M2 (latest HEAD)

---

## Finding 1: Arbitrary Class Instantiation via Mailcap Entries (CRITICAL)

### CVSS Score: 9.8

### Description

At `MailcapCommandMap.java:620-646`, `getDataContentHandler()` calls `Class.forName(name)` → `newInstance()` with class name from mailcap entries. At `CommandInfo.java:156-188`, `instantiate()` calls `Class.forName(cn, true, loader)` → `getDeclaredConstructor().newInstance()`. Class name stored in `MailcapFile.java:421-436` from `x-java-*` parameters with zero validation — no allowlist, no package prefix check, no type verification before instantiation.

Cast to `DataContentHandler` happens **after** instantiation — constructor side effects already executed.

**Attack vectors:** META-INF/mailcap on classpath (dependency poisoning), `addMailcap()` API with user input, `~/.jakarta.mailcap` or `~/.mailcap` (local privilege escalation), `$JAVA_HOME/conf/mailcap` (JDK persistence).

### Fix

Verify class implements expected interface before `newInstance()`. Implement class allowlist.

---

## Finding 2: Unsafe Deserialization in CommandInfo.getCommandObject() (CRITICAL)

### CVSS Score: 9.8

### Description

At `CommandInfo.java:121-128`, when loaded class implements `Externalizable`, creates raw `ObjectInputStream` over DataHandler's input stream and calls `readExternal()`. No `ObjectInputFilter`, no type validation. Combined with Finding 1 (class from mailcap) and attacker-controlled input stream content (e.g., crafted email attachment), achieves full deserialization RCE via gadget chains (Commons Collections, Spring, etc.).

### Fix

Apply `ObjectInputFilter` (JEP 290). Remove `Externalizable` code path or require explicit opt-in.

---

## Finding 3: SSRF via URLDataSource — No Protocol/Host Filtering (HIGH)

### CVSS Score: 7.5

### Description

At `URLDataSource.java:56-92`, accepts any `java.net.URL` with zero restrictions. `getContentType()` opens network connections via `openConnection()` as side effect of getter. `getInputStream()` opens streams. `file://`, `jar://`, `gopher://`, `ftp://` all work. No hostname/IP validation — cloud metadata `http://169.254.169.254/` accessible. `DataHandler(URL)` auto-creates URLDataSource.

### Fix

Protocol allowlist (http/https only). Block private/loopback IPs. Add connection timeouts.

---

## Finding 4: Unvalidated Mailcap Loading from Multiple Untrusted Sources (HIGH)

### CVSS Score: 7.2

### Description

At `MailcapCommandMap.java:141-192`, default constructor loads from 5+ sources: `~/.jakarta.mailcap`, `~/.mailcap`, `$JAVA_HOME/conf/jakarta.mailcap`, `$JAVA_HOME/conf/mailcap`, ALL `META-INF/jakarta.mailcap` and `META-INF/mailcap` on entire classpath. No integrity verification, no signature check, no disable option. Legacy `.mailcap` paths expand attack surface. This is the injection vector for Findings 1, 2, and 5.

### Fix

Add system property to disable file-based loading. Log which files loaded. Remove legacy fallback paths.

---

## Finding 5: Static Initializer Exploitation via Class.forName(init=true) (HIGH)

### CVSS Score: 8.1

### Description

At `CommandInfo.java:179`, `Class.forName(cn, true, loader)` — `true` triggers static initializers before instantiation and before type checking. At `MailcapCommandMap.java:637`, `Class.forName(name)` (default = initialize). Static initializers can execute commands, open connections, modify global state. ClassCastException thrown later does NOT prevent exploitation — static initializer already ran.

### Fix

Use `Class.forName(name, false, loader)`. Verify interface before initialization.

---

## Attack Chain

```
Mailcap Sources (F4) → Class.forName init=true (F5) → Static Initializer RCE
                      → Arbitrary Instantiation (F1) → Constructor RCE
                      → Externalizable + ObjectInputStream (F2) → Gadget Chain RCE
URLDataSource (F3) → SSRF / Local File Read
```

---

## Disclosure Timeline

- **2026-06-27:** Vulnerabilities discovered and verified in latest source
