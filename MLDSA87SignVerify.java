import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Base64;

public class MLDSA87SignVerify {

    private static final String PKCS12_FILE =
            System.getProperty("user.home") +
            "/PQC/ML-DSA-87_PKCS12.p12";

    private static final String OUTPUT_FILE =
            System.getProperty("user.home") +
            "/PQC/ML-DSA-87-SignedMessage.txt";

    public static void main(String[] args) {

        try {
            Console console = System.console();

            if (console == null) {
                System.err.println(
                        "ERROR: No interactive console is available."
                );
                System.err.println(
                        "Run this program from a command-line terminal."
                );
                System.exit(1);
            }

            System.out.println("==============================================");
            System.out.println(" ML-DSA-87 Java PQC Sign / Verify");
            System.out.println("==============================================");
            System.out.println();

            // ---------------------------------------------------------
            // 1. Verify that the PKCS#12 file exists
            // ---------------------------------------------------------

            Path pkcs12Path = Path.of(PKCS12_FILE);

            if (!Files.exists(pkcs12Path)) {
                throw new IllegalArgumentException(
                        "PKCS#12 file not found: " + PKCS12_FILE
                );
            }

            System.out.println("PKCS#12 file:");
            System.out.println("  " + PKCS12_FILE);
            System.out.println();

            // ---------------------------------------------------------
            // 2. Prompt for PKCS#12 password
            // ---------------------------------------------------------

            char[] password = console.readPassword(
                    "Enter PKCS#12 password: "
            );

            if (password == null || password.length == 0) {
                throw new IllegalArgumentException(
                        "A PKCS#12 password is required."
                );
            }

            // ---------------------------------------------------------
            // 3. Load PKCS#12 keystore
            // ---------------------------------------------------------

            KeyStore keyStore = KeyStore.getInstance("PKCS12");

            try {
                keyStore.load(
                        Files.newInputStream(pkcs12Path),
                        password
                );
            } finally {
                // Do not retain the password unnecessarily.
                java.util.Arrays.fill(password, '\0');
            }

            System.out.println();
            System.out.println("PKCS#12 keystore loaded successfully.");

            // ---------------------------------------------------------
            // 4. Find the ML-DSA private-key entry
            // ---------------------------------------------------------

            String alias = null;

            var aliases = keyStore.aliases();

            while (aliases.hasMoreElements()) {

                String candidate = aliases.nextElement();

                if (keyStore.isKeyEntry(candidate)) {
                    alias = candidate;
                    break;
                }
            }

            if (alias == null) {
                throw new IllegalStateException(
                        "No private-key entry found in PKCS#12 file."
                );
            }

            System.out.println("Key alias:");
            System.out.println("  " + alias);

            // ---------------------------------------------------------
            // 5. Extract the private key
            // ---------------------------------------------------------

            // The OpenSSL PKCS#12 created by the supplied shell script
            // protects the private key using the same password used
            // during PKCS#12 export.

            char[] keyPassword = console.readPassword(
                    "Enter private-key password: "
            );

            PrivateKey privateKey;

            try {
                privateKey = (PrivateKey)
                        keyStore.getKey(alias, keyPassword);
            } finally {
                java.util.Arrays.fill(keyPassword, '\0');
            }

            if (privateKey == null) {
                throw new IllegalStateException(
                        "Unable to extract private key."
                );
            }

            System.out.println(
                    "Private-key algorithm: " +
                    privateKey.getAlgorithm()
            );

            // ---------------------------------------------------------
            // 6. Extract public key from X.509 certificate
            // ---------------------------------------------------------

            Certificate certificate =
                    keyStore.getCertificate(alias);

            if (certificate == null) {
                throw new IllegalStateException(
                        "No certificate found for alias: " + alias
                );
            }

            PublicKey publicKey =
                    certificate.getPublicKey();

            System.out.println(
                    "Public-key algorithm: " +
                    publicKey.getAlgorithm()
            );

            // ---------------------------------------------------------
            // 7. Verify that this is an ML-DSA key
            // ---------------------------------------------------------

            if (!"ML-DSA".equalsIgnoreCase(
                    privateKey.getAlgorithm())) {

                throw new IllegalStateException(
                        "The private key is not an ML-DSA key. " +
                        "Detected: " +
                        privateKey.getAlgorithm()
                );
            }

            if (!"ML-DSA".equalsIgnoreCase(
                    publicKey.getAlgorithm())) {

                throw new IllegalStateException(
                        "The certificate public key is not an " +
                        "ML-DSA key. Detected: " +
                        publicKey.getAlgorithm()
                );
            }

            // ---------------------------------------------------------
            // 8. Prompt for message
            // ---------------------------------------------------------

            System.out.println();
            String message = console.readLine(
                    "Enter message to sign: "
            );

            if (message == null || message.isEmpty()) {
                throw new IllegalArgumentException(
                        "Message cannot be empty."
                );
            }

            byte[] messageBytes =
                    message.getBytes(StandardCharsets.UTF_8);

            // ---------------------------------------------------------
            // 9. Create ML-DSA-87 digital signature
            // ---------------------------------------------------------

            Signature signer =
                    Signature.getInstance("ML-DSA");

            signer.initSign(privateKey);
            signer.update(messageBytes);

            byte[] signature = signer.sign();

            System.out.println();
            System.out.println(
                    "ML-DSA signature generated successfully."
            );

            System.out.println(
                    "Signature size: " +
                    signature.length +
                    " bytes"
            );

            // ---------------------------------------------------------
            // 10. Save message + Base64 signature
            // ---------------------------------------------------------

            String encodedSignature =
                    Base64.getEncoder()
                            .encodeToString(signature);

            String output =
                    "Algorithm: ML-DSA-87\n" +
                    "Encoding: UTF-8\n" +
                    "\n" +
                    "Message:\n" +
                    message +
                    "\n" +
                    "\n" +
                    "Signature (Base64):\n" +
                    encodedSignature +
                    "\n";

            Path outputPath =
                    Path.of(OUTPUT_FILE);

            Files.writeString(
                    outputPath,
                    output,
                    StandardCharsets.UTF_8
            );

            System.out.println();
            System.out.println(
                    "Signed message saved to:"
            );
            System.out.println(
                    "  " + OUTPUT_FILE
            );

            // ---------------------------------------------------------
            // 11. Verify using the extracted public key
            // ---------------------------------------------------------

            Signature verifier =
                    Signature.getInstance("ML-DSA");

            verifier.initVerify(publicKey);
            verifier.update(messageBytes);

            boolean verified =
                    verifier.verify(signature);

            System.out.println();
            System.out.println(
                    "=============================================="
            );

            if (verified) {
                System.out.println(
                        "SUCCESS: ML-DSA-87 signature VERIFIED."
                );
            } else {
                System.out.println(
                        "FAILURE: ML-DSA-87 signature INVALID."
                );
            }

            System.out.println(
                    "=============================================="
            );

        } catch (Exception e) {

            System.err.println();
            System.err.println(
                    "ERROR: " + e.getMessage()
            );

            e.printStackTrace(System.err);

            System.exit(1);
        }
    }
}
