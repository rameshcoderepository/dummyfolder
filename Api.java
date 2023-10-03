import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class BhavishyaBankAPI {

    // Load Bhavishya's private key (for signing) and Bank's public key (for encryption) from files or other sources
    private static PrivateKey bhavishyaPrivateKey;
    private static PublicKey bankPublicKey;

    public static void main(String[] args) {
        try {
            // Step 1: Generate a secret key for AES encryption (32 bytes)
            SecretKey secretKey = generateSecretKey();

            // Step 2: Encrypt the plain data using AES with the generated secret key
            String plainData = "{\"REQUEST_REFERENCE_NUMBER\":\"XXXBH2 XXX183202200000001\", \"REQUEST\":\"SampleData\"}";
            String encryptedData = encryptWithAES(plainData, secretKey);

            // Step 3: Sign the plain data using Bhavishya's private key
            String digitalSignature = signDataWithRSA(plainData, bhavishyaPrivateKey);

            // Step 4: Encrypt the secret key using Bank's public key
            String encryptedSecretKey = encryptSecretKey(secretKey, bankPublicKey);

            // Step 5: Prepare the final request JSON with encrypted data, digital signature, and encrypted secret key
            String requestReferenceNumber = "XXXBH25111900000000000006";
            String requestJSON = buildRequestJSON(encryptedData, digitalSignature, encryptedSecretKey, requestReferenceNumber);

            // At this point, you can send the request JSON to the Bank over HTTP

            // For response handling, follow a similar process in reverse order

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        // Generate a random 32-byte secret key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private static String encryptWithAES(String plainText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String signDataWithRSA(String plainData, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(plainData.getBytes());
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private static String encryptSecretKey(SecretKey secretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSecretKeyBytes = cipher.doFinal(secretKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedSecretKeyBytes);
    }

    private static String buildRequestJSON(String encryptedData, String digitalSignature, String encryptedSecretKey, String requestReferenceNumber) {
        // Build the request JSON according to the specified format
        String requestJSON = "{\n" +
                "\"REQUEST_REFERENCE_NUMBER\": \"" + requestReferenceNumber + "\",\n" +
                "\"REQUEST\": \"" + encryptedData + "\",\n" +
                "\"DIGI_SIGN\": \"" + digitalSignature + "\",\n" +
                "\"AccessToken\": \"" + encryptedSecretKey + "\"\n" +
                "}";
        return requestJSON;
    }
}
