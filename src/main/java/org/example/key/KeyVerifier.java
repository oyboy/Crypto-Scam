package org.example.key;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class KeyVerifier {
    public byte[] createKeyVerifier(byte[] key) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
            hmac.init(keySpec);
            return hmac.doFinal("KEY_VERIFIER".getBytes());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            System.err.println("Error creating key verifier: " + e.getMessage());
        }
        return null;
    }
    public boolean verifyKey(byte[] candidateKey, byte[] storedVerifier) {
        try{
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(candidateKey, "HmacSHA256");
            hmac.init(keySpec);
            byte[] computedVerifier = hmac.doFinal("KEY_VERIFIER".getBytes());

            return MessageDigest.isEqual(computedVerifier, storedVerifier);
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalArgumentException e) {
            System.err.println("Error verifying key: " + e.getMessage());
        }
        return false;
    }
}