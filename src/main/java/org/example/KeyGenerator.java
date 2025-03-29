package org.example;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class KeyGenerator {
    public byte[] generateRandomKey(int keySizeBytes) {
        BBSRandom secureRandom = new BBSRandom();
        return secureRandom.nextBytes(keySizeBytes);
    }
    public String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public byte[] generateKeyFromPassword(String password, int keySizeBytes) {
        byte[] key = null;
        try{
            key = generateKeyFromPassword(password, generateSalt(128), 100_000, keySizeBytes);
        } catch (Exception ex) {
            System.err.println("Error generating key from password: " + ex.getMessage());
        }
        return key;
    }

    private byte[] generateKeyFromPassword(String password, byte[] salt, int iterations, int keyLengthBytes)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                iterations,
                keyLengthBytes * 8
        );
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }
    private byte[] generateSalt(int saltSizeBytes) {
        BBSRandom secureRandom = new BBSRandom();
        return secureRandom.nextBytes(saltSizeBytes);
    }
}
