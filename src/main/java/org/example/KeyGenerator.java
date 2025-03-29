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
    public byte[] generateKeyFromPassword(String password, byte[] salt, int keyLengthBytes) {
        try{
            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(),
                    salt,
                    100_000,
                    keyLengthBytes * 8
            );
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println("Error while generating key from password: " + e.getMessage());
        }
        return null;
    }
    public byte[] generateSalt(int saltSizeBytes) {
        BBSRandom secureRandom = new BBSRandom();
        return secureRandom.nextBytes(saltSizeBytes);
    }
}
