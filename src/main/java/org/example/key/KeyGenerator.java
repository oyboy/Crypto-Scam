package org.example.key;

import org.example.util.BBSRandom;
import org.example.util.DataOperator;

import java.security.NoSuchAlgorithmException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

public class KeyGenerator {
    private static final int ITERATIONS = 100_000;
    private static final int BLOCK_SIZE = 64;

    public byte[] generateKey(String password, byte[] salt, int keySizeBytes) {
        if (password == null) {
            BBSRandom sr = new BBSRandom();

            byte[] randomBytes = sr.nextBytes(keySizeBytes);
            String randomPassword = DataOperator.bytesToHex(randomBytes);

            System.out.println("Generated password: " + randomPassword);
            return generateKeyFromPassword(randomPassword, salt, keySizeBytes);
        } else {
            return generateKeyFromPassword(password, salt, keySizeBytes);
        }
    }

    public byte[] generateSalt(int saltSizeBytes) {
        BBSRandom sr = new BBSRandom();
        return sr.nextBytes(saltSizeBytes);
    }

    private byte[] generateKeyFromPassword(String password, byte[] salt, int keySizeBytes) {
        try {
            return pbkdf2HmacSha256(password.getBytes(StandardCharsets.UTF_8), salt, keySizeBytes);
        } catch (Exception e) {
            System.err.println("Error while generating key from password: " + e.getMessage());
            return null;
        }
    }

    private byte[] pbkdf2HmacSha256(byte[] password, byte[] salt, int keyLength) throws NoSuchAlgorithmException {
        int hLen = 32; // Output size of SHA-256 in bytes
        int l = (int) Math.ceil((double) keyLength / hLen);
        int r = keyLength - (l - 1) * hLen;

        byte[] derivedKey = new byte[keyLength];
        int destPos = 0;

        for (int i = 1; i <= l; i++) {
            byte[] t = f(password, salt, i);
            int length = (i == l) ? r : hLen;
            System.arraycopy(t, 0, derivedKey, destPos, length);
            destPos += length;
        }
        return derivedKey;
    }

    private byte[] f(byte[] password, byte[] salt, int blockIndex) throws NoSuchAlgorithmException {
        byte[] intBlock = ByteBuffer.allocate(4).putInt(blockIndex).array();
        byte[] saltAndBlock = DataOperator.unionArrays(salt, intBlock);

        byte[] u = hmacSha256(password, saltAndBlock);
        byte[] output = u.clone();

        for (int i = 1; i < KeyGenerator.ITERATIONS; i++) {
            u = hmacSha256(password, u);
            for (int j = 0; j < output.length; j++) {
                output[j] ^= u[j];
            }
        }
        return output;
    }

    private byte[] hmacSha256(byte[] key, byte[] message) throws NoSuchAlgorithmException {
        if (key.length > BLOCK_SIZE) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            key = digest.digest(key);
        }
        if (key.length < BLOCK_SIZE) {
            key = Arrays.copyOf(key, BLOCK_SIZE);
        }

        byte[] oKeyPad = new byte[BLOCK_SIZE];
        byte[] iKeyPad = new byte[BLOCK_SIZE];

        for (int i = 0; i < BLOCK_SIZE; i++) {
            oKeyPad[i] = (byte) (key[i] ^ 0x5c);
            iKeyPad[i] = (byte) (key[i] ^ 0x36);
        }

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        digest.update(iKeyPad);
        byte[] innerHash = digest.digest(message);

        digest.reset();
        digest.update(oKeyPad);
        return digest.digest(innerHash);
    }
}