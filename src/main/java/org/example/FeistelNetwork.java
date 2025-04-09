package org.example;

import javax.crypto.IllegalBlockSizeException;
import java.security.MessageDigest;
import java.util.Arrays;

public class FeistelNetwork {
    private final byte[] KEY;
    private final int ROUNDS = 12;

    public FeistelNetwork(byte[] key) {
        if (key == null || key.length < ROUNDS) {
            throw new IllegalArgumentException("Key must be at least " + ROUNDS + " bytes long");
        }
        this.KEY = key.clone();
        Blowfish.init(KEY);
    }

    public byte[] encryptBlock(byte[] block) throws IllegalBlockSizeException {
        if (block.length != 8) throw new IllegalBlockSizeException("block length must be 8 bytes");

        byte[] left = Arrays.copyOfRange(block, 0, 4);
        byte[] right = Arrays.copyOfRange(block, 4, 8);
        for (int i = 0; i < ROUNDS; i++) {
            byte[] roundKey = generateRoundKey(i);
            byte[] temp = right;
            right = xor(left, encryptFunction(right, roundKey));
            left = temp;
        }
        return unionArrays(left, right);
    }

    public byte[] decryptBlock(byte[] block) throws IllegalBlockSizeException {
        if (block.length != 8) throw new IllegalBlockSizeException("Block length must be 8 bytes");

        byte[] left = Arrays.copyOfRange(block, 0, 4);
        byte[] right = Arrays.copyOfRange(block, 4, 8);

        for (int i = ROUNDS-1; i >= 0; i--) {
            byte[] roundKey = generateRoundKey(i);
            byte[] temp = left;
            left = xor(right, encryptFunction(left, roundKey));
            right = temp;
        }

        return unionArrays(left, right);
    }
    private byte[] encryptFunction(byte[] subblock, byte[] k){
        byte[] blowfishResult = Blowfish.applyF(subblock, k);
        byte[] kuznechikResult = Kuznechik.encrypt(subblock, k);

        return xor(blowfishResult, kuznechikResult);
    }
    //returns 4-byte key
    private byte[] generateRoundKey(int round) {
        byte[] salt = {(byte)0x9E, (byte)0x37, (byte)0x79, (byte)0xC1};
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(KEY);
            md.update(salt);
            md.update((byte) round);
            md.update((byte) (round >> 8));
            md.update((byte) (round >> 16));

            byte[] digest = md.digest();
            return Arrays.copyOf(digest, 4);
        } catch (Exception e) {
            throw new RuntimeException("Key generation failed", e);
        }
    }

    private byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) return null;
        byte[] c = new byte[a.length];
        for (int i = 0; i < c.length; i++) {
            c[i] = (byte) (a[i] ^ b[i]);
        }
        return c;
    }
    private byte[] unionArrays(byte[] a, byte[] b) {
        byte[] combined = new byte[a.length + b.length];
        System.arraycopy(a,0, combined,0, a.length);
        System.arraycopy(b,0, combined, a.length, b.length);
        return combined;
    }
}