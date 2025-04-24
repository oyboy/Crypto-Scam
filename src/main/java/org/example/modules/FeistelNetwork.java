package org.example.modules;

import javax.crypto.IllegalBlockSizeException;
import java.security.MessageDigest;
import java.util.Arrays;

import static org.example.util.DataOperator.unionArrays;
import static org.example.util.DataOperator.xor;

public class FeistelNetwork {
    private final byte[] KEY;
    private final int ROUNDS = 12;
    private final Blowfish blowfish;

    public FeistelNetwork(byte[] key) {
        if (key == null || key.length < ROUNDS) {
            throw new IllegalArgumentException("Key must be at least " + ROUNDS + " bytes long");
        }
        this.KEY = key.clone();
        this.blowfish = new Blowfish(key);
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
        byte[] k1 = Arrays.copyOfRange(k, 0, k.length/2);
        byte[] k2 = Arrays.copyOfRange(k, k.length/2, k.length);

        byte[] blowfishResult = blowfish.applyF(subblock, k1);
        byte[] kuznechikResult = Kuznechik.encrypt(subblock, k2);

        byte[] combined = xor(blowfishResult, kuznechikResult);
        return PBlockTransformer.apply(combined);
    }
    //returns 8-byte key
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
            return Arrays.copyOf(digest, 8);
        } catch (Exception e) {
            throw new RuntimeException("Key generation failed", e);
        }
    }
}