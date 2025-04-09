package org.example;

import javax.crypto.IllegalBlockSizeException;
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
    // subblock = k = 32 bits
    private byte[] encryptFunction(byte[] subblock, byte[] k){
        byte[] result = new byte[subblock.length];
        result = Blowfish.applyF(result, k);
        return result;
    }
    private byte[] generateRoundKey(int round) {
        byte[] roundKey = new byte[4];
        for (int i = 0; i < roundKey.length; i++) {
            roundKey[i] = (byte)(KEY[(round + i) % KEY.length] ^ (round * 0x55));
        }
        return roundKey;
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