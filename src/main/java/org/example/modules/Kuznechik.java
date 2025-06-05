package org.example.modules;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static org.example.util.DataOperator.xor;

public class Kuznechik {
    private static final byte[] SBOX = {
            0x0C, 0x04, 0x06, 0x02, 0x0A, 0x05, 0x0B, 0x09,
            0x0E, 0x08, 0x0D, 0x07, 0x01, 0x03, 0x0F, 0x01
    };

    private static final int[] PBOX = {
            5, 2, 11, 8, 15, 6, 9, 12, 3, 0, 13, 10, 7, 4, 1, 14,
            21, 18, 27, 24, 31, 22, 25, 28, 19, 16, 29, 26, 23, 20, 17, 30,
            37, 34, 43, 40, 47, 38, 41, 44, 35, 32, 45, 42, 39, 36, 33, 46,
            53, 50, 59, 56, 63, 54, 57, 60, 51, 48, 61, 58, 55, 52, 49, 62
    };
    private static final int BLOCK_SIZE = 64;
    private static final int KEY_SIZE = 8;

    public static byte[] encrypt(byte[] data, byte[] key) {
        if (data.length != BLOCK_SIZE) throw new IllegalArgumentException("Data must be " + BLOCK_SIZE + " bytes");
        if (key.length != KEY_SIZE) throw new IllegalArgumentException("Key must be " + KEY_SIZE + " bytes");
        byte[] expandedKey = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            expandedKey[i] = key[i % KEY_SIZE];
        }
        byte[] xored = xor(data, expandedKey);
        byte[] sboxed = applySBox(xored);
        return applyLinearTransformation(sboxed);
    }

    private static byte[] applySBox(byte[] data) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            int highNibble = (data[i] >>> 4) & 0x0F;
            int lowNibble = data[i] & 0x0F;
            result[i] = (byte) ((SBOX[highNibble] << 4) | SBOX[lowNibble]);
        }
        return result;
    }

    private static byte[] applyLinearTransformation(byte[] data) {
        byte[][] parts = new byte[8][8];
        for (int i = 0; i < 8; i++) {
            parts[i] = Arrays.copyOfRange(data, i * 8, (i + 1) * 8);
        }
        for (int i = 0; i < 8; i++) {
            parts[i] = applyPBox(parts[i]);
        }
        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
        for (byte[] part : parts) {
            buffer.put(part);
        }
        return buffer.array();
    }

    private static byte[] applyPBox(byte[] eightBytes) {
        if (eightBytes.length != 8) throw new IllegalArgumentException("P-box requires 8 bytes");
        long bits = ByteBuffer.wrap(eightBytes).getLong();
        long transformed = 0;

        for (int i = 0; i < 64; i++) {
            int bitPos = 63 - PBOX[i % PBOX.length];
            long bit = (bits >> bitPos) & 1;
            transformed |= (bit << (63 - i));
        }
        return ByteBuffer.allocate(8).putLong(transformed).array();
    }
}