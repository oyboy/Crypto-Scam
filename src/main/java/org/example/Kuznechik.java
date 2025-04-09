package org.example;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class Kuznechik {
    private static final byte[] SBOX = {
            0x0C, 0x04, 0x06, 0x02, 0x0A, 0x05, 0x0B, 0x09,
            0x0E, 0x08, 0x0D, 0x07, 0x01, 0x03, 0x0F, 0x01
    };

    private static final int[] PBOX = {
            5, 2, 11, 8, 15, 6, 9, 12, 3, 0, 13, 10, 7, 4, 1, 14
    };

    public static byte[] encrypt(byte[] data, byte[] key) {
        if (data.length != 4) throw new IllegalArgumentException("Data must be 4 bytes");
        if (key.length != 4) throw new IllegalArgumentException("Key must be 4 bytes");

        byte[] xored = xor(data, key);
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
        byte[] part1 = Arrays.copyOfRange(data, 0, 2);
        byte[] part2 = Arrays.copyOfRange(data, 2, 4);

        part1 = applyPBox(part1);
        part2 = applyPBox(part2);

        return ByteBuffer.allocate(4)
                .put(part1)
                .put(part2)
                .array();
    }

    private static byte[] applyPBox(byte[] twoBytes) {
        if (twoBytes.length != 2) throw new IllegalArgumentException("P-box requires 2 bytes");
        int bits = ((twoBytes[0] & 0xFF) << 8) | (twoBytes[1] & 0xFF);
        int transformed = 0;
        for (int i = 0; i < 16; i++) {
            int bit = (bits >> (15 - PBOX[i])) & 1;
            transformed |= (bit << (15 - i));
        }
        return new byte[] {
                (byte) (transformed >>> 8),
                (byte) transformed
        };
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }
}
