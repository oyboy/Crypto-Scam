package org.example;

public class PBlockTransformer {
    private static final int[] MIX_COLUMNS_MATRIX = {
            0x02, 0x03, 0x01, 0x01,
            0x01, 0x02, 0x03, 0x01,
            0x01, 0x01, 0x02, 0x03,
            0x03, 0x01, 0x01, 0x02
    };

    public static byte[] apply(byte[] data) {
        if (data.length != 4) throw new IllegalArgumentException("Input must be 4 bytes");

        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++) {
            int val = 0;
            for (int j = 0; j < 4; j++) {
                val ^= galoisMultiply(data[j] & 0xFF, MIX_COLUMNS_MATRIX[i*4 + j]);
            }
            result[i] = (byte) val;
        }
        return result;
    }

    private static int galoisMultiply(int a, int b) {
        int p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                p ^= a;
            }
            boolean hiBit = (a & 0x80) != 0;
            a <<= 1;
            if (hiBit) {
                a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1
            }
            b >>= 1;
        }
        return p;
    }
}