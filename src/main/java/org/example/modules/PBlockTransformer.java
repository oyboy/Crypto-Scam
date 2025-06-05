package org.example.modules;

public class PBlockTransformer {
    private static final int[] MIX_COLUMNS_MATRIX = {
            0x02, 0x03, 0x01, 0x01,
            0x01, 0x02, 0x03, 0x01,
            0x01, 0x01, 0x02, 0x03,
            0x03, 0x01, 0x01, 0x02
    };

    public static byte[] apply(byte[] data) {
        if (data.length % 64 != 0) {
            throw new IllegalArgumentException("Input must be a multiple of 64 bytes");
        }
        byte[] result = new byte[data.length];
        int numBlocks = data.length / 64;
        for (int blockIndex = 0; blockIndex < numBlocks; blockIndex++) {
            byte[] block = new byte[64];
            System.arraycopy(data, blockIndex * 64, block, 0, 64);

            byte[] transformedBlock = applyBlock(block);
            System.arraycopy(transformedBlock, 0, result, blockIndex * 64, 64);
        }
        return result;
    }

    private static byte[] applyBlock(byte[] block) {
        if (block.length != 64) {
            throw new IllegalArgumentException("Block must be 64 bytes");
        }
        byte[] result = new byte[64];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int val = 0;
                for (int k = 0; k < 4; k++) {
                    val ^= galoisMultiply(block[i * 16 + k] & 0xFF, MIX_COLUMNS_MATRIX[j * 4 + k]);
                }
                result[i * 16 + j] = (byte) val;
            }
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