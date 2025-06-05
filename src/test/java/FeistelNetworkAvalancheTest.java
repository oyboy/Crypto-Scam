import org.example.modules.FeistelNetwork;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class FeistelNetworkAvalancheTest {
    private FeistelNetwork feistel;
    private static final byte[] TEST_KEY = new byte[64];
    private static final int BLOCK_SIZE = 128;
    private static final double MIN_AVALANCHE_PERCENT = 10.0;

    @BeforeEach
    void setUp() {
        new SecureRandom().nextBytes(TEST_KEY);
        feistel = new FeistelNetwork(TEST_KEY);
    }

    private int countDifferentBits(byte[] a, byte[] b) {
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff += Integer.bitCount(a[i] ^ b[i]);
        }
        return diff;
    }

    @Test
    void testAvalancheEffect() throws Exception {
        byte[] original = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(original);

        int totalBits = BLOCK_SIZE * 8;
        int sampleBits = 10;
        int passedTests = 0;

        for (int i = 0; i < sampleBits; i++) {
            int bitPos = i * (totalBits / sampleBits);
            byte[] modified = flipBit(original, bitPos);

            byte[] encOriginal = feistel.encryptBlock(original);
            byte[] encModified = feistel.encryptBlock(modified);

            int diffBits = countDifferentBits(encOriginal, encModified);
            double changedPercentage = 100.0 * diffBits / totalBits;

            System.out.printf("Bit %4d changed: %.2f%% of output bits%n",
                    bitPos, changedPercentage);

            if (changedPercentage >= MIN_AVALANCHE_PERCENT) {
                passedTests++;
            }
        }

        double passRate = 100.0 * passedTests / sampleBits;
        System.out.printf("Avalanche effect pass rate: %.1f%% (%d/%d)%n",
                passRate, passedTests, sampleBits);

        assertTrue(passRate >= 50.0,
                "Avalanche effect should be observed in at least 50% of cases");
    }

    @Test
    void testAvalancheStatistics() throws Exception {
        byte[] original = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(original);

        int totalBits = BLOCK_SIZE * 8;
        int tests = 20;
        int totalChangedBits = 0;

        for (int i = 0; i < tests; i++) {
            int bitPos = i * (totalBits / tests);
            byte[] modified = flipBit(original, bitPos);

            byte[] encOriginal = feistel.encryptBlock(original);
            byte[] encModified = feistel.encryptBlock(modified);

            totalChangedBits += countDifferentBits(encOriginal, encModified);
        }

        double avgChangedPercentage = 100.0 * totalChangedBits / (tests * totalBits);
        System.out.printf("Average avalanche effect: %.2f%%%n", avgChangedPercentage);

        if (avgChangedPercentage < 20.0) {
            System.err.println("WARNING: Weak avalanche effect detected!");
        }
    }

    private byte[] flipBit(byte[] input, int bitPos) {
        byte[] modified = input.clone();
        int bytePos = bitPos / 8;
        int bitInByte = bitPos % 8;
        modified[bytePos] ^= (1 << bitInByte);
        return modified;
    }
}