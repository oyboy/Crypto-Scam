import org.example.FeistelNetwork;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class FeistelNetworkAvalancheTest {
    private FeistelNetwork feistel;
    private static final byte[] TEST_KEY = "ThisIsASecretKey1234".getBytes();

    @BeforeEach
    void setUp() {
        feistel = new FeistelNetwork(TEST_KEY);
    }

    private int countDifferentBits(byte[] a, byte[] b) {
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            int xor = a[i] ^ b[i];
            while (xor != 0) {
                diff += xor & 1;
                xor >>>= 1;
            }
        }
        return diff;
    }
    private byte[] flipBit(byte[] input, int bitPos) {
        byte[] modified = input.clone();
        int bytePos = bitPos / 8;
        int bitInByte = bitPos % 8;
        modified[bytePos] ^= (1 << bitInByte);
        return modified;
    }

    @Test
    void test10PercentAvalanche() throws Exception {
        byte[] original = new byte[8];
        int changedBitsTotal = 0;
        int tests = 0;

        for (int bitPos = 0; bitPos < 6; bitPos++) {
            byte[] modified = flipBit(original, bitPos);
            byte[] encOriginal = feistel.encryptBlock(original);
            byte[] encModified = feistel.encryptBlock(modified);

            int diffBits = countDifferentBits(encOriginal, encModified);
            changedBitsTotal += diffBits;
            tests++;

            assertTrue(diffBits > 10, "Изменение бита "+bitPos+" вызвало только "+diffBits+" изменений");
        }

        double avgChanged = (double)changedBitsTotal / tests;
        assertTrue(avgChanged > 20, "Среднее изменение битов слишком низкое: " + avgChanged);
    }

    @Test
    void test30PercentAvalanche() throws Exception {
        byte[] original = new byte[8];
        int changedBitsTotal = 0;
        int tests = 0;

        for (int bitPos = 0; bitPos < 20; bitPos += 3) {
            byte[] modified = flipBit(original, bitPos);
            byte[] encOriginal = feistel.encryptBlock(original);
            byte[] encModified = feistel.encryptBlock(modified);

            int diffBits = countDifferentBits(encOriginal, encModified);
            changedBitsTotal += diffBits;
            tests++;

            assertTrue(diffBits > 15, "Изменение бита "+bitPos+" вызвало только "+diffBits+" изменений");
        }

        double avgChanged = (double)changedBitsTotal / tests;
        assertTrue(avgChanged > 25, "Среднее изменение битов слишком низкое: " + avgChanged);
    }

    @Test
    void test50PercentAvalanche() throws Exception {
        byte[] original = new byte[8];
        int changedBitsTotal = 0;
        int tests = 0;

        for (int bitPos = 0; bitPos < 32; bitPos += 2) {
            byte[] modified = flipBit(original, bitPos);
            byte[] encOriginal = feistel.encryptBlock(original);
            byte[] encModified = feistel.encryptBlock(modified);

            int diffBits = countDifferentBits(encOriginal, encModified);
            changedBitsTotal += diffBits;
            tests++;

            assertTrue(diffBits > 20, "Изменение бита "+bitPos+" вызвало только "+diffBits+" изменений");
        }

        double avgChanged = (double)changedBitsTotal / tests;
        assertTrue(avgChanged > 30, "Среднее изменение битов слишком низкое: " + avgChanged);
    }

    @Test
    void test70PercentAvalanche() throws Exception {
        byte[] original = new byte[8];
        int changedBitsTotal = 0;
        int tests = 0;

        for (int bitPos = 0; bitPos < 45; bitPos += 1) {
            byte[] modified = flipBit(original, bitPos);
            byte[] encOriginal = feistel.encryptBlock(original);
            byte[] encModified = feistel.encryptBlock(modified);

            int diffBits = countDifferentBits(encOriginal, encModified);
            changedBitsTotal += diffBits;
            tests++;

            assertTrue(diffBits > 25, "Изменение бита "+bitPos+" вызвало только "+diffBits+" изменений");
        }

        double avgChanged = (double)changedBitsTotal / tests;
        assertTrue(avgChanged > 35, "Среднее изменение битов слишком низкое: " + avgChanged);
        System.out.println("70% avalanche - среднее изменение битов: " + avgChanged);
    }

    @Test
    void testFullAvalanche() throws Exception {
        byte[] original = new byte[8];
        byte[] modified = flipBit(original, 0);
        byte[] encOriginal = feistel.encryptBlock(original);
        byte[] encModified = feistel.encryptBlock(modified);

        int diffBits = countDifferentBits(encOriginal, encModified);
        System.out.println("Лавинный эффект (1 бит изменений): " + diffBits + " бит");

        assertTrue(diffBits > 25, "Лавинный эффект недостаточен: только " + diffBits + " бит изменилось");
    }
}