import org.example.modules.FeistelNetwork;
import org.example.modules.PBlockTransformer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import javax.crypto.IllegalBlockSizeException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class FeistelNetworkTest {

    private FeistelNetwork feistel;
    private final byte[] testKey = "ThisIsASecretKey12341234567890123456890123456789012345678901234567890123".getBytes();
    private final byte[] testBlock = new byte[128];

    @BeforeEach
    void setUp() {
        new SecureRandom().nextBytes(testBlock);
        feistel = new FeistelNetwork(testKey);
    }

    @Test
    void testEncryptDecryptBlock() throws Exception {
        byte[] original = Arrays.copyOf(testBlock, 128);

        byte[] encrypted = feistel.encryptBlock(original);
        byte[] decrypted = feistel.decryptBlock(encrypted);

        assertArrayEquals(original, decrypted, "Decrypted block should match original");
    }

    @Test
    void testEncryptDifferentBlocksProduceDifferentOutput() throws Exception {
        byte[] block1 = new byte[128];
        byte[] block2 = new byte[128];
        new SecureRandom().nextBytes(block1);
        new SecureRandom().nextBytes(block2);

        byte[] encrypted1 = feistel.encryptBlock(block1);
        byte[] encrypted2 = feistel.encryptBlock(block2);

        assertFalse(Arrays.equals(encrypted1, encrypted2),
                "Different blocks should encrypt to different outputs");
    }

    @Test
    void testEncryptSameBlockSameOutput() throws Exception {
        byte[] block = new byte[128];
        new SecureRandom().nextBytes(block);
        byte[] encrypted1 = feistel.encryptBlock(block);
        byte[] encrypted2 = feistel.encryptBlock(block);

        assertArrayEquals(encrypted1, encrypted2,
                "Same block with same key should produce same encrypted output");
    }

    @Test
    void testEncryptAndDecryptSameBlock() throws Exception {
        byte[] block = new byte[128];
        new SecureRandom().nextBytes(block);
        byte[] encrypted = feistel.encryptBlock(block);
        byte[] decrypted = feistel.decryptBlock(encrypted);
        assertArrayEquals(block, decrypted, "Decrypted block should match original");
    }

    @Test
    void testInvalidBlockSize() {
        byte[] shortBlock = new byte[127]; // 1 byte less than required
        byte[] longBlock = new byte[129]; // 1 byte more than required

        assertThrows(IllegalBlockSizeException.class,
                () -> feistel.encryptBlock(shortBlock),
                "Should throw for block smaller than 128 bytes");

        assertThrows(IllegalBlockSizeException.class,
                () -> feistel.encryptBlock(longBlock),
                "Should throw for block larger than 128 bytes");
    }

    @Test
    void testInvalidKeySize() {
        byte[] shortKey = "ShortKey".getBytes();

        assertThrows(IllegalArgumentException.class,
                () -> new FeistelNetwork(shortKey),
                "Should throw for key shorter than required");
    }

    @Test
    void testKeyImmutability() throws IllegalBlockSizeException {
        byte[] mutableKey = new byte[128];
        new SecureRandom().nextBytes(mutableKey);
        FeistelNetwork fn = new FeistelNetwork(mutableKey);
        mutableKey[0] = 'X';

        byte[] testBlock = new byte[128];
        new SecureRandom().nextBytes(testBlock);
        byte[] encrypted1 = fn.encryptBlock(testBlock);
        byte[] encrypted2 = fn.encryptBlock(testBlock);

        assertArrayEquals(encrypted1, encrypted2,
                "Encryption should be immune to external key modifications");
    }

    @Test
    void testEmptyBlock() {
        assertThrows(IllegalBlockSizeException.class,
                () -> feistel.encryptBlock(new byte[0]),
                "Should throw for empty block");
    }

    @Test
    void testNullBlock() {
        assertThrows(NullPointerException.class,
                () -> feistel.encryptBlock(null),
                "Should throw for null block");
    }

    @Test
    void testNullKey() {
        assertThrows(IllegalArgumentException.class,
                () -> new FeistelNetwork(null),
                "Should throw for null key");
    }

    @Test
    void testAllZeroBlock() throws Exception {
        byte[] zeroBlock = new byte[128];
        byte[] encrypted = feistel.encryptBlock(zeroBlock);
        byte[] decrypted = feistel.decryptBlock(encrypted);

        assertArrayEquals(zeroBlock, decrypted,
                "Zero block should decrypt correctly");
        assertFalse(Arrays.equals(zeroBlock, encrypted),
                "Zero block should not encrypt to itself");
    }

    @Test
    void testAllOnesBlock() throws Exception {
        byte[] onesBlock = new byte[128];
        Arrays.fill(onesBlock, (byte)0xFF);

        byte[] encrypted = feistel.encryptBlock(onesBlock);
        byte[] decrypted = feistel.decryptBlock(encrypted);

        assertArrayEquals(onesBlock, decrypted,
                "All ones block should decrypt correctly");
    }

    @Test
    void testPBlockIntegration() {
        byte[] testData = new byte[128];
        new SecureRandom().nextBytes(testData);
        byte[] key = new byte[128];
        new SecureRandom().nextBytes(key);

        byte[] transformed = PBlockTransformer.apply(testData);

        assertFalse(Arrays.equals(testData, transformed));
    }
}