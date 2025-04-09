import org.example.FeistelNetwork;
import org.example.PBlockTransformer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import javax.crypto.IllegalBlockSizeException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class FeistelNetworkTest {

    private FeistelNetwork feistel;
    private final byte[] testKey = "ThisIsASecretKey1234".getBytes();
    private final byte[] testBlock = "TestBlock".getBytes();

    @BeforeEach
    void setUp() {
        feistel = new FeistelNetwork(testKey);
    }

    @Test
    void testEncryptDecryptBlock() throws Exception {
        byte[] original = Arrays.copyOfRange(testBlock, 0, 8);

        byte[] encrypted = feistel.encryptBlock(original);
        byte[] decrypted = feistel.decryptBlock(encrypted);

        assertArrayEquals(original, decrypted, "Decrypted block should match original");
    }

    @Test
    void testEncryptDifferentBlocksProduceDifferentOutput() throws Exception {
        byte[] block1 = "BlockOne".getBytes();
        byte[] block2 = "BlockTwo".getBytes();

        byte[] encrypted1 = feistel.encryptBlock(block1);
        byte[] encrypted2 = feistel.encryptBlock(block2);

        assertFalse(Arrays.equals(encrypted1, encrypted2),
                "Different blocks should encrypt to different outputs");
    }

    @Test
    void testEncryptSameBlockSameOutput() throws Exception {
        byte[] block = "SameBloc".getBytes();
        byte[] encrypted1 = feistel.encryptBlock(block);
        byte[] encrypted2 = feistel.encryptBlock(block);

        assertArrayEquals(encrypted1, encrypted2,
                "Same block with same key should produce same encrypted output");
    }

    @Test
    void testInvalidBlockSize() {
        byte[] shortBlock = "Short".getBytes();
        byte[] longBlock = "ThisBlockIsTooLong".getBytes();

        assertThrows(IllegalBlockSizeException.class,
                () -> feistel.encryptBlock(shortBlock),
                "Should throw for block smaller than 8 bytes");

        assertThrows(IllegalBlockSizeException.class,
                () -> feistel.encryptBlock(longBlock),
                "Should throw for block larger than 8 bytes");
    }

    @Test
    void testInvalidKeySize() {
        byte[] shortKey = "ShortKey".getBytes();

        assertThrows(IllegalArgumentException.class,
                () -> new FeistelNetwork(shortKey),
                "Should throw for key shorter than ROUNDS bytes");
    }

    @Test
    void testKeyImmutability() throws IllegalBlockSizeException {
        byte[] mutableKey = "MutableKey1234567890".getBytes();
        FeistelNetwork fn = new FeistelNetwork(mutableKey);
        mutableKey[0] = 'X';

        byte[] testBlock = "TestBlok".getBytes();
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
        byte[] zeroBlock = new byte[8];
        byte[] encrypted = feistel.encryptBlock(zeroBlock);
        byte[] decrypted = feistel.decryptBlock(encrypted);

        assertArrayEquals(zeroBlock, decrypted,
                "Zero block should decrypt correctly");
        assertFalse(Arrays.equals(zeroBlock, encrypted),
                "Zero block should not encrypt to itself");
    }

    @Test
    void testAllOnesBlock() throws Exception {
        byte[] onesBlock = new byte[8];
        Arrays.fill(onesBlock, (byte)0xFF);

        byte[] encrypted = feistel.encryptBlock(onesBlock);
        byte[] decrypted = feistel.decryptBlock(encrypted);

        assertArrayEquals(onesBlock, decrypted,
                "All ones block should decrypt correctly");
    }
    @Test
    void testPBlockIntegration() {
        byte[] testData = {0x00, 0x11, 0x22, 0x33};
        byte[] key = new byte[8];
        new SecureRandom().nextBytes(key);

        byte[] transformed = PBlockTransformer.apply(testData);

        assertFalse(Arrays.equals(testData, transformed));
        assertNotEquals(0x00, transformed[0] & 0xFF);
        assertNotEquals(0x11, transformed[1] & 0xFF);
    }
}