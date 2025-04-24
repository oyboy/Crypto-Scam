import org.example.Cryptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class CryptorTest {
    private Cryptor cryptor;
    private byte[] key;
    private final byte[] TEST_TEXT = "Hello World! This is a test message 12345".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() {
        cryptor = new Cryptor();
        key = "ThisIsAStrongKey1234567890AB".getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void testEncryptDecryptConsistency() {
        byte[] encrypted = cryptor.encrypt(TEST_TEXT, key);
        byte[] decrypted = cryptor.decrypt(encrypted, key);
        assertArrayEquals(TEST_TEXT, decrypted);
    }

    @Test
    void testEmptyArray() {
        byte[] empty = new byte[0];
        byte[] encrypted = cryptor.encrypt(empty, key);
        byte[] decrypted = cryptor.decrypt(encrypted, key);
        assertArrayEquals(empty, decrypted);
    }

    @Test
    void testDifferentInputsProduceDifferentOutputs() {
        byte[] text1 = "Text 1".getBytes(StandardCharsets.UTF_8);
        byte[] text2 = "Text 2".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted1 = cryptor.encrypt(text1, key);
        byte[] encrypted2 = cryptor.encrypt(text2, key);
        assertNotEquals(Arrays.toString(encrypted1), Arrays.toString(encrypted2));
    }

    @Test
    void testSameInputSameKeyDifferentOutput() {
        byte[] encrypted1 = cryptor.encrypt(TEST_TEXT, key);
        byte[] encrypted2 = cryptor.encrypt(TEST_TEXT, key);
        assertNotEquals(Arrays.toString(encrypted1), Arrays.toString(encrypted2));
    }

    @Test
    void testDifferentKeysDifferentOutput() {
        byte[] key2 = "DifferentKey1234567890AB".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted1 = cryptor.encrypt(TEST_TEXT, key);
        byte[] encrypted2 = cryptor.encrypt(TEST_TEXT, key2);
        assertNotEquals(Arrays.toString(encrypted1), Arrays.toString(encrypted2));
    }

    @Test
    void testVeryLongText() {
        StringBuilder longText = new StringBuilder();
        longText.append(new String(TEST_TEXT, StandardCharsets.UTF_8).repeat(10000));
        byte[] encrypted = cryptor.encrypt(longText.toString().getBytes(StandardCharsets.UTF_8), key);
        byte[] decrypted = cryptor.decrypt(encrypted, key);
        assertArrayEquals(longText.toString().getBytes(StandardCharsets.UTF_8), decrypted);
    }

    @Test
    void testSpecialCharacters() {
        String text = "特殊字符 こんにちは привет! @#$%^&*()";
        byte[] encrypted = cryptor.encrypt(text.getBytes(StandardCharsets.UTF_8), key);
        byte[] decrypted = cryptor.decrypt(encrypted, key);
        assertArrayEquals(text.getBytes(StandardCharsets.UTF_8), decrypted);
    }

    @Test
    void testInvalidKey() {
        byte[] shortKey = "short".getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class, () -> cryptor.encrypt(TEST_TEXT, shortKey));
    }
}