import org.example.Cryptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;

public class CryptorTest {
    private Cryptor cryptor;
    private byte[] key;
    private final String TEST_TEXT = "Hello World! This is a test message 12345";

    @BeforeEach
    void setUp() {
        cryptor = new Cryptor();
        key = "ThisIsAStrongKey1234567890AB".getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void testEncryptDecryptConsistency() {
        String encrypted = cryptor.encrypt(TEST_TEXT, key);
        String decrypted = cryptor.decrypt(encrypted, key);
        assertEquals(TEST_TEXT, decrypted);
    }

    @Test
    void testEmptyString() {
        String empty = null;
        String encrypted = cryptor.encrypt(empty, key);
        String decrypted = cryptor.decrypt(encrypted, key);
        assertEquals(empty, decrypted);
    }

    @Test
    void testDifferentInputsProduceDifferentOutputs() {
        String text1 = "Text 1";
        String text2 = "Text 2";
        String encrypted1 = cryptor.encrypt(text1, key);
        String encrypted2 = cryptor.encrypt(text2, key);
        assertNotEquals(encrypted1, encrypted2);
    }

    @Test
    void testSameInputSameKeySameOutput() {
        String encrypted1 = cryptor.encrypt(TEST_TEXT, key);
        String encrypted2 = cryptor.encrypt(TEST_TEXT, key);
        assertNotEquals(encrypted1, encrypted2);
    }

    @Test
    void testDifferentKeysDifferentOutput() {
        byte[] key2 = "DifferentKey1234567890AB".getBytes(StandardCharsets.UTF_8);
        String encrypted1 = cryptor.encrypt(TEST_TEXT, key);
        String encrypted2 = cryptor.encrypt(TEST_TEXT, key2);
        assertNotEquals(encrypted1, encrypted2);
    }

    @Test
    void testVeryLongText() {
        StringBuilder longText = new StringBuilder();
        longText.append(TEST_TEXT.repeat(10000));
        String encrypted = cryptor.encrypt(longText.toString(), key);
        String decrypted = cryptor.decrypt(encrypted, key);
        assertEquals(longText.toString(), decrypted);
    }

    @Test
    void testSpecialCharacters() {
        String text = "特殊字符 こんにちは привет! @#$%^&*()";
        String encrypted = cryptor.encrypt(text, key);
        String decrypted = cryptor.decrypt(encrypted, key);
        assertEquals(text, decrypted);
    }

    @Test
    void testInvalidKey() {
        byte[] shortKey = "short".getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class, () -> cryptor.encrypt(TEST_TEXT, shortKey));
    }
}