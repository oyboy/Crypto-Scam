import org.example.KeyGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class KeyGeneratorTest {
    private static final long TIME = 200L;
    @Test
    void testGenerateRandomKey_lengthIs32Bytes() {
        byte[] key = new KeyGenerator().generateRandomKey(32);
        assertEquals(32, key.length, "Длина ключа должна быть 32 байта (256 бит)");
    }
    @Test
    void testGenerateRandomKey_fasterThanTimems() {
        long startTime = System.currentTimeMillis();
        byte[] key = new KeyGenerator().generateRandomKey(32);
        long duration = System.currentTimeMillis() - startTime;
        assertTrue(duration < TIME, "Генерация ключа должна занимать <200 мс");
    }
    @Test
    void testGenerateKeyFromPassword_lengthIs32Bytes() throws Exception {
        byte[] key = new KeyGenerator().generateKeyFromPassword(
                "password123", 32
        );
        assertEquals(32, key.length, "Длина ключа должна быть 32 байта (256 бит)");
    }
    @Test
    void testGenerateKeyFromPassword_fasterThanTimems() throws Exception {
        long startTime = System.currentTimeMillis();
        byte[] key = new KeyGenerator().generateKeyFromPassword(
                "password123",32
        );
        long duration = System.currentTimeMillis() - startTime;
        assertTrue(duration < TIME, "Генерация ключа должна занимать <200 мс");
    }
}