import org.example.key.KeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class KeyGeneratorTest {
    @Test
    void testGenerateKeyFromPassword_isDeterministic() {
        KeyGenerator generator = new KeyGenerator();
        String password = "myPassword";
        byte[] salt = "mySalt".getBytes();

        byte[] key1 = generator.generateKey(password, salt, 32);
        byte[] key2 = generator.generateKey(password, salt, 32);

        assertArrayEquals(key1, key2, "Ключи при одинаковом пароле и соли должны совпадать");
    }
    @Test
    void testGenerateKeyFromPassword_differentSaltProducesDifferentKeys() {
        KeyGenerator generator = new KeyGenerator();
        String password = "myPassword";
        byte[] salt1 = "saltOne".getBytes();
        byte[] salt2 = "saltTwo".getBytes();

        byte[] key1 = generator.generateKey(password, salt1, 32);
        byte[] key2 = generator.generateKey(password, salt2, 32);

        assertFalse(Arrays.equals(key1, key2), "Ключи при разных солях должны отличаться");
    }
    @Test
    void testGenerateKeyFromPassword_differentPasswordProducesDifferentKeys() {
        KeyGenerator generator = new KeyGenerator();
        byte[] salt = "constantSalt".getBytes();

        byte[] key1 = generator.generateKey("pass1", salt, 32);
        byte[] key2 = generator.generateKey("pass2", salt, 32);

        assertFalse(Arrays.equals(key1, key2), "Ключи при разных паролях должны отличаться");
    }
    @Timeout(value = 1)
    @Test
    void testGenerateKeyFromPassword_completesInReasonableTime() {
        byte[] key = new KeyGenerator().generateKey("password", "salt".getBytes(), 32);
        assertEquals(32, key.length);
    }
}