import org.example.ConfigManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class ConfigManagerTest {
    private static final String TEST_CONFIG_PATH = System.getProperty("user.home") + "/.secures/main.conf";
    private static final String TEST_PATH = "/test/path";
    private static final String TEST_PASSWORD = "securePassword123";

    @BeforeAll
    static void setup() throws IOException {
        Files.deleteIfExists(Paths.get(TEST_CONFIG_PATH));
        Files.createDirectories(Paths.get(System.getProperty("user.home") + "/.secures"));
    }

    @AfterEach
    void cleanup() throws IOException {
        ConfigManager.clearCache();
        Files.deleteIfExists(Paths.get(TEST_CONFIG_PATH));
    }

    @Test
    @DisplayName("Инициализация конфига для пути")
    void testInitConfigForPath() throws Exception {
        ConfigManager.initConfigForPath(TEST_PATH, TEST_PASSWORD);

        assertTrue(Files.exists(Paths.get(TEST_CONFIG_PATH)));
        String configContent = Files.readString(Paths.get(TEST_CONFIG_PATH));
        assertTrue(configContent.contains("|salt="));
        assertTrue(configContent.contains("|verifier="));
    }

    @Test
    @DisplayName("Успешное получение ключа для пути")
    void testGetKeyForPath_Success() throws Exception {
        ConfigManager.initConfigForPath(TEST_PATH, TEST_PASSWORD);

        byte[] key = ConfigManager.getKeyForPath(TEST_PATH, TEST_PASSWORD);

        assertNotNull(key);
        assertEquals(64, key.length);
    }

    @Test
    @DisplayName("Неверный пароль вызывает исключение")
    void testGetKeyForPath_WrongPassword() throws Exception {
        ConfigManager.initConfigForPath(TEST_PATH, TEST_PASSWORD);

        assertThrows(SecurityException.class, () -> {
            ConfigManager.getKeyForPath(TEST_PATH, "wrongPassword");
        });
    }

    @Test
    @DisplayName("Несуществующий путь вызывает IOException")
    void testGetKeyForPath_NotExists() {
        assertThrows(IOException.class, () -> {
            ConfigManager.getKeyForPath("/non/existent/path", TEST_PASSWORD);
        });
    }

    @Test
    @DisplayName("Кеширование ключей работает корректно")
    void testKeyCaching() throws Exception {
        ConfigManager.initConfigForPath(TEST_PATH, TEST_PASSWORD);

        byte[] key1 = ConfigManager.getKeyForPath(TEST_PATH, TEST_PASSWORD);
        byte[] key2 = ConfigManager.getKeyForPath(TEST_PATH, TEST_PASSWORD);

        assertNotSame(key1, key2);
        assertArrayEquals(key1, key2);
    }

    @Test
    @DisplayName("Очистка кеша работает корректно")
    void testClearCache() throws Exception {
        ConfigManager.initConfigForPath(TEST_PATH, TEST_PASSWORD);
        byte[] key = ConfigManager.getKeyForPath(TEST_PATH, TEST_PASSWORD);

        ConfigManager.clearCache();

        byte[] zeroKey = new byte[64];
        Arrays.fill(zeroKey, (byte) 0);
        assertArrayEquals(zeroKey, key);
    }

    @Test
    @DisplayName("Генерация configId детерминирована")
    void testGenerateConfigId() {
        String path1 = "/test/path";
        String path2 = "/test/path";
        String path3 = "/different/path";

        String id1 = ConfigManager.generateConfigId(path1);
        String id2 = ConfigManager.generateConfigId(path2);
        String id3 = ConfigManager.generateConfigId(path3);

        assertEquals(id1, id2);
        assertNotEquals(id1, id3);
        assertEquals(16, id1.length());
    }
}
