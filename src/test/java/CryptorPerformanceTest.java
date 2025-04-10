import org.example.Cryptor;
import org.example.KeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.io.*;
import static org.junit.jupiter.api.Assertions.*;

class CryptorPerformanceTest {
    private static final int MINIMUM_SPEED_KBPS = 250;
    private static final String[] TEST_FILES = {"test-files/document.txt"};

    private Cryptor encryptor;
    private KeyGenerator keyGenerator;
    private byte[] testKey;

    @BeforeEach
    void setUp() {
        encryptor = new Cryptor();
        keyGenerator = new KeyGenerator();
        testKey = keyGenerator.generateRandomKey(256/8);
    }

    @Test
    void testAllFilesEncryptionSpeed() throws Exception {
        for (String filename : TEST_FILES) {
            File input = new File(filename);
            if (!input.exists()) continue;

            long sizeKB = input.length() / 1024;
            long start = System.nanoTime();
            encryptor.encryptFile(input, new File("enc_" + filename), testKey);
            double speed = sizeKB / ((System.nanoTime() - start) / 1e9);
            System.out.printf("%s - %.2f KB/s%n", filename, speed);

            new File("enc_" + filename).delete();
            assertTrue(speed >= MINIMUM_SPEED_KBPS,
                    String.format("%s: %.2f KB/s < %d KB/s", filename, speed, MINIMUM_SPEED_KBPS));
        }
    }

    @Test
    void testAllFilesDecryptionSpeed() throws Exception {
        for (String filename : TEST_FILES) {
            File original = new File(filename);
            if (!original.exists()) continue;

            File encrypted = new File("enc_" + filename);
            encryptor.encryptFile(original, encrypted, testKey);

            long sizeKB = encrypted.length() / 1024;
            long start = System.nanoTime();
            encryptor.decryptFile(encrypted, new File("dec_" + filename), testKey);

            double speed = sizeKB / ((System.nanoTime() - start) / 1e9);
            System.out.printf("%s - %.2f KB/s%n", filename, speed);

            encrypted.delete();
            new File("dec_" + filename).delete();
            assertTrue(speed >= MINIMUM_SPEED_KBPS,
                    String.format("%s: %.2f KB/s < %d KB/s", filename, speed, MINIMUM_SPEED_KBPS));
        }
    }

}
