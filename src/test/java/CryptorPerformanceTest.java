import org.example.Cryptor;
import org.example.key.KeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.io.*;
import static org.junit.jupiter.api.Assertions.*;

class CryptorPerformanceTest {
    private static final int MINIMUM_SPEED_MBPS = 10;
    private static final String PATH = "test-files/";
    private static final String[] TEST_FILES = {"profile.json", "empty", "test.txt", "image.jpg", "kino.mp3"};

    private Cryptor encryptor;
    private byte[] testKey;

    @BeforeEach
    void setUp() {
        encryptor = new Cryptor();
        testKey = new KeyGenerator().generateKey("pass", "salt".getBytes(), 256 / 8);
    }

    @Test
    void testAllFilesEncryptionSpeed() throws Exception {
        for (String filename : TEST_FILES) {
            File input = new File(PATH + filename);
            if (!input.exists()) continue;
            if (input.length() < 1024) {
                System.out.println(filename + " is too small for speed test, skipping.");
                continue;
            }
            long sizeKB = input.length() / 1024;
            long start = System.nanoTime();

            encryptor.encryptFile(input, new File(PATH + "enc_" + filename), testKey, "salt".getBytes());

            double speedKBps = sizeKB / ((System.nanoTime() - start) / 1e9);
            double speedMbps = (speedKBps * 8) / 1000;
            System.out.printf("%s - %.2f Mbps%n", filename, speedMbps);

            new File(PATH + "enc_" + filename).delete();
            assertTrue(speedMbps >= MINIMUM_SPEED_MBPS,
                    String.format("%s: %.2f Mbps < %d Mbps", filename, speedMbps, MINIMUM_SPEED_MBPS));
        }
    }

    @Test
    void testAllFilesDecryptionSpeed() throws Exception {
        for (String filename : TEST_FILES) {
            File original = new File(PATH + filename);
            if (!original.exists()) continue;
            if (original.length() < 1024) {
                System.out.println(filename + " is too small for speed test, skipping.");
                continue;
            }
            File encrypted = new File(PATH + "enc_" + filename);
            encryptor.encryptFile(original, encrypted, testKey, new KeyGenerator().generateSalt(128 / 8));

            long sizeKB = encrypted.length() / 1024;
            long start = System.nanoTime();
            encryptor.decryptFile(encrypted, new File(PATH + "dec_" + filename), testKey);

            double speedKBps = sizeKB / ((System.nanoTime() - start) / 1e9);
            double speedMbps = (speedKBps * 8) / 1000;
            System.out.printf("%s - %.2f Mbps%n", filename, speedMbps);

            encrypted.delete();
            new File(PATH + "dec_" + filename).delete();
            assertTrue(speedMbps >= MINIMUM_SPEED_MBPS,
                    String.format("%s: %.2f Mbps < %d Mbps", filename, speedMbps, MINIMUM_SPEED_MBPS));
        }
    }
}