import org.example.Cryptor;
import org.example.key.KeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class CryptorHeavyPerfomanceTest {
    private static final int MINIMUM_SPEED_KBPS = 250;
    private Cryptor encryptor;
    private byte[] testKey;

    @BeforeEach
    void setUp() {
        encryptor = new Cryptor();
        testKey = new KeyGenerator().generateKeyFromPassword("pass",
                new KeyGenerator().generateSalt(32), 256/8);
    }

    @Test
    void testLargeFileEncryptionDecryption() throws Exception {
        File largeFile = new File("test-files-heavy/ET.mp4");
        File encrypted = new File("test-files-heavy/ET_enc.mp4");
        File decrypted = new File("test-files-heavy/ET_dec.mp4");

        byte[] salt = new KeyGenerator().generateSalt(16);

        long sizeKB = largeFile.length() / 1024;

        // Encryption
        long start = System.nanoTime();
        encryptor.encryptFile(largeFile, encrypted, testKey, salt);
        double encryptSpeed = sizeKB / ((System.nanoTime() - start) / 1e9);
        System.out.printf("Large file encryption speed: %.2f KB/s%n", encryptSpeed);

        // Decryption
        start = System.nanoTime();
        encryptor.decryptFile(encrypted, decrypted, testKey);
        double decryptSpeed = sizeKB / ((System.nanoTime() - start) / 1e9);
        System.out.printf("Large file decryption speed: %.2f KB/s%n", decryptSpeed);

        encrypted.delete();
        decrypted.delete();

        assertTrue(encryptSpeed >= MINIMUM_SPEED_KBPS,
                String.format("Encryption speed %.2f KB/s < %d KB/s", encryptSpeed, MINIMUM_SPEED_KBPS));
        assertTrue(decryptSpeed >= MINIMUM_SPEED_KBPS,
                String.format("Decryption speed %.2f KB/s < %d KB/s", decryptSpeed, MINIMUM_SPEED_KBPS));
    }

    @Test
    void testDirectoryWithManySmallFilesEncryptionDecryption() throws Exception {
        Path dir = Paths.get("test-files-heavy/many-small");
        assertTrue(Files.exists(dir), "Test directory does not exist: " + dir);

        List<Path> files = Files.walk(dir)
                .filter(Files::isRegularFile)
                .toList();

        List<String> failures = new ArrayList<>();
        long totalSizeKB = 0;
        long start = System.nanoTime();

        for (Path file : files) {
            File input = file.toFile();
            try {
                byte[] salt = new KeyGenerator().generateSalt(16);
                File encrypted = new File(input.getParent(), "enc_" + input.getName());

                encryptor.encryptFile(input, encrypted, testKey, salt);
                totalSizeKB += input.length() / 1024;

                File decrypted = new File(input.getParent(), "dec_" + input.getName());
                encryptor.decryptFile(encrypted, decrypted, testKey);

                encrypted.delete();
                decrypted.delete();
            } catch (Exception e) {
                failures.add(String.format("Failed for file: %s - %s\n%s",
                        file.getFileName(),
                        file.getParent(),
                        e.getMessage()
                ));
            }
        }

        double elapsedSeconds = (System.nanoTime() - start) / 1e9;
        double speed = totalSizeKB / elapsedSeconds;

        System.out.printf("Directory encryption+decryption speed: %.2f KB/s%n", speed);

        if (speed < MINIMUM_SPEED_KBPS) {
            failures.add(String.format("Total speed %.2f KB/s < %d KB/s", speed, MINIMUM_SPEED_KBPS));
        }

        if (!failures.isEmpty()) {
            fail("Some files failed:\n" + String.join("\n", failures));
        }
    }
}
