package org.example;

import org.example.key.KeyVerifier;
import org.example.modules.FeistelNetwork;
import org.example.util.BBSRandom;

import javax.crypto.IllegalBlockSizeException;
import java.io.*;
import java.util.Arrays;
import static org.example.util.DataOperator.*;

public class Cryptor {
    private static final int BLOCK_SIZE = 128;
    private static final int VERIFIER_SIZE = 32;
    private static final int SALT_SIZE = 16;

    private final BBSRandom bbsRandom = new BBSRandom();
    private long lastUpdateTime = 0;

    private byte[] addPadding(byte[] input) {
        int paddingLength = BLOCK_SIZE - (input.length % BLOCK_SIZE);
        byte[] padded = Arrays.copyOf(input, input.length + paddingLength);
        Arrays.fill(padded, input.length, padded.length, (byte) paddingLength);
        return padded;
    }

    private byte[] removePadding(byte[] input) {
        if (input.length == 0) throw new IllegalArgumentException("Unexpected end of block");

        int paddingLength = input[input.length - 1] & 0xFF;
        if (paddingLength <= 0 || paddingLength > BLOCK_SIZE) {
            throw new IllegalArgumentException("Invalid padding");
        }
        return Arrays.copyOf(input, input.length - paddingLength);
    }

    private byte[] createInitVector() {
        return bbsRandom.nextBytes(BLOCK_SIZE);
    }

    public byte[] encrypt(byte[] input, byte[] key) {
        if (input == null || input.length == 0) {
            System.err.println("Input is empty");
            return new byte[0];
        }

        FeistelNetwork feistel = new FeistelNetwork(key);
        byte[] paddedInput = addPadding(input);
        byte[] iv = createInitVector();

        byte[] encrypted = new byte[paddedInput.length];
        byte[] prev = iv.clone();

        for (int i = 0; i < paddedInput.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(paddedInput, i, i + BLOCK_SIZE);
            byte[] xored = xor(block, prev);
            try {
                byte[] encryptedBlock = feistel.encryptBlock(xored);
                System.arraycopy(encryptedBlock, 0, encrypted, i, BLOCK_SIZE);
                prev = encryptedBlock;
            } catch (IllegalBlockSizeException e) {
                System.err.println("Illegal block size: " + e.getMessage());
            }
        }

        return unionArrays(iv, encrypted);
    }

    public byte[] decrypt(byte[] encryptedData, byte[] key) {
        if (encryptedData == null || encryptedData.length == 0) {
            System.err.println("Encrypted data is empty");
            return new byte[0];
        }

        byte[] iv = Arrays.copyOfRange(encryptedData, 0, BLOCK_SIZE);
        byte[] encrypted = Arrays.copyOfRange(encryptedData, BLOCK_SIZE, encryptedData.length);

        FeistelNetwork feistel = new FeistelNetwork(key);
        byte[] decrypted = new byte[encrypted.length];
        byte[] prev = iv.clone();

        for (int i = 0; i < encrypted.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(encrypted, i, i + BLOCK_SIZE);
            try {
                byte[] decryptedBlock = feistel.decryptBlock(block);
                byte[] xored = xor(decryptedBlock, prev);
                System.arraycopy(xored, 0, decrypted, i, BLOCK_SIZE);
                prev = block;
            } catch (IllegalBlockSizeException e) {
                System.err.println("Illegal block size: " + e.getMessage());
            }
        }

        try {
            return removePadding(decrypted);
        } catch (IllegalArgumentException e) {
            System.err.println("Padding error! Returning raw decrypted bytes:");
            return decrypted;
        }
    }

    public void encryptFile(File inputFile, File outputFile, byte[] key, byte[] salt) throws IOException, IllegalBlockSizeException {
        boolean overwrite = inputFile.getCanonicalPath().equals(outputFile.getCanonicalPath());
        File tempFile = overwrite ? File.createTempFile("enc_temp_", ".dat") : outputFile;
        boolean success = false;

        try {
            KeyVerifier keyVerifier = new KeyVerifier();
            byte[] verifier = keyVerifier.createKeyVerifier(key);
            if (verifier == null) throw new IOException("Failed to create key verifier");

            try (InputStream in = new BufferedInputStream(new FileInputStream(inputFile));
                 OutputStream out = new BufferedOutputStream(new FileOutputStream(tempFile))) {

                FeistelNetwork feistel = new FeistelNetwork(key);
                byte[] iv = createInitVector();
                out.write(iv);
                byte[] prev = iv.clone();

                long totalInputSize = inputFile.length();
                long processed = 0;

                System.out.println("Encrypting: " + inputFile.getName());

                byte[] buffer = new byte[BLOCK_SIZE];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    byte[] chunk = (bytesRead < BLOCK_SIZE)
                            ? addPadding(Arrays.copyOf(buffer, bytesRead))
                            : Arrays.copyOf(buffer, BLOCK_SIZE);

                    byte[] xored = xor(chunk, prev);
                    byte[] encryptedBlock = feistel.encryptBlock(xored);
                    out.write(encryptedBlock);
                    prev = encryptedBlock;

                    processed += bytesRead;
                    printProgressBar(processed, totalInputSize);
                }

                if (totalInputSize % BLOCK_SIZE == 0) {
                    byte[] padBlock = addPadding(new byte[0]);
                    byte[] xored = xor(padBlock, prev);
                    byte[] encryptedBlock = feistel.encryptBlock(xored);
                    out.write(encryptedBlock);
                }

                out.write(verifier);
                out.write(salt);
                printProgressBar(totalInputSize + verifier.length + salt.length, totalInputSize + verifier.length + salt.length);
                System.out.println("\nEncryption completed!");
            }
            if (overwrite) {
                if (!inputFile.delete() || !tempFile.renameTo(inputFile)) {
                    throw new IOException("Failed to replace original file after encryption");
                }
            }
            success = true;
        } finally {
            if (!success && overwrite && tempFile.exists()) {
                tempFile.delete();
            }
        }
    }

    public void decryptFile(File inputFile, File outputFile, byte[] key) throws IOException, IllegalBlockSizeException {
        boolean overwrite = inputFile.getCanonicalPath().equals(outputFile.getCanonicalPath());
        File tempFile = overwrite ? File.createTempFile("dec_temp_", ".dat") : outputFile;
        boolean success = false;

        try {
            long fileSize = inputFile.length();
            if (fileSize < BLOCK_SIZE + VERIFIER_SIZE + SALT_SIZE) throw new IOException("Invalid file format");

            byte[] verifier = new byte[VERIFIER_SIZE];
            try (RandomAccessFile raf = new RandomAccessFile(inputFile, "r")) {
                raf.seek(fileSize - VERIFIER_SIZE - SALT_SIZE);
                raf.readFully(verifier);
            }

            KeyVerifier keyVerifier = new KeyVerifier();
            if (!keyVerifier.verifyKey(key, verifier)) throw new IllegalArgumentException("Invalid key");

            long encryptedLen = fileSize - BLOCK_SIZE - VERIFIER_SIZE - SALT_SIZE;
            long blocksCount = encryptedLen / BLOCK_SIZE;

            try (InputStream in = new BufferedInputStream(new FileInputStream(inputFile));
                 OutputStream out = new BufferedOutputStream(new FileOutputStream(tempFile))) {

                FeistelNetwork feistel = new FeistelNetwork(key);
                byte[] iv = in.readNBytes(BLOCK_SIZE);
                byte[] prev = iv.clone();
                byte[] currentBlock = new byte[BLOCK_SIZE];
                byte[] nextBlock = new byte[BLOCK_SIZE];

                System.out.println("Decrypting...");

                if (in.read(currentBlock) != BLOCK_SIZE)
                    throw new IOException("Invalid encrypted block");

                for (long i = 0; i < blocksCount - 1; i++) {
                    if (in.read(nextBlock) != BLOCK_SIZE)
                        throw new IOException("Invalid encrypted block");

                    byte[] decrypted = feistel.decryptBlock(currentBlock);
                    byte[] xored = xor(decrypted, prev);
                    out.write(xored);

                    prev = currentBlock;
                    currentBlock = nextBlock.clone();

                    printProgressBar((i + 1) * BLOCK_SIZE, encryptedLen);
                }

                byte[] decrypted = feistel.decryptBlock(currentBlock);
                byte[] xored = xor(decrypted, prev);
                try {
                    out.write(removePadding(xored));
                } catch (IllegalArgumentException e) {
                    System.err.println("Padding error, writing raw: " + e.getMessage());
                    out.write(xored);
                }
                printProgressBar(encryptedLen, encryptedLen);
                System.out.println("\nDecryption finished.");
            }
            if (overwrite) {
                if (!inputFile.delete() || !tempFile.renameTo(inputFile)) {
                    throw new IOException("Failed to replace original file after decryption");
                }
            }
            success = true;
        } finally {
            if (!success && overwrite && tempFile.exists()) {
                tempFile.delete();
            }
        }
    }

    public byte[] readSalt(File file) {
        byte[] salt = new byte[SALT_SIZE];
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            raf.seek(raf.length() - SALT_SIZE);
            raf.readFully(salt);
        } catch (IOException e) {
            System.err.println("Failed to read salt: " + e.getMessage());
        }
        return salt;
    }

    private void printProgressBar(long processed, long total) {
        if (processed >= total) {
            System.out.printf("\r[100%%] %d/%d bytes", total, total);
            return;
        }

        long now = System.nanoTime();
        long update_interval = 800L;
        if (now - lastUpdateTime < update_interval * 1_000_000) return;
        lastUpdateTime = now;
        int percent = (int) (100 * processed / total);
        System.out.printf("\r[%3d%%] %d/%d bytes", percent, processed, total);
        System.out.flush();
    }
}