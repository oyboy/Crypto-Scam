package org.example;

import javax.crypto.IllegalBlockSizeException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.example.DataOperator.*;

public class Cryptor {
    private final int BLOCK_SIZE = 8;
    private final BBSRandom bbsRandom = new BBSRandom();
    private final String IV_DELIMITER = "::";

    private byte[] addPadding(byte[] input) {
        if (input.length % BLOCK_SIZE == 0) return input;
        int paddingLength = BLOCK_SIZE - (input.length % BLOCK_SIZE);
        byte[] padded = Arrays.copyOf(input, input.length + paddingLength);
        Arrays.fill(padded, input.length, padded.length, (byte) paddingLength);
        return padded;
    }
    private byte[] removePadding(byte[] input) throws IllegalArgumentException {
        int paddingLength = input[input.length - 1] & 0xFF;
        if (paddingLength <= 0 || paddingLength > BLOCK_SIZE) {
            throw new IllegalArgumentException("Invalid padding");
        }
        return Arrays.copyOf(input, input.length - paddingLength);
    }

    private byte[] createInitVector() {
        return bbsRandom.nextBytes(BLOCK_SIZE);
    }

    public String encrypt(String text, byte[] key) {
        if (text == null || text.isEmpty()) {
            System.err.println("Text is empty");
            return null;
        }
        FeistelNetwork feistelNetwork = new FeistelNetwork(key);
        byte[] input = text.getBytes(StandardCharsets.UTF_8);
        byte[] paddedInput = addPadding(input);
        byte[] iv = createInitVector();

        byte[] encrypted = new byte[paddedInput.length];
        byte[] previousBlock = iv.clone();

        for (int i = 0; i < paddedInput.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(paddedInput, i, i + BLOCK_SIZE);
            byte[] xored = xor(block, previousBlock);
            try {
                byte[] encryptedBlock = feistelNetwork.encryptBlock(xored);
                System.arraycopy(encryptedBlock, 0, encrypted, i, BLOCK_SIZE);
                previousBlock = encryptedBlock;
            } catch (IllegalBlockSizeException e) {
                System.err.println("Illegal block size: " + e.getMessage());
            }
        }
        return bytesToHex(iv) + IV_DELIMITER + bytesToHex(encrypted);
    }

    public String decrypt(String encryptedText, byte[] key) {
        if (encryptedText == null || encryptedText.isEmpty()) {
            System.err.println("Encrypted text is empty");
            return null;
        }
        FeistelNetwork feistelNetwork = new FeistelNetwork(key);
        String[] parts = encryptedText.split(IV_DELIMITER, 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid encrypted format");
        }
        byte[] iv = hexToBytes(parts[0]);
        byte[] encrypted = hexToBytes(parts[1]);

        byte[] decrypted = new byte[encrypted.length];
        byte[] previousBlock = iv.clone();

        for (int i = 0; i < encrypted.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(encrypted, i, i + BLOCK_SIZE);
            try {
                byte[] decryptedBlock = feistelNetwork.decryptBlock(block);
                byte[] xored = xor(decryptedBlock, previousBlock);
                System.arraycopy(xored, 0, decrypted, i, BLOCK_SIZE);
                previousBlock = block;
            } catch (IllegalBlockSizeException e) {
                System.err.println("Illegal block size: " + e.getMessage());
            }
        }

        try {
            byte[] unpadded = removePadding(decrypted);
            return new String(unpadded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            System.err.println("Padding error! Full decrypted data dump:");
            System.err.println("Hex: " + bytesToHex(decrypted));
            System.err.println("Raw: " + Arrays.toString(decrypted));
            return new String(decrypted, StandardCharsets.UTF_8);
        }
    }
}