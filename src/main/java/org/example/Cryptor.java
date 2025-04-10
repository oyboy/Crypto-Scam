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
        System.out.println("Padded length: " + paddingLength);
        if (paddingLength <= 0 || paddingLength > BLOCK_SIZE) {
            throw new IllegalArgumentException("Invalid padding");
        }
        return Arrays.copyOf(input, input.length - paddingLength);
    }

    private byte[] createInitVector() {
        return bbsRandom.nextBytes(BLOCK_SIZE);
    }

    public String encrypt(String text, byte[] key) {
        System.out.println("=== ENCRYPTION STARTED ===");
        FeistelNetwork feistelNetwork = new FeistelNetwork(key);
        byte[] input = text.getBytes(StandardCharsets.UTF_8);

        System.out.println("Original text bytes: " + Arrays.toString(input));
        System.out.println("Original text length: " + input.length + " bytes");

        byte[] paddedInput = addPadding(input);
        System.out.println("Padded text bytes: " + Arrays.toString(paddedInput));
        System.out.println("Padded text length: " + paddedInput.length + " bytes");

        byte[] iv = createInitVector();
        System.out.println("IV generated: " + bytesToHex(iv));

        byte[] encrypted = new byte[paddedInput.length];
        byte[] previousBlock = iv.clone();

        for (int i = 0; i < paddedInput.length; i += BLOCK_SIZE) {
            System.out.println("\nProcessing block at offset: " + i);

            byte[] block = Arrays.copyOfRange(paddedInput, i, i + BLOCK_SIZE);
            System.out.println("Original block: " + bytesToHex(block));

            byte[] xored = xor(block, previousBlock);
            System.out.println("After XOR with prev: " + bytesToHex(xored));

            try {
                byte[] encryptedBlock = feistelNetwork.encryptBlock(xored);
                System.out.println("Encrypted block: " + bytesToHex(encryptedBlock));

                System.arraycopy(encryptedBlock, 0, encrypted, i, BLOCK_SIZE);
                previousBlock = encryptedBlock;
            } catch (IllegalBlockSizeException e) {
                System.err.println("Illegal block size: " + e.getMessage());
            }
        }

        System.out.println("\nFinal encrypted data: " + bytesToHex(encrypted));
        System.out.println("=== ENCRYPTION COMPLETED ===");

        return bytesToHex(iv) + IV_DELIMITER + bytesToHex(encrypted);
    }

    public String decrypt(String encryptedText, byte[] key) {
        System.out.println("\n=== DECRYPTION STARTED ===");
        FeistelNetwork feistelNetwork = new FeistelNetwork(key);
        String[] parts = encryptedText.split(IV_DELIMITER, 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid encrypted format");
        }

        byte[] iv = hexToBytes(parts[0]);
        byte[] encrypted = hexToBytes(parts[1]);

        System.out.println("IV received: " + bytesToHex(iv));
        System.out.println("Encrypted data: " + bytesToHex(encrypted));
        System.out.println("Encrypted data length: " + encrypted.length + " bytes");

        byte[] decrypted = new byte[encrypted.length];
        byte[] previousBlock = iv.clone();

        for (int i = 0; i < encrypted.length; i += BLOCK_SIZE) {
            System.out.println("\nProcessing block at offset: " + i);

            byte[] block = Arrays.copyOfRange(encrypted, i, i + BLOCK_SIZE);
            System.out.println("Encrypted block: " + bytesToHex(block));

            try {
                byte[] decryptedBlock = feistelNetwork.decryptBlock(block);
                System.out.println("After decryption: " + bytesToHex(decryptedBlock));

                byte[] xored = xor(decryptedBlock, previousBlock);
                System.out.println("After XOR with prev: " + bytesToHex(xored));

                System.arraycopy(xored, 0, decrypted, i, BLOCK_SIZE);
                previousBlock = block;

                System.out.println("Current decrypted state: " + bytesToHex(decrypted));
            } catch (IllegalBlockSizeException e) {
                System.err.println("Illegal block size: " + e.getMessage());
            }
        }

        System.out.println("\nFinal decrypted bytes: " + Arrays.toString(decrypted));
        System.out.println("Hex view: " + bytesToHex(decrypted));

        try {
            byte[] unpadded = removePadding(decrypted);
            System.out.println("After padding removal: " + Arrays.toString(unpadded));
            System.out.println("Hex view: " + bytesToHex(unpadded));
            System.out.println("=== DECRYPTION COMPLETED ===");
            return new String(unpadded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            System.err.println("Padding error! Full decrypted data dump:");
            System.err.println("Hex: " + bytesToHex(decrypted));
            System.err.println("Raw: " + Arrays.toString(decrypted));
        }
        return null;
    }
}