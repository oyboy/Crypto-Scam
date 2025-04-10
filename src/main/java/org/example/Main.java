package org.example;

import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        Cryptor cryptor = new Cryptor();
        KeyGenerator generator = new KeyGenerator();
        byte[] salt = generator.generateSalt(128/8);
        byte[] key = generator.generateKeyFromPassword("MyPassword", salt, 256/8);

        try {
            File original = new File("test-files/document.txt");
            File encrypted = new File("test-files/enc_document.txt");
            cryptor.encryptFile(original, encrypted, key);

            File decrypted = new File("test-files/dec_document.txt");
            cryptor.decryptFile(encrypted, decrypted, key);

        } catch (IllegalBlockSizeException | IOException l) {
            System.err.println("Error: " + l.getMessage());
        }
    }
}