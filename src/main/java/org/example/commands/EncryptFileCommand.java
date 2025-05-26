package org.example.commands;

import org.example.Cryptor;
import org.example.key.KeyGenerator;
import picocli.CommandLine;
import java.io.File;

@CommandLine.Command(name="encrypt-file", description = "Encrypt file command")
public class EncryptFileCommand implements Runnable {
    @CommandLine.Option(names = {"-f", "--file"}, required = true, description = "File name")
    String filename;

    @CommandLine.Option(names = {"-o", "--output-file"}, description = "Output file")
    String output_filename;

    @CommandLine.Option(names = {"-p", "--pass-phrase"}, description = "Pass phrase")
    String passphrase;

    @Override
    public void run() {
        Cryptor cryptor = new Cryptor();
        KeyGenerator generator = new KeyGenerator();
        byte[] salt = generator.generateSalt(128/8);
        byte[] key = generator.generateKey(passphrase, salt, 256/8);

        try {
            File original = new File(filename);
            File encrypted = output_filename == null ? original : new File(output_filename);

            cryptor.encryptFile(original, encrypted, key, salt);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}