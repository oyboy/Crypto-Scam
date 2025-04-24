package org.example.commands;

import org.example.Cryptor;
import org.example.key.KeyGenerator;
import org.example.MetaCryptor;
import picocli.CommandLine;
import java.io.File;

@CommandLine.Command(name="encrypt-file", description = "Encrypt file command")
public class EncryptFileCommand implements Runnable {
    @CommandLine.Option(names = {"-f", "--file"}, required = true, description = "File name")
    String filename;

    @CommandLine.Option(names = {"-o", "--output-file"}, description = "Output file")
    String output_filename;

    @CommandLine.Option(names = {"-p", "--pass-phrase"}, required = true, description = "Pass phrase")
    String passphrase;

    @Override
    public void run() {
        Cryptor cryptor = new Cryptor();
        MetaCryptor metaCryptor = new MetaCryptor();
        KeyGenerator generator = new KeyGenerator();
        byte[] salt = generator.generateSalt(128/8);
        byte[] key = generator.generateKeyFromPassword(passphrase, salt, 256/8);

        try {
            File original = new File(filename);
            File encrypted = output_filename == null ? original : new File(output_filename);

            cryptor.encryptFile(original, encrypted, key, salt);
            //metaCryptor.cryptMetadata(original, key);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}