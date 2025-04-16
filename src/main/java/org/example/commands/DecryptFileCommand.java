package org.example.commands;

import org.example.Cryptor;
import org.example.KeyGenerator;
import picocli.CommandLine;

import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOException;

@CommandLine.Command(name="decrypt-file", description = "Decrypt file command")
public class DecryptFileCommand implements Runnable {
    @CommandLine.Option(names = {"-f", "--file"}, required = true, description = "File name")
    String filename;

    @CommandLine.Option(names = {"-o", "--output-file"}, description = "Output file")
    String output_filename;

    @CommandLine.Option(names = {"-p", "--pass-phrase"}, required = true, description = "Pass phrase")
    String passphrase;

    @Override
    public void run() {
        Cryptor cryptor = new Cryptor();
        KeyGenerator generator = new KeyGenerator();
        File original = new File(filename);
        File encrypted = output_filename == null ? original : new File(output_filename);

        byte[] salt = cryptor.readSalt(original);
        byte[] key = generator.generateKeyFromPassword(passphrase, salt, 256/8);

        try {
            cryptor.decryptFile(original, encrypted, key);
        } catch (IllegalArgumentException ia) {
            System.err.println("Unable to decrypt file: " + ia.getMessage());
        }
        catch (IllegalBlockSizeException | IOException l) {
            System.err.println("Error: " + l.getMessage());
        }
    }
}
