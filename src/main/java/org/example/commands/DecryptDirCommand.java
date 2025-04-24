package org.example.commands;

import org.example.Cryptor;
import org.example.key.KeyGenerator;
import picocli.CommandLine;

import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@CommandLine.Command(name = "decrypt-dir", description = "Decrypt directory recursively")
public class DecryptDirCommand implements Runnable {
    @CommandLine.Option(names = {"-d", "--directory"}, required = true, description = "Encrypted directory")
    String directory;

    @CommandLine.Option(names = {"-o", "--output-dir"}, description = "Output directory for decrypted files")
    String outputDirectory;

    @CommandLine.Option(names = {"-p", "--pass-phrase"}, required = true, description = "Pass phrase")
    String passphrase;

    @Override
    public void run() {
        Cryptor cryptor = new Cryptor();
        KeyGenerator generator = new KeyGenerator();

        try {
            File inputDir = new File(directory);
            File outDir = outputDirectory == null ? inputDir : new File(outputDirectory);

            if (!inputDir.isDirectory()) {
                throw new IllegalArgumentException("Provided path is not a directory.");
            }

            List<File> files = listFilesRecursively(inputDir);

            for (File file : files) {
                byte[] salt = cryptor.readSalt(file);
                byte[] key = generator.generateKeyFromPassword(passphrase, salt, 256 / 8);

                String relativePath = inputDir.toPath().relativize(file.toPath()).toString();
                File outputFile = new File(outDir, relativePath);
                outputFile.getParentFile().mkdirs();

                try {
                    cryptor.decryptFile(file, outputFile, key);
                } catch (IllegalArgumentException ia) {
                    System.err.println("Unable to decrypt file " + file.getPath() + ": " + ia.getMessage());
                } catch (IllegalBlockSizeException | IOException l) {
                    System.err.println("Error decrypting file " + file.getPath() + ": " + l.getMessage());
                }
            }
            System.out.println("Directory has been decrypted.");
        } catch (Exception e) {
            System.err.println("Error decrypting directory: " + e.getMessage());
        }
    }

    private List<File> listFilesRecursively(File dir) {
        List<File> fileList = new ArrayList<>();
        File[] files = dir.listFiles();
        if (files == null) return fileList;

        for (File file : files) {
            if (file.isDirectory()) {
                fileList.addAll(listFilesRecursively(file));
            } else {
                fileList.add(file);
            }
        }
        return fileList;
    }
}
