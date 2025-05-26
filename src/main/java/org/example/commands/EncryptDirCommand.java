package org.example.commands;

import org.example.Cryptor;
import org.example.key.KeyGenerator;
import picocli.CommandLine;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@CommandLine.Command(name = "encrypt-dir", description = "Encrypt directory recursively")
public class EncryptDirCommand implements Runnable {
    @CommandLine.Option(names = {"-d", "--directory"}, required = true, description = "Directory to encrypt")
    String directory;

    @CommandLine.Option(names = {"-o", "--output-dir"}, description = "Output directory for encrypted files")
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
                byte[] salt = generator.generateSalt(128 / 8);
                byte[] key = generator.generateKey(passphrase, salt, 256 / 8);

                String relativePath = inputDir.toPath().relativize(file.toPath()).toString();
                File outputFile = new File(outDir, relativePath);
                outputFile.getParentFile().mkdirs();

                cryptor.encryptFile(file, outputFile, key, salt);
            }
            System.out.println("Directory encrypted successfully.");
        } catch (Exception e) {
            System.err.println("Error encrypting directory: " + e.getMessage());
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