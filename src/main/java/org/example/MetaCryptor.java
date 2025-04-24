package org.example;

import org.example.util.MetaExtractor;
import java.io.*;

public class MetaCryptor {
    public void cryptMetadata(File file, byte[] key) throws Exception {
        Cryptor cryptor = new Cryptor();

        byte[] metadata = MetaExtractor.extractMetadata(file);
        System.out.println("extracted meta: " + new String(metadata));

        byte[] cryptedMeta = cryptor.encrypt(metadata, key);
        System.out.println("encrypted meta: " + new String(cryptedMeta));
        writeEncryptedMetadata(cryptedMeta, file);

        byte[] metadata2 = MetaExtractor.extractMetadata(file);
        System.out.println("extracted meta2: " + new String(metadata2));
    }
    private void writeEncryptedMetadata(byte[] encryptedMetadata, File file) {
        try (FileOutputStream fos = new FileOutputStream(file, true)) {
            fos.write(encryptedMetadata);
            System.out.println("Зашифрованные метаданные успешно записаны в файл.");
        } catch (IOException e) {
            System.err.println("Ошибка записи в файл: " + e.getMessage());
        }
    }
}