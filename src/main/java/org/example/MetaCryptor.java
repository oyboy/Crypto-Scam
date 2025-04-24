package org.example;

import org.example.util.MetaExtractor;
import java.io.*;

public class MetaCryptor {
    public void cryptMetadata(File file) {
        try {
            byte[] metadata = MetaExtractor.extractMetadata(file);
            System.out.println("extracted meta: " + new String(metadata));
        } catch (Exception e) {
            System.err.println("Ошибка шифрования метаданных: " + e.getMessage());
        }
    }
}