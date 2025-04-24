package org.example.util;

import org.apache.tika.metadata.Metadata;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.sax.BodyContentHandler;

import javax.imageio.ImageIO;
import javax.imageio.metadata.IIOMetadata;
import javax.imageio.stream.ImageInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Iterator;

public class MetaExtractor {
    private static byte[] extractImageMetadata(File file) throws Exception {
        ImageInputStream iis = ImageIO.createImageInputStream(file);
        Iterator<?> readers = ImageIO.getImageReaders(iis);
        if (readers.hasNext()) {
            var reader = (javax.imageio.ImageReader) readers.next();
            reader.setInput(iis, true);
            IIOMetadata metadata = reader.getImageMetadata(0);

            return metadata.getAsTree("javax_imageio_1.0").toString().getBytes();
        }
        return new byte[0];
    }

    private static byte[] extractDocumentMetadata(File file) throws Exception {
        Metadata metadata = new Metadata();
        InputStream stream = new FileInputStream(file);
        AutoDetectParser parser = new AutoDetectParser();
        parser.parse(stream, new BodyContentHandler(-1), metadata, new ParseContext());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (String name : metadata.names()) {
            outputStream.write((name + ": " + metadata.get(name) + "\n").getBytes());
        }
        return outputStream.toByteArray();
    }

    public static byte[] extractMetadata(File file) throws Exception {
        String fileName = file.getName().toLowerCase();
        if (fileName.endsWith(".jpg") || fileName.endsWith(".png") || fileName.endsWith(".jpeg")) {
            return extractImageMetadata(file);
        } else if (fileName.endsWith(".pdf") || fileName.endsWith(".docx") || fileName.endsWith(".txt")) {
            return extractDocumentMetadata(file);
        }
        throw new UnsupportedOperationException("Неподдерживаемый файл для извлечения меты");
    }
}