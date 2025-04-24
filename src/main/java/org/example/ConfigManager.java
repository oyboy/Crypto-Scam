package org.example;

import org.example.key.KeyGenerator;
import org.example.key.KeyVerifier;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class ConfigManager {
    private static final KeyVerifier VERIFIER = new KeyVerifier();
    private static final KeyGenerator KEYGEN = new KeyGenerator();
    private static final String CONFIG_DIR = System.getProperty("user.home") + "/.secures";
    private static final String MAIN_CONFIG = CONFIG_DIR + "/main.conf";
    private static final ConcurrentMap<String, byte[]> keyCache = new ConcurrentHashMap<>();

    static {
        try {
            Files.createDirectories(Paths.get(CONFIG_DIR));
        } catch (IOException e) {
            System.err.println("Failed to create config directory: " + e.getMessage());
        }
    }

    public static void initConfigForPath(String path, String passPhrase) throws IOException {
        byte[] salt = KEYGEN.generateSalt(32);
        byte[] key = KEYGEN.generateKeyFromPassword(passPhrase, salt, 64);
        byte[] verifier = VERIFIER.createKeyVerifier(key);

        String configId = generateConfigId(path);
        String entry = String.format("%s|salt=%s|verifier=%s",
                configId,
                Base64.getEncoder().encodeToString(salt),
                Base64.getEncoder().encodeToString(verifier));

        Files.write(Paths.get(MAIN_CONFIG), (entry + System.lineSeparator()).getBytes(),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        cleanSensitiveData(key);
    }

    public static byte[] getKeyForPath(String path, String passPhrase) throws IOException {
        String configId = generateConfigId(path);
        byte[] cachedKey = keyCache.get(configId);
        if (cachedKey != null) {
            return cachedKey.clone();
        }

        String configLine = findConfigLine(configId);
        if (configLine == null) {
            throw new IOException("Config not found for path: " + path);
        }

        Map<String, String> config = parseConfigLine(configLine);
        byte[] salt = Base64.getDecoder().decode(config.get("salt"));
        byte[] storedVerifier = Base64.getDecoder().decode(config.get("verifier"));

        byte[] candidateKey = KEYGEN.generateKeyFromPassword(passPhrase, salt, 64);
        try {
            if (!VERIFIER.verifyKey(candidateKey, storedVerifier)) {
                delayAndClean(candidateKey);
                throw new SecurityException("Invalid password for path: " + path);
            }

            byte[] keyCopy = candidateKey.clone();
            keyCache.put(configId, keyCopy);
            return keyCopy;
        } finally {
            cleanSensitiveData(candidateKey);
        }
    }

    public static String generateConfigId(String path) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(path.getBytes());
            return Base64.getEncoder().encodeToString(hash).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
    private static String findConfigLine(String configId) throws IOException {
        if (!Files.exists(Paths.get(MAIN_CONFIG))) {
            return null;
        }

        return Files.lines(Paths.get(MAIN_CONFIG))
                .filter(line -> line.startsWith(configId + "|"))
                .findFirst()
                .orElse(null);
    }
    private static Map<String, String> parseConfigLine(String line) {
        Map<String, String> config = new HashMap<>();
        String[] parts = line.split("\\|");
        for (int i = 1; i < parts.length; i++) {
            String[] keyValue = parts[i].split("=", 2);
            if (keyValue.length == 2) {
                config.put(keyValue[0], keyValue[1]);
            }
        }
        return config;
    }
    private static void delayAndClean(byte[] data) {
        try {
            Thread.sleep(2);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            cleanSensitiveData(data);
        }
    }
    private static void cleanSensitiveData(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }
    public static void clearCache() {
        keyCache.values().forEach(ConfigManager::cleanSensitiveData);
        keyCache.clear();
    }
}