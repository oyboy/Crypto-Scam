package org.example;

public class Main {
    public static void main(String[] args) {
        String text = "Hello World!";
        Cryptor cryptor = new Cryptor();
        KeyGenerator generator = new KeyGenerator();
        byte[] salt = generator.generateSalt(128/8);
        byte[] key = generator.generateKeyFromPassword("MyPassword", salt, 256/8);

        String crypted = cryptor.encrypt(text, key);
        System.out.println("crypted: " + crypted);

        String decrypted = cryptor.decrypt(crypted, key);
        System.out.println("decrypted: " + decrypted);

        key[1] = 0x00;
        String anotherDecrypted = cryptor.decrypt(crypted, key);
        System.out.println("decrypted with changed key: " + anotherDecrypted);
        System.out.println("Crypted length: " + crypted.length());
    }
}