package org.example.util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class BBSRandom {
    private BigInteger state;
    private final BigInteger M;

    public BBSRandom() {
        BigInteger p = generateBlumPrime(512);
        BigInteger q = generateBlumPrime(512);
        this.M = p.multiply(q);
        this.state = getSeed();
    }

    private int nextBit() {
        state = state.modPow(BigInteger.TWO, M);
        return state.testBit(0) ? 1 : 0;
    }

    public byte[] nextBytes(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length * 8; i++) {
            int bit = nextBit();
            bytes[i / 8] |= (bit << (i % 8));
        }
        return bytes;
    }

    private BigInteger getSeed() {
        byte[] seedMaterial = collectEntropy();
        BigInteger seed;
        try {
            seed = new BigInteger(1, hashManyTimes(seedMaterial, 5));
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        seed = seed.mod(M);
        if (seed.equals(BigInteger.ZERO)) {
            seed = seed.add(BigInteger.ONE);
        }
        if (!seed.gcd(M).equals(BigInteger.ONE)) {
            seed = seed.add(BigInteger.TWO);
        }
        return seed;
    }

    private byte[] collectEntropy() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long nanoTime = System.nanoTime();
            long currentTime = System.currentTimeMillis();
            long threadId = Thread.currentThread().getId();
            long freeMem = Runtime.getRuntime().freeMemory();
            long totalMem = Runtime.getRuntime().totalMemory();
            byte[] entropy = ByteBuffer.allocate(8 * 5)
                    .putLong(nanoTime)
                    .putLong(currentTime)
                    .putLong(threadId)
                    .putLong(freeMem)
                    .putLong(totalMem)
                    .array();
            return digest.digest(entropy);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] hashManyTimes(byte[] input, int rounds) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] result = Arrays.copyOf(input, input.length);
        for (int i = 0; i < rounds; i++) {
            result = digest.digest(result);
        }
        return result;
    }

    private BigInteger generateBlumPrime(int bitLength) {
        BigInteger prime = BigInteger.probablePrime(bitLength, new java.util.Random(System.nanoTime()));
        while (!prime.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))) {
            prime = prime.nextProbablePrime();
        }
        return prime;
    }
}