package org.example.util;

import java.math.BigInteger;
import java.security.SecureRandom;

public class BBSRandom {
    private BigInteger state;
    private final BigInteger M;
    private final SecureRandom random = new SecureRandom();

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
    /*bad*/
    private BigInteger getSeed(){
        BigInteger seed;
        do {
            seed = new BigInteger(M.bitLength(), random).mod(M);
        } while (seed.equals(BigInteger.ZERO) || !seed.gcd(M).equals(BigInteger.ONE));
        return seed;
    }
    private BigInteger generateBlumPrime(int bitLength) {
        BigInteger prime;
        do {
            prime = BigInteger.probablePrime(bitLength, random);
        } while (!prime.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3)));
        return prime;
    }
}
