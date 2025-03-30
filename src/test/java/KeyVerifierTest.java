import org.example.KeyVerifier;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class KeyVerifierTest {
    private final KeyVerifier keyVerifier = new KeyVerifier();

    @Test
    void testCreateKeyVerifier_validKey_returnsNonNull() {
        byte[] key = "secret".getBytes();
        byte[] verifier = keyVerifier.createKeyVerifier(key);
        assertNotNull(verifier, "Verifier should not be null for a valid key");
    }

    @Test
    void testVerifyKey_validKeyAndVerifier_returnsTrue() {
        byte[] key = "secret".getBytes();
        byte[] verifier = keyVerifier.createKeyVerifier(key);
        boolean result = keyVerifier.verifyKey(key, verifier);
        assertTrue(result, "Verification should succeed with a valid key and verifier");
    }

    @Test
    void testVerifyKey_invalidKey_returnsFalse() {
        byte[] key = "secret".getBytes();
        byte[] verifier = keyVerifier.createKeyVerifier(key);
        byte[] invalidKey = "wrong_secret".getBytes();
        boolean result = keyVerifier.verifyKey(invalidKey, verifier);
        assertFalse(result, "Verification should fail with an invalid key");
    }

    @Test
    void testVerifyKey_invalidVerifier_returnsFalse() {
        byte[] key = "secret".getBytes();
        byte[] invalidVerifier = "wrong_verifier".getBytes();
        boolean result = keyVerifier.verifyKey(key, invalidVerifier);
        assertFalse(result, "Verification should fail with an invalid verifier");
    }

    @Test
    void testVerifyKey_nullCandidateKey_returnsFalse() {
        byte[] key = "secret".getBytes();
        byte[] verifier = keyVerifier.createKeyVerifier(key);
        boolean result = keyVerifier.verifyKey(null, verifier);
        assertFalse(result, "Verification should fail with a null candidate key");
    }

    @Test
    void testVerifyKey_nullStoredVerifier_returnsFalse() {
        byte[] key = "secret".getBytes();
        boolean result = keyVerifier.verifyKey(key, null);
        assertFalse(result, "Verification should fail with a null stored verifier");
    }
}
