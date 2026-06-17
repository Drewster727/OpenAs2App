package org.openas2.pgp;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import jakarta.mail.internet.MimeBodyPart;

import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for PGPUtils encrypt/decrypt round-trip using ephemeral BouncyCastle keys.
 */
public class PGPUtilsTest {

    private static PGPPublicKey testPublicKey;
    private static PGPSecretKeyRingCollection testSecretKeyRings;
    private static final char[] TEST_PASSPHRASE = "test-passphrase".toCharArray();

    @BeforeAll
    static void generateTestKeys() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        java.security.KeyPair kp = kpg.generateKeyPair();

        JcaPGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, kp, new Date());
        testPublicKey = pgpKeyPair.getPublicKey();

        PGPSecretKey secretKey = new PGPSecretKey(
                pgpKeyPair.getPrivateKey(),
                pgpKeyPair.getPublicKey(),
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                true,
                new JcePBESecretKeyEncryptorBuilder(org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256)
                        .build(TEST_PASSPHRASE));

        PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(
                Collections.singletonList(secretKey));
        testSecretKeyRings = new PGPSecretKeyRingCollection(
                Collections.singletonList(secretKeyRing));
    }

    @Test
    void encryptAndDecryptRoundTrip() throws Exception {
        byte[] original = "Hello NAESB 4.0 EDI payload!".getBytes();

        byte[] encrypted = PGPUtils.encrypt(original, testPublicKey);
        assertNotNull(encrypted);
        assertTrue(encrypted.length > 0);

        byte[] decrypted = PGPUtils.decrypt(encrypted, testSecretKeyRings, TEST_PASSPHRASE);
        assertArrayEquals(original, decrypted, "Decrypted bytes must match original");
    }

    @Test
    void encryptedBytesDetectedAsPGP() throws Exception {
        byte[] plaintext = "EDI data".getBytes();
        byte[] encrypted = PGPUtils.encrypt(plaintext, testPublicKey);

        MimeBodyPart part = PGPUtils.wrapBytes(encrypted, "application/octet-stream");
        assertTrue(PGPUtils.isPGPEncrypted(part), "Encrypted content should be detected as PGP");
    }

    @Test
    void plainBytesNotDetectedAsPGP() throws Exception {
        byte[] plaintext = "ISA*00*...\r\n".getBytes();
        MimeBodyPart part = PGPUtils.wrapBytes(plaintext, "text/plain");
        assertFalse(PGPUtils.isPGPEncrypted(part), "Plain EDI content should not be detected as PGP");
    }

    @Test
    void wrapAndExtractBytes() throws Exception {
        byte[] original = "round-trip mime wrap test".getBytes();
        MimeBodyPart part = PGPUtils.wrapBytes(original, "application/octet-stream");

        byte[] extracted = PGPUtils.extractBytes(part);
        assertArrayEquals(original, extracted, "Extracted bytes must match wrapped bytes");
    }

    @Test
    void wrapBytesPreservesContentType() throws Exception {
        String contentType = "application/edi-x12";
        MimeBodyPart part = PGPUtils.wrapBytes("test".getBytes(), contentType);
        assertTrue(part.getContentType().startsWith(contentType),
                "Content-Type should be preserved: " + part.getContentType());
    }
}
