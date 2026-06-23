package org.openas2.pgp;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests for {@link PGPKeyFactory#getSigningKey} against a private keyring with no User ID
 * set on its key (matches GeneratePGPTestKeys / today's deployed keyrings).
 */
public class PGPKeyFactoryTest {

    private static final char[] PASSPHRASE = "test-passphrase".toCharArray();
    private static long expectedKeyId;

    @BeforeAll
    static void setUpProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private PGPKeyFactory buildFactory(Path tempDir) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        JcaPGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, kp, new Date());
        expectedKeyId = pgpKeyPair.getPublicKey().getKeyID();

        PGPSecretKey secretKey = new PGPSecretKey(
                pgpKeyPair.getPrivateKey(),
                pgpKeyPair.getPublicKey(),
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                true,
                new JcePBESecretKeyEncryptorBuilder(org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.AES_256)
                        .build(PASSPHRASE));

        File privateKeyringFile = tempDir.resolve("private_keyring.gpg").toFile();
        try (OutputStream fos = new FileOutputStream(privateKeyringFile)) {
            new PGPSecretKeyRing(Collections.singletonList(secretKey)).encode(fos);
        }

        File publicKeysDir = tempDir.resolve("public_keys").toFile();
        publicKeysDir.mkdirs();

        Map<String, String> parameters = new HashMap<>();
        parameters.put(PGPKeyFactory.PARAM_PRIVATE_KEYRING, privateKeyringFile.getAbsolutePath());
        parameters.put(PGPKeyFactory.PARAM_PRIVATE_KEYRING_PASS, new String(PASSPHRASE));
        parameters.put(PGPKeyFactory.PARAM_PUBLIC_KEYS_DIR, publicKeysDir.getAbsolutePath());

        PGPKeyFactory factory = new PGPKeyFactory();
        factory.init(null, parameters);
        return factory;
    }

    @Test
    void getSigningKeyFallsBackToSoleKeyWhenNoUserIdMatches(@TempDir Path tempDir) throws Exception {
        PGPKeyFactory factory = buildFactory(tempDir);

        PGPPrivateKey signingKey = factory.getSigningKey("some_alias_not_in_keyring");

        assertNotNull(signingKey);
        assertEquals(expectedKeyId, signingKey.getKeyID());
    }
}
