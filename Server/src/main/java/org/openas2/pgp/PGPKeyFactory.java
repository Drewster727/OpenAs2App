package org.openas2.pgp;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.openas2.BaseComponent;
import org.openas2.OpenAS2Exception;
import org.openas2.Session;
import org.openas2.params.InvalidParameterException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

/**
 * OpenAS2 Component that manages PGP keys for NAESB 4.0 payload encryption.
 *
 * <p>Register in config.xml as:
 * <pre>{@code
 * <pgpkeys classname="org.openas2.pgp.PGPKeyFactory"
 *     public_keys_dir="/opt/openas2/config/pgp/public_keys"
 *     private_keyring="/opt/openas2/config/pgp/private_keyring.gpg"
 *     private_keyring_password="changeit" />
 * }</pre>
 *
 * <p>Partner public keys are stored as ASCII-armored files named {@code <alias>.asc}
 * in the {@code public_keys_dir} directory. The private keyring is a standard
 * PGP secret keyring file.
 */
public class PGPKeyFactory extends BaseComponent {

    private static final Logger logger = LoggerFactory.getLogger(PGPKeyFactory.class);

    public static final String COMPID = "pgp_keys";

    public static final String PARAM_PUBLIC_KEYS_DIR = "public_keys_dir";
    public static final String PARAM_PRIVATE_KEYRING = "private_keyring";
    public static final String PARAM_PRIVATE_KEYRING_PASS = "private_keyring_password";

    private String publicKeysDir;
    private PGPSecretKeyRingCollection secretKeyRingCollection;
    private char[] privateKeyPassphrase;

    @Override
    public void init(Session session, Map<String, String> parameters) throws OpenAS2Exception {
        super.init(session, parameters);

        publicKeysDir = getParameter(PARAM_PUBLIC_KEYS_DIR, true);
        String privateKeyringPath = getParameter(PARAM_PRIVATE_KEYRING, true);
        String passphrase = getParameter(PARAM_PRIVATE_KEYRING_PASS, true);
        privateKeyPassphrase = passphrase.toCharArray();

        File privateKeyringFile = new File(privateKeyringPath);
        if (!privateKeyringFile.exists()) {
            throw new OpenAS2Exception("PGP private keyring file not found: " + privateKeyringPath);
        }
        File publicKeysDirFile = new File(publicKeysDir);
        if (!publicKeysDirFile.exists() || !publicKeysDirFile.isDirectory()) {
            throw new OpenAS2Exception("PGP public keys directory not found: " + publicKeysDir);
        }

        try (FileInputStream fis = new FileInputStream(privateKeyringFile)) {
            secretKeyRingCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(fis),
                    new JcaKeyFingerprintCalculator());
        } catch (IOException | PGPException e) {
            throw new OpenAS2Exception("Failed to load PGP private keyring from: " + privateKeyringPath, e);
        }
    }

    /**
     * Load a partner's PGP public key from {@code <public_keys_dir>/<alias>.asc}.
     * Returns the first encryption-capable key found in the file.
     *
     * @param alias the filename (without .asc extension) of the partner's public key
     * @throws OpenAS2Exception if the file is missing or cannot be parsed
     */
    public PGPPublicKey getPublicKey(String alias) throws OpenAS2Exception {
        File keyFile = new File(publicKeysDir, alias + ".asc");
        if (!keyFile.exists()) {
            throw new OpenAS2Exception("PGP public key file not found for alias '" + alias + "': " + keyFile.getAbsolutePath());
        }
        try (FileInputStream fis = new FileInputStream(keyFile)) {
            PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(fis),
                    new JcaKeyFingerprintCalculator());

            Iterator<PGPPublicKeyRing> rings = keyRingCollection.getKeyRings();
            while (rings.hasNext()) {
                Iterator<PGPPublicKey> keys = rings.next().getPublicKeys();
                while (keys.hasNext()) {
                    PGPPublicKey key = keys.next();
                    if (key.isEncryptionKey()) {
                        return key;
                    }
                }
            }
            throw new OpenAS2Exception("No encryption-capable PGP public key found in file for alias: " + alias);
        } catch (IOException | PGPException e) {
            throw new OpenAS2Exception("Failed to load PGP public key for alias: " + alias, e);
        }
    }

    /**
     * Returns the full secret keyring collection. Used by {@link PGPUtils#decrypt} which
     * automatically matches the correct secret key via the key ID in the encrypted message.
     */
    public PGPSecretKeyRingCollection getSecretKeyRingCollection() throws OpenAS2Exception {
        if (secretKeyRingCollection == null) {
            throw new OpenAS2Exception("PGP secret keyring not loaded");
        }
        return secretKeyRingCollection;
    }

    public char[] getPrivateKeyPassphrase() {
        return privateKeyPassphrase;
    }

    /**
     * Resolve the local PGP signing key for {@code alias} from the private keyring.
     * Matches {@code alias} against each key's User ID first (forward-compatible with
     * keyrings holding multiple identities); if no User ID matches and the keyring holds
     * exactly one secret key, falls back to that key, since today's deployed keyrings
     * (see GeneratePGPTestKeys) have no User ID set at all.
     *
     * @param alias the configured {@code pgp_sender_key_alias} value
     * @throws OpenAS2Exception if no usable signing key can be resolved, or extraction fails
     */
    public PGPPrivateKey getSigningKey(String alias) throws OpenAS2Exception {
        if (secretKeyRingCollection == null) {
            throw new OpenAS2Exception("PGP secret keyring not loaded");
        }

        PGPSecretKey matched = null;
        PGPSecretKey onlyKey = null;
        int keyCount = 0;

        Iterator<PGPSecretKeyRing> rings = secretKeyRingCollection.getKeyRings();
        while (rings.hasNext()) {
            PGPSecretKey secretKey = rings.next().getSecretKey();
            if (secretKey == null) {
                continue;
            }
            keyCount++;
            onlyKey = secretKey;
            Iterator<String> userIds = secretKey.getUserIDs();
            while (userIds.hasNext()) {
                if (alias.equals(userIds.next())) {
                    matched = secretKey;
                    break;
                }
            }
        }

        PGPSecretKey signingKey = matched;
        if (signingKey == null) {
            if (keyCount == 1) {
                if (logger.isDebugEnabled()) {
                    logger.debug("No PGP secret key User ID matched alias '" + alias + "'; falling back to the sole key in the private keyring");
                }
                signingKey = onlyKey;
            } else {
                throw new OpenAS2Exception("PGP signing key not found for alias '" + alias + "' (private keyring contains " + keyCount + " keys, none matched by User ID)");
            }
        }

        try {
            return signingKey.extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder().build(privateKeyPassphrase));
        } catch (PGPException e) {
            throw new OpenAS2Exception("Failed to extract PGP private signing key for alias: " + alias, e);
        }
    }
}
