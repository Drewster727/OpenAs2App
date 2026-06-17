package org.openas2.pgp;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeBodyPart;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

/**
 * Stateless PGP utility methods for NAESB 4.0 payload-level encryption/decryption.
 * Uses BouncyCastle OpenPGP (bcpg-jdk18on).
 */
public class PGPUtils {

    // Magic bytes for binary OpenPGP packets (0xC0 or 0x80 range with type 0-15)
    private static final byte PGP_BINARY_MARKER = (byte) 0x85;  // Public-Key Encrypted Session Key packet
    private static final String PGP_ARMORED_MARKER = "-----BEGIN PGP MESSAGE-----";

    /**
     * Encrypt plaintext bytes using the recipient's PGP public key.
     * Uses AES-256 with integrity protection. Output is binary (not ASCII-armored).
     */
    public static byte[] encrypt(byte[] plaintext, PGPPublicKey recipientKey) throws IOException, PGPException {
        BcPGPDataEncryptorBuilder encryptorBuilder = new BcPGPDataEncryptorBuilder(PGPEncryptedData.AES_256);
        encryptorBuilder.setWithIntegrityPacket(true);
        encryptorBuilder.setSecureRandom(new SecureRandom());

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encryptorBuilder);
        encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(recipientKey));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ByteArrayOutputStream compressedOut = new ByteArrayOutputStream()) {
            // Compress before encryption for better results
            PGPCompressedDataGenerator compressor = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
            try (var compStream = compressor.open(compressedOut)) {
                PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
                try (var literalStream = literalGen.open(compStream, PGPLiteralData.BINARY, "", plaintext.length, new Date())) {
                    literalStream.write(plaintext);
                }
            }
            byte[] compressedBytes = compressedOut.toByteArray();

            try (var encStream = encGen.open(out, compressedBytes.length)) {
                encStream.write(compressedBytes);
            }
        }
        return out.toByteArray();
    }

    /**
     * Decrypt PGP-encrypted bytes using our secret keyring.
     * BouncyCastle automatically matches the correct secret key via the key ID embedded in the message.
     */
    public static byte[] decrypt(byte[] ciphertext, PGPSecretKeyRingCollection secretKeyRings, char[] passphrase)
            throws IOException, PGPException {
        InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(ciphertext));
        JcaPGPObjectFactory pgpFactory = new JcaPGPObjectFactory(in);

        Object obj = pgpFactory.nextObject();

        // Handle PGP armoring wrapper
        PGPEncryptedDataList encDataList;
        if (obj instanceof PGPEncryptedDataList) {
            encDataList = (PGPEncryptedDataList) obj;
        } else {
            encDataList = (PGPEncryptedDataList) pgpFactory.nextObject();
        }

        // Find the encrypted data entry that matches one of our secret keys
        PGPPublicKeyEncryptedData pkeData = null;
        PGPPrivateKey privateKey = null;

        Iterator<?> it = encDataList.getEncryptedDataObjects();
        while (it.hasNext() && privateKey == null) {
            pkeData = (PGPPublicKeyEncryptedData) it.next();
            PGPSecretKey secretKey = secretKeyRings.getSecretKey(pkeData.getKeyID());
            if (secretKey != null) {
                privateKey = secretKey.extractPrivateKey(
                        new JcePBESecretKeyDecryptorBuilder().build(passphrase));
            }
        }

        if (privateKey == null || pkeData == null) {
            throw new PGPException("No matching private key found in secret keyring for this message");
        }

        InputStream decryptedStream = pkeData.getDataStream(
                new JcePublicKeyDataDecryptorFactoryBuilder().build(privateKey));

        JcaPGPObjectFactory plainFactory = new JcaPGPObjectFactory(decryptedStream);
        Object message = plainFactory.nextObject();

        // Unwrap compression if present
        if (message instanceof PGPCompressedData) {
            PGPCompressedData compressed = (PGPCompressedData) message;
            plainFactory = new JcaPGPObjectFactory(compressed.getDataStream());
            message = plainFactory.nextObject();
        }

        if (!(message instanceof PGPLiteralData)) {
            throw new PGPException("Unexpected PGP data type: " + message.getClass().getName());
        }

        PGPLiteralData literalData = (PGPLiteralData) message;
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int bytesRead;
        InputStream literalStream = literalData.getInputStream();
        while ((bytesRead = literalStream.read(buffer)) != -1) {
            result.write(buffer, 0, bytesRead);
        }

        // Verify integrity if the packet supports it
        if (pkeData.isIntegrityProtected() && !pkeData.verify()) {
            throw new PGPException("PGP message integrity check failed");
        }

        return result.toByteArray();
    }

    /**
     * Returns true if the MimeBodyPart content appears to be PGP-encrypted
     * (handles both ASCII-armored and binary OpenPGP format).
     */
    public static boolean isPGPEncrypted(MimeBodyPart part) throws MessagingException, IOException {
        byte[] bytes = extractBytes(part);
        if (bytes.length == 0) {
            return false;
        }
        // ASCII-armored check
        if (bytes.length >= PGP_ARMORED_MARKER.length()) {
            String prefix = new String(bytes, 0, PGP_ARMORED_MARKER.length());
            if (prefix.startsWith(PGP_ARMORED_MARKER)) {
                return true;
            }
        }
        // Binary OpenPGP: first byte is a packet tag. Public-Key Encrypted Session Key
        // packets have tag 1 (old format: 0x84/0x85/0x86/0x87, new format: 0xC1).
        byte firstByte = bytes[0];
        // Check bit 7 is set (all OpenPGP packets) and packet type is 1 (PKESK) or 3 (SKESK)
        if ((firstByte & 0x80) != 0) {
            int tag;
            if ((firstByte & 0x40) != 0) {
                // New format: bits 5-0 are packet tag
                tag = firstByte & 0x3F;
            } else {
                // Old format: bits 5-2 are packet tag
                tag = (firstByte & 0x3C) >> 2;
            }
            // Tag 1 = Public-Key Encrypted Session Key, Tag 3 = Symmetric-Key Encrypted Session Key
            return tag == 1 || tag == 3;
        }
        return false;
    }

    /**
     * Extract the raw byte content from a MimeBodyPart.
     */
    public static byte[] extractBytes(MimeBodyPart part) throws MessagingException, IOException {
        Object content = part.getContent();
        if (content instanceof byte[]) {
            return (byte[]) content;
        }
        if (content instanceof InputStream) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            try (InputStream is = (InputStream) content) {
                while ((bytesRead = is.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }
            }
            return baos.toByteArray();
        }
        // Fallback: treat as string content
        return content.toString().getBytes();
    }

    /**
     * Wrap raw bytes into a MimeBodyPart with the given content-type.
     * Used to re-wrap decrypted or encrypted payload back into a MIME structure.
     */
    public static MimeBodyPart wrapBytes(byte[] data, String contentType) throws MessagingException {
        MimeBodyPart part = new MimeBodyPart();
        part.setContent(data, contentType != null ? contentType : "application/octet-stream");
        part.setHeader("Content-Type", contentType != null ? contentType : "application/octet-stream");
        return part;
    }
}
