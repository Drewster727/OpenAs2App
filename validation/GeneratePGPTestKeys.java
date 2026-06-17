package org.openas2.pgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

/**
 * Generates a PGP RSA key pair and writes:
 *   <outputDir>/public_keys/partnera.asc  — ASCII-armored public key
 *   <outputDir>/private_keyring.gpg       — binary secret keyring
 *
 * Usage: mvn exec:java -pl Server -Dexec.mainClass=org.openas2.pgp.GeneratePGPTestKeys \
 *            -Dexec.classpathScope=test \
 *            -Dexec.args="config/pgp test-passphrase"
 */
public class GeneratePGPTestKeys {

    public static void main(String[] args) throws Exception {
        // args: <outputDir> <alias> <passphrase> [<extraPublicKeyDestDir>]
        String outputDir = args.length > 0 ? args[0] : "config/pgp";
        String alias     = args.length > 1 ? args[1] : "partnera";
        String passphrase = args.length > 2 ? args[2] : "test-passphrase";
        String extraPublicKeyDir = args.length > 3 ? args[3] : null;

        Security.addProvider(new BouncyCastleProvider());

        System.out.println("Generating RSA-2048 PGP key pair...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(
                PublicKeyAlgorithmTags.RSA_GENERAL, kp, new Date());

        PGPSecretKey secretKey = new PGPSecretKey(
                pgpKeyPair.getPrivateKey(),
                pgpKeyPair.getPublicKey(),
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                true, // is master key
                new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .build(passphrase.toCharArray()));

        // Write public key as ASCII-armored .asc
        File publicKeysDir = new File(outputDir, "public_keys");
        publicKeysDir.mkdirs();
        File publicKeyFile = new File(publicKeysDir, alias + ".asc");
        byte[] pubKeyBytes;
        try (java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
             ArmoredOutputStream armoredOut = new ArmoredOutputStream(baos)) {
            PGPPublicKeyRing pubRing = new PGPPublicKeyRing(
                    java.util.Collections.singletonList(pgpKeyPair.getPublicKey()));
            pubRing.encode(armoredOut);
            armoredOut.close();
            pubKeyBytes = baos.toByteArray();
        }
        try (OutputStream fos = new FileOutputStream(publicKeyFile)) {
            fos.write(pubKeyBytes);
        }
        System.out.println("Public key written to: " + publicKeyFile.getAbsolutePath());

        // Optionally copy the public key to a second destination (cross-distribution)
        if (extraPublicKeyDir != null) {
            File extraDir = new File(extraPublicKeyDir);
            extraDir.mkdirs();
            File extraFile = new File(extraDir, alias + ".asc");
            try (OutputStream fos = new FileOutputStream(extraFile)) {
                fos.write(pubKeyBytes);
            }
            System.out.println("Public key also written to: " + extraFile.getAbsolutePath());
        }

        // Write secret keyring as binary .gpg
        File privateKeyFile = new File(outputDir, "private_keyring.gpg");
        try (OutputStream fos = new FileOutputStream(privateKeyFile)) {
            PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(
                    java.util.Collections.singletonList(secretKey));
            secretKeyRing.encode(fos);
        }
        System.out.println("Private keyring written to: " + privateKeyFile.getAbsolutePath());
        System.out.println("Passphrase: " + passphrase);
        System.out.printf("Key ID: %016X%n", pgpKeyPair.getPublicKey().getKeyID());
    }
}
