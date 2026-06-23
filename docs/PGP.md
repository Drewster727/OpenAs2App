# PGP Support

This fork adds optional OpenPGP payload encryption and signing on top of standard AS2. It exists primarily to satisfy NAESB 4.0 EDM transport, which expects sender authentication via OpenPGP signatures rather than X.509/S-MIME (CMS) signatures, but it can be used by any partnership that wants PGP instead of (or alongside) the built-in X.509 `encrypt`/`sign` mechanism.

Both encryption and signing are **optional and configured per partnership** — a partnership that doesn't set the PGP attributes below behaves exactly as it did before this feature existed.

## How it fits together

- AS2's normal S/MIME encrypt/sign (the `encrypt` and `sign` partnership attributes, backed by the AS2 keystore) is untouched and works independently.
- PGP encryption/signing is applied to the payload **before** any S/MIME processing — the PGP-protected payload is what gets wrapped in the AS2 MIME envelope.
- PGP keys live in a separate store from the AS2 X.509 keystore: a local **private keyring** (this station's own PGP keypair) and a **public keys directory** (one ASCII-armored `.asc` file per partner, named by an alias).

## 1. Set up the `<pgpkeys>` component

Add a `<pgpkeys>` element to `config.xml`:

```xml
<pgpkeys classname="org.openas2.pgp.PGPKeyFactory"
    public_keys_dir="/opt/openas2/config/pgp/public_keys"
    private_keyring="/opt/openas2/config/pgp/private_keyring.gpg"
    private_keyring_password="changeit" />
```

- `private_keyring` — a binary OpenPGP secret keyring file holding **this station's own** PGP keypair. Used both to decrypt inbound payloads and (when signing is enabled) to sign outbound payloads.
- `private_keyring_password` — passphrase protecting the secret key(s) in that keyring.
- `public_keys_dir` — a directory of ASCII-armored public keys, one file per partner, named `<alias>.asc`. Used both to encrypt outbound payloads for a partner and (when verification is enabled) to verify that partner's inbound signatures.

If `pgp_encrypt` or `pgp_sign` is set on a partnership but no `<pgpkeys>` component is registered, message processing fails fast with a clear `OpenAS2Exception` rather than silently skipping PGP.

## 2. Generate keys

For real deployments, generate PGP keys with your normal tooling (e.g. `gpg --full-generate-key`), export the public key as ASCII-armored (`gpg --armor --export <id> > <alias>.asc`), and export the secret keyring (`gpg --export-secret-keys > private_keyring.gpg`).

For local testing, the repo includes a generator that produces an RSA-2048 keypair suitable for both encryption and signing:

```bash
mvn exec:java -pl Server \
    -Dexec.mainClass=org.openas2.pgp.GeneratePGPTestKeys \
    -Dexec.classpathScope=test \
    -Dexec.args="config/pgp test-passphrase"
```

This writes `config/pgp/public_keys/partnera.asc` and `config/pgp/private_keyring.gpg`, and prints the key ID and passphrase used. Run it once per station — each station needs its own keypair, and needs the **other** station's public key copied into its own `public_keys_dir` under an alias of your choosing (see below).

> The generated key has no User ID attached. PGP signing key lookup (`pgp_sender_key_alias`, see below) falls back to "the one key in this private keyring" when there's no User ID match — this works out of the box with these generated keys.

## 3. Key layout between two partners

Say station A ("Acme") sends to station B ("Beta"):

- On **A**'s station: A's own keypair is in A's `private_keyring.gpg`. B's public key is copied into A's `public_keys_dir` as `beta.asc`.
- On **B**'s station: B's own keypair is in B's `private_keyring.gpg`. A's public key is copied into B's `public_keys_dir` as `acme.asc`.

The same public key file already needed for PGP **encryption** (so A can encrypt for B, and B can encrypt for A) is reused for PGP **signature verification** — no separate key distribution step is needed for signing.

## 4. Partnership attributes

Set these as flat `<attribute>` elements inside a `<partnership>` block in `partnerships.xml`.

| Attribute | Meaning |
|---|---|
| `pgp_encrypt` | `"true"` to PGP-encrypt the outbound payload. |
| `pgp_receiver_key_alias` | Alias (filename, without `.asc`) of the **receiving partner's** public key in `public_keys_dir`. Used to encrypt outbound payloads for them. |
| `pgp_sign` | `"true"` to PGP-sign the outbound payload, and/or (on the partnership entry matched for inbound processing) to require and verify an inbound PGP signature. |
| `pgp_sender_key_alias` | Dual-purpose, read the same way on both sides: when **this station is sending**, it's the alias of *our own* signing key in the local private keyring; when **this station is receiving**, it's the alias of the *remote partner's* verification key in `public_keys_dir`. |

`pgp_sign` requires `pgp_sender_key_alias` to be set, on whichever side is using it.

### Example: Acme → Beta (sign + encrypt)

On **Acme**'s station, the outbound partnership:

```xml
<partnership name="Acme-to-Beta">
    <sender name="Acme"/>
    <receiver name="Beta"/>
    <attribute name="pgp_encrypt" value="true"/>
    <attribute name="pgp_receiver_key_alias" value="beta"/>
    <attribute name="pgp_sign" value="true"/>
    <attribute name="pgp_sender_key_alias" value="acme"/>
</partnership>
```

Here `pgp_sender_key_alias="acme"` resolves against Acme's own private keyring (signing key).

On **Beta**'s station, the mirrored entry used to match and process this inbound traffic:

```xml
<partnership name="Acme-to-Beta">
    <sender name="Acme"/>
    <receiver name="Beta"/>
    <attribute name="pgp_encrypt" value="true"/>
    <attribute name="pgp_receiver_key_alias" value="beta"/>
    <attribute name="pgp_sign" value="true"/>
    <attribute name="pgp_sender_key_alias" value="acme"/>
</partnership>
```

Same attribute values — but here `pgp_sender_key_alias="acme"` resolves against Beta's `public_keys_dir/acme.asc` (Acme's public key, used to verify the signature). Which key store gets used depends only on which code path runs (sending vs. receiving), not on any extra config.

## 5. Behavior and failure handling

- **Outbound:** if `pgp_encrypt` is set, the payload is PGP-encrypted (and signed first, inline, if `pgp_sign` is also set) before any S/MIME signing/encryption.
- **Inbound:** a PGP-encrypted payload is auto-detected and decrypted. If `pgp_sign` is set on the matched partnership, a signature is *required* — a missing or invalid signature fails the message the same way an X.509 signature failure would: the MDN comes back with `DISP_VERIFY_SIGNATURE_FAILED` ("Authentication of the originator of the message failed"). If `pgp_sign` is not set, an inbound signature (if present) is parsed past but not checked.
- `pgp_sign`/`pgp_encrypt` are independent of the legacy `sign`/`encrypt` (X.509) attributes — nothing disables X.509 automatically. If you're migrating from X.509 to PGP signing, drop `sign="SHA-256"` yourself once PGP signing is verified working end-to-end.

## 6. Relevant source

- `Server/src/main/java/org/openas2/pgp/PGPKeyFactory.java` — the `<pgpkeys>` component; key loading and resolution (`getPublicKey`, `getSigningKey`, `getSecretKeyRingCollection`).
- `Server/src/main/java/org/openas2/pgp/PGPUtils.java` — encrypt/decrypt/sign/verify primitives (`encrypt`, `signAndEncrypt`, `decrypt`, `decryptAndVerify`).
- `Server/src/main/java/org/openas2/partner/Partnership.java` — attribute constants (`PA_PGP_ENCRYPT`, `PID_PGP_RECEIVER_KEY_ALIAS`, `PA_PGP_SIGN`, `PID_PGP_SENDER_KEY_ALIAS`).
- `Server/src/main/java/org/openas2/processor/sender/AS2SenderModule.java` (`secure()`) and `Server/src/main/java/org/openas2/processor/receiver/AS2ReceiverHandler.java` (`decryptAndVerify()`) — where the above is wired into the send/receive pipeline.
- `Server/src/test/java/org/openas2/pgp/` — `PGPUtilsTest`, `PGPKeyFactoryTest`, and `GeneratePGPTestKeys` (the test key generator referenced above).
