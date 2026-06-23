# PGP AS2 EDI Validation — Two-Station Test

This is a step-by-step runbook for standing up two independent OpenAS2 stations locally with Docker and exchanging a PGP-signed, PGP-encrypted AS2 EDI message between them — useful whenever you're changing anything in `org.openas2.pgp.*`, `AS2SenderModule`/`AS2ReceiverHandler`'s PGP handling, or just want to confirm PGP encrypt/sign still works end-to-end. See `docs/PGP.md` for the feature/config reference this test exercises.

Everything below lives in a `validation/` folder at the repo root. **That folder is not committed** — it holds generated private keyrings and is purely a local scratch environment. Recreate it fresh each time using the steps below (or reuse one you already built).

## What this validates

Two stations, `MyCompany` and `PartnerA`, configured with **PGP only** — no X.509 `sign`/`encrypt` attributes — so a successful run proves PGP encryption *and* the PGP signing feature (`pgp_sign` / `pgp_sender_key_alias`) are doing all the work:

```
MyCompany station                                PartnerA station
  EDI file dropped in outbox
  → PGP sign (own private key)
  → PGP encrypt (partner's public key)
  → AS2 POST over HTTP  ────────────────────→   → AS2 receive
                                                  → PGP decrypt (own private key)
                                                  → PGP verify (partner's public key)
                                                  → store plaintext EDI
                                                ←──────────────────  MDN response
```

## 1. Create the folder structure

From the repo root:

```bash
mkdir -p validation/config validation/config-partner
rsync -a --exclude='DB' --exclude='as2_certs.p12' --exclude='ssl_certs.jks' Server/src/config/ validation/config/
rsync -a --exclude='DB' --exclude='as2_certs.p12' --exclude='ssl_certs.jks' Server/src/config/ validation/config-partner/
cp Server/src/config/as2_certs.p12 validation/config/as2_certs.p12
cp Server/src/config/as2_certs.p12 validation/config-partner/as2_certs.p12
mkdir -p validation/data/outbox/PartnerA_OID validation/data-partner/outbox/MyCompany_OID
```

`Server/src/config/` is the shipped default install template — it gives you a working `config.xml`/`logback.xml`/etc. baseline for both stations without having to write one from scratch. The X.509 `as2_certs.p12` is copied along purely so `PKCS12CertificateFactory` has a valid file to load at startup — its contents are irrelevant here since this test doesn't use X.509 sign/encrypt at all.

## 2. Add `<pgpkeys>` to both stations' `config.xml`

Insert this block in each, right before the `<certificates ...>` element (use a different `private_keyring_password` per station):

**`validation/config/config.xml`** (MyCompany):
```xml
<pgpkeys classname="org.openas2.pgp.PGPKeyFactory"
         public_keys_dir="%home%/pgp/public_keys"
         private_keyring="%home%/pgp/private_keyring.gpg"
         private_keyring_password="mycompany-passphrase"/>
```

**`validation/config-partner/config.xml`** (PartnerA):
```xml
<pgpkeys classname="org.openas2.pgp.PGPKeyFactory"
         public_keys_dir="%home%/pgp/public_keys"
         private_keyring="%home%/pgp/private_keyring.gpg"
         private_keyring_password="partnera-passphrase"/>
```

## 3. Write `partnerships.xml` for both stations

**`validation/config/partnerships.xml`** (MyCompany — sends to PartnerA):
```xml
<partnerships>
    <partner name="MyCompany" as2_id="MyCompany_OID" x509_alias="mycompany" email="as2msgs@openas2.com"/>
    <partner name="PartnerA" as2_id="PartnerA_OID" x509_alias="partnera" email="as2msgs@partnera.com"/>

    <!-- Outbound: MyCompany sends to PartnerA. PGP-only auth/confidentiality. -->
    <partnership name="MyCompany-to-PartnerA">
        <sender name="MyCompany"/>
        <receiver name="PartnerA"/>
        <pollerConfig enabled="true"/>
        <attribute name="protocol" value="as2"/>
        <attribute name="content_transfer_encoding" value="binary"/>
        <attribute name="subject" value="File $attributes.filename$ sent from $sender.name$ to $receiver.name$"/>
        <attribute name="as2_url" value="http://openas2_partner:10080"/>
        <attribute name="as2_mdn_to" value="edi@myCompany.com"/>
        <attribute name="as2_mdn_options" value="signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, SHA-256"/>
        <attribute name="pgp_encrypt" value="true"/>
        <attribute name="pgp_receiver_key_alias" value="partnera"/>
        <attribute name="pgp_sign" value="true"/>
        <attribute name="pgp_sender_key_alias" value="mycompany"/>
        <attribute name="resend_max_retries" value="3"/>
    </partnership>

    <!-- Inbound: matched when PartnerA sends to MyCompany. -->
    <partnership name="PartnerA-to-MyCompany">
        <sender name="PartnerA"/>
        <receiver name="MyCompany"/>
        <attribute name="store_received_file_to" value="$properties.storageBaseDir$/inbox/$msg.receiver.as2_id$/inbox/$msg.sender.as2_id$-$rand.12345$-$msg.content-disposition.filename$"/>
        <attribute name="pgp_sign" value="true"/>
        <attribute name="pgp_sender_key_alias" value="partnera"/>
    </partnership>
</partnerships>
```

**`validation/config-partner/partnerships.xml`** (PartnerA — receives from MyCompany):
```xml
<partnerships>
    <partner name="MyCompany" as2_id="MyCompany_OID" x509_alias="mycompany" email="as2msgs@openas2.com"/>
    <partner name="PartnerA" as2_id="PartnerA_OID" x509_alias="partnera" email="as2msgs@partnera.com"/>

    <!-- Inbound: matched when MyCompany sends to PartnerA (PartnerA's local copy of the same direction). -->
    <partnership name="MyCompany-to-PartnerA">
        <sender name="MyCompany"/>
        <receiver name="PartnerA"/>
        <attribute name="store_received_file_to" value="$properties.storageBaseDir$/inbox/$msg.receiver.as2_id$/inbox/$msg.sender.as2_id$-$rand.12345$-$msg.content-disposition.filename$"/>
        <attribute name="pgp_sign" value="true"/>
        <attribute name="pgp_sender_key_alias" value="mycompany"/>
    </partnership>

    <!-- Outbound: PartnerA sends to MyCompany (not exercised by this runbook, kept for symmetry). -->
    <partnership name="PartnerA-to-MyCompany">
        <sender name="PartnerA"/>
        <receiver name="MyCompany"/>
        <pollerConfig enabled="true"/>
        <attribute name="protocol" value="as2"/>
        <attribute name="content_transfer_encoding" value="binary"/>
        <attribute name="subject" value="File $attributes.filename$ sent from $sender.name$ to $receiver.name$"/>
        <attribute name="as2_url" value="http://openas2:10080"/>
        <attribute name="as2_mdn_to" value="edi@partnera.com"/>
        <attribute name="as2_mdn_options" value="signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, SHA-256"/>
        <attribute name="pgp_encrypt" value="true"/>
        <attribute name="pgp_receiver_key_alias" value="mycompany"/>
        <attribute name="pgp_sign" value="true"/>
        <attribute name="pgp_sender_key_alias" value="partnera"/>
        <attribute name="resend_max_retries" value="3"/>
    </partnership>
</partnerships>
```

Note both stations carry an identical copy of the `MyCompany-to-PartnerA` entry — that's intentional, see `docs/PGP.md` for why.

## 4. Generate and cross-distribute PGP keys

`Server/src/test/java/org/openas2/pgp/GeneratePGPTestKeys.java` always writes its public key as `public_keys/partnera.asc` regardless of which station it's run for (it's a test-only tool, not station-aware), so generate each station's keys into a scratch directory first, then place/rename the files explicitly:

```bash
mkdir -p /tmp/mycompany_keys /tmp/partnera_keys

./mvnw -q exec:java -pl Server \
    -Dexec.mainClass=org.openas2.pgp.GeneratePGPTestKeys \
    -Dexec.classpathScope=test \
    -Dexec.args="/tmp/mycompany_keys mycompany-passphrase"

./mvnw -q exec:java -pl Server \
    -Dexec.mainClass=org.openas2.pgp.GeneratePGPTestKeys \
    -Dexec.classpathScope=test \
    -Dexec.args="/tmp/partnera_keys partnera-passphrase"

mkdir -p validation/config/pgp/public_keys validation/config-partner/pgp/public_keys

# Own private keyrings
cp /tmp/mycompany_keys/private_keyring.gpg validation/config/pgp/private_keyring.gpg
cp /tmp/partnera_keys/private_keyring.gpg validation/config-partner/pgp/private_keyring.gpg

# MyCompany needs PartnerA's public key under alias "partnera"
cp /tmp/partnera_keys/public_keys/partnera.asc validation/config/pgp/public_keys/partnera.asc

# PartnerA needs MyCompany's public key under alias "mycompany" (note the rename)
cp /tmp/mycompany_keys/public_keys/partnera.asc validation/config-partner/pgp/public_keys/mycompany.asc

rm -rf /tmp/mycompany_keys /tmp/partnera_keys
```

Resulting layout:
```
validation/config/pgp/private_keyring.gpg              ← MyCompany's own key
validation/config/pgp/public_keys/partnera.asc          ← PartnerA's public key
validation/config-partner/pgp/private_keyring.gpg       ← PartnerA's own key
validation/config-partner/pgp/public_keys/mycompany.asc ← MyCompany's public key
```

## 5. Write `validation/docker-compose.yml`

Uses a separate build context (`..`, since `Dockerfile` lives at the repo root) and host ports that won't collide with the main `docker-compose.yml` stack if it's already running (4080/4081/8080/8443):

```yaml
services:
  openas2:
    build:
      context: ..
      dockerfile: Dockerfile
    ports:
      - 6080:10080
      - 6081:10081
    tty: true
    stdin_open: true
    volumes:
      - ./config:/opt/openas2/config:rw
      - ./data:/opt/openas2/data:rw

  openas2_partner:
    build:
      context: ..
      dockerfile: Dockerfile
    ports:
      - 6082:10080
      - 6083:10081
    tty: true
    stdin_open: true
    volumes:
      - ./config-partner:/opt/openas2/config:rw
      - ./data-partner:/opt/openas2/data:rw
```

## 6. Build and start

Use a distinct compose project name (`-p as2pgpval`) so this never gets confused with, or torn down by, the main stack:

```bash
docker compose -f validation/docker-compose.yml -p as2pgpval build
docker compose -f validation/docker-compose.yml -p as2pgpval up -d
```

Confirm both stations loaded the PGP key factory cleanly:

```bash
docker compose -f validation/docker-compose.yml -p as2pgpval logs openas2 | grep "PGP key factory"
docker compose -f validation/docker-compose.yml -p as2pgpval logs openas2_partner | grep "PGP key factory"
```

Both should print `PGP key factory loaded.` with no errors above it.

## 7. Test A — signed + encrypted message (happy path)

Drop any EDI file into MyCompany's outbox:

```bash
cat > validation/data/outbox/PartnerA_OID/test.edi << 'EOF'
ISA*00*          *00*          *ZZ*MYCOMPANY      *ZZ*PARTNERA       *260101*1200*^*00401*000000001*0*P*>~
GS*PO*MYCOMPANY*PARTNERA*20260101*1200*1*X*004010~
ST*850*0001~
BEG*00*NE*PO-00001**20260101~
PO1*1*100*CF**BP*GAS-001~
CTT*1~
AMT*TT*5000.00~
SE*7*0001~
GE*1*1~
IEA*1*000000001~
EOF
```

The directory poller picks it up within ~5 seconds. Check the MDN and stored file:

```bash
docker compose -f validation/docker-compose.yml -p as2pgpval logs openas2 --tail 30 | grep -iE "MDN \[|authenticated|signature"
cat validation/data-partner/inbox/PartnerA_OID/inbox/*
```

**Expected MDN text:** `...the EDI Interchange was successfully decrypted and its integrity was verified. In addition, the sender of the message, Sender MyCompany_OID... was authenticated as the originator of the message.` The stored file in PartnerA's inbox should match what you dropped, byte for byte.

## 8. Test B — encrypted but unsigned message (must be rejected)

Flip `pgp_sign` to `false` on the sending side only, to simulate a partner that hasn't enabled PGP signing, and confirm the receiver (which still requires it) rejects the message rather than silently accepting it:

```bash
sed -i '' 's#<attribute name="pgp_sign" value="true"/>\n        <attribute name="pgp_sender_key_alias" value="mycompany"/>#&#' validation/config/partnerships.xml  # no-op placeholder; edit MyCompany-to-PartnerA's pgp_sign to "false" manually instead
```

(Simplest is to just open `validation/config/partnerships.xml` and change the `pgp_sign` value to `false` on the `MyCompany-to-PartnerA` partnership, leaving PartnerA's config untouched.)

```bash
docker compose -f validation/docker-compose.yml -p as2pgpval restart openas2
cat > validation/data/outbox/PartnerA_OID/test_unsigned.edi << 'EOF'
ISA*00*          *00*          *ZZ*MYCOMPANY      *ZZ*PARTNERA       *260101*1201*^*00401*000000002*0*P*>~
GS*PO*MYCOMPANY*PARTNERA*20260101*1201*2*X*004010~
ST*850*0002~
SE*1*0002~
GE*1*2~
IEA*1*000000002~
EOF
docker compose -f validation/docker-compose.yml -p as2pgpval logs openas2_partner --tail 30
```

**Expected:** PartnerA logs `org.bouncycastle.openpgp.PGPException: Expected PGP signature not present in decrypted message`, returns an MDN with disposition `processed/Error:integrity-check-failed` and text `...Authentication of the originator of the message failed.`, and stores the message under `validation/data-partner/inbox/error/` instead of the real inbox.

Set `pgp_sign` back to `true` and `docker compose -f validation/docker-compose.yml -p as2pgpval restart openas2` before re-running Test A, otherwise MyCompany's resend queue will keep retrying the unsigned message and keep failing — `DirectoryResenderModule` retransmits the exact already-secured bytes from the original send, it does not re-sign on resend. If that happens, just delete the stuck file(s) under `validation/data/resend/`.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No matching private key found in secret keyring for this message` | Public key sent to a partner doesn't match that partner's actual private keyring | Regenerate both keypairs and re-run the cross-distribution step in order |
| `PGP key factory loaded.` missing from startup logs | `<pgpkeys>` element missing/misplaced in `config.xml`, or the keyring/dir paths are wrong | Confirm the block from step 2 is present and `validation/config*/pgp/` files actually exist |
| `pgp_sign requires pgp_sender_key_alias to be set in partnership '...'` | `pgp_sign="true"` set without `pgp_sender_key_alias` | Add the missing attribute |
| MDN: `...Authentication of the originator of the message failed.` | Either a genuinely missing/invalid signature (see Test B), or `pgp_sender_key_alias` points at the wrong public key file in `public_keys_dir` | Check the alias matches the `.asc` filename actually present, and that it's the correct partner's key |
| `Table "MSG_METADATA" not found (this database is empty)` errors in logs | The embedded H2 message-tracking DB schema wasn't initialized in this fresh data volume | Harmless for this test — it only affects message-tracking persistence, not AS2/PGP processing. Ignore, or run `Server/src/bin/h2_create_new_db.sh` against the station's `DB/` directory if you need tracking to work |
| File stays in outbox, nothing happens | `pollerConfig enabled="true"` missing from the sending partnership, or `<pgpkeys>` not registered while `pgp_encrypt`/`pgp_sign` is set (check logs for a startup `OpenAS2Exception`) | Verify the partnership and config blocks above |

## Cleanup

```bash
docker compose -f validation/docker-compose.yml -p as2pgpval down
rm -rf validation/
```
