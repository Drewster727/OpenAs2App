# NAESB 4.0 PGP Validation Runbook

This document describes how to reproduce the end-to-end PGP payload encryption test between two OpenAS2 instances. Everything needed is in the `validation/` folder.

---

## Overview

NAESB 4.0 requires **PGP encryption at the EDI payload level**, inside the AS2 envelope. This is separate from the existing S/MIME layer — three independent security layers stack on top of each other:

```
EDI payload
  └─ PGP encrypt (partner's public key)       ← NAESB 4.0 requirement
       └─ AS2 envelope (S/MIME sign/encrypt)   ← existing AS2 standard
            └─ TLS (transport)                 ← network layer
```

Each party holds:
- Their own **private key** (for decrypting inbound messages)
- The other party's **public key** (for encrypting outbound messages)

Inbound PGP decryption is **auto-detected** — if `PGPKeyFactory` is registered and the payload looks like a PGP message, it decrypts automatically. Outbound encryption is **opt-in per partnership** via `pgp_encrypt=true` in `partnerships.xml`.

---

## Architecture

Two Docker containers communicate over Docker's internal network:

| Container | AS2 ID | Internal hostname | Host ports |
|-----------|--------|-------------------|------------|
| `openas2` | `MyCompany_OID` | `openas2` | 4080 (AS2), 4081 (MDN), 8443 (REST API) |
| `openas2_partner` | `PartnerA_OID` | `openas2_partner` | 5080 (AS2), 5081 (MDN) |

**Outbound pipeline:**
```
EDI file → directory poller → PGPUtils.encrypt() → AS2SenderModule → HTTP POST
```

**Inbound pipeline:**
```
HTTP POST → AS2ReceiverHandler → S/MIME unwrap → PGPUtils.isPGPEncrypted() → PGPUtils.decrypt() → store file
```

---

## Files in This Folder

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Defines both containers, port mappings, and volume mounts |
| `config/config.xml` | MyCompany OpenAS2 config — includes `<pgpkeys>` registration |
| `config/partnerships.xml` | MyCompany partnerships — `pgp_encrypt=true` on outbound to PartnerA |
| `config-partner/config.xml` | PartnerA OpenAS2 config — includes `<pgpkeys>` registration |
| `config-partner/partnerships.xml` | PartnerA partnerships — `pgp_encrypt=true` on outbound to MyCompany |
| `GeneratePGPTestKeys.java` | Reference copy of the key generation utility |

> The runnable key generator lives at `Server/src/test/java/org/openas2/pgp/GeneratePGPTestKeys.java`.

---

## Prerequisites

- Docker and Docker Compose
- Maven wrapper (`./mvnw`) — only needed for key generation
- The repo built at least once so the Maven local cache is populated

---

## Step 1 — Generate PGP Keys

Run the key generator twice from the **repo root**. The optional 4th argument cross-distributes each party's public key to the other's config.

```bash
# Generate MyCompany's key pair
# Writes: config/pgp/private_keyring.gpg
#         config/pgp/public_keys/mycompany.asc
# Copies: config-partner/pgp/public_keys/mycompany.asc  (PartnerA needs this to encrypt to MyCompany)
./mvnw exec:java -pl Server \
  -Dexec.mainClass=org.openas2.pgp.GeneratePGPTestKeys \
  -Dexec.classpathScope=test \
  -Dexec.args="config/pgp mycompany mycompany-passphrase config-partner/pgp/public_keys"

# Generate PartnerA's key pair
# Writes: config-partner/pgp/private_keyring.gpg
#         config-partner/pgp/public_keys/partnera.asc
# Copies: config/pgp/public_keys/partnera.asc  (MyCompany needs this to encrypt to PartnerA)
./mvnw exec:java -pl Server \
  -Dexec.mainClass=org.openas2.pgp.GeneratePGPTestKeys \
  -Dexec.classpathScope=test \
  -Dexec.args="config-partner/pgp partnera partnera-passphrase config/pgp/public_keys"
```

After this step the key layout should be:

```
config/
  pgp/
    private_keyring.gpg              ← MyCompany private key
    public_keys/
      mycompany.asc                  ← MyCompany public key (self)
      partnera.asc                   ← PartnerA public key (received from partner)

config-partner/
  pgp/
    private_keyring.gpg              ← PartnerA private key
    public_keys/
      partnera.asc                   ← PartnerA public key (self)
      mycompany.asc                  ← MyCompany public key (received from partner)
```

> Do **not** commit `private_keyring.gpg` files to git.

---

## Step 2 — Build and Start Containers

From the repo root:

```bash
docker compose build
docker compose up -d
```

Confirm both containers loaded their PGP key factories:

```bash
docker compose logs openas2 | grep "PGP key factory"
docker compose logs openas2_partner | grep "PGP key factory"
```

Both should show:
```
INFO org.openas2.XMLSession - PGP key factory loaded.
```

---

## Step 3 — Run the Tests

### Test A: PartnerA → MyCompany

Drop any EDI file into PartnerA's outbox:

```bash
cat > data-partner/outbox/MyCompany_OID/test_inbound.edi << 'EOF'
ISA*00*          *00*          *ZZ*PARTNERA       *ZZ*MYCOMPANY      *260101*1200*^*00401*000000001*0*P*>~
GS*FA*PARTNERA*MYCOMPANY*20260101*1200*1*X*004010~
ST*997*0001~
AK1*PO*1~
AK9*A*1*1*1~
SE*3*0001~
GE*1*1~
IEA*1*000000001~
EOF
```

Within ~5 seconds the directory poller picks it up, PGP-encrypts it with MyCompany's public key, and POSTs it to `http://openas2:10080`.

**Verify success:**
```bash
# Check logs for "processed" MDN (no "decryption-failed")
docker compose logs openas2 | tail -20

# Check the stored file is readable EDI (not binary PGP data)
cat data/inbox/MyCompany_OID/inbox/*
```

### Test B: MyCompany → PartnerA

```bash
cat > data/outbox/PartnerA_OID/test_outbound.edi << 'EOF'
ISA*00*          *00*          *ZZ*MYCOMPANY      *ZZ*PARTNERA       *260101*1200*^*00401*000000002*0*P*>~
GS*PO*MYCOMPANY*PARTNERA*20260101*1200*2*X*004010~
ST*850*0001~
BEG*00*NE*PO-00001**20260101~
PO1*1*100*CF**BP*GAS-001~
CTT*1~
AMT*TT*5000.00~
SE*7*0001~
GE*1*2~
IEA*1*000000002~
EOF
```

**Verify success:**
```bash
docker compose logs openas2 | grep "test_outbound" | grep "processed"
cat data-partner/inbox/PartnerA_OID/inbox/*
```

---

## Key Configuration Reference

### config.xml — register the PGP key factory

```xml
<pgpkeys classname="org.openas2.pgp.PGPKeyFactory"
         public_keys_dir="%home%/pgp/public_keys"
         private_keyring="%home%/pgp/private_keyring.gpg"
         private_keyring_password="mycompany-passphrase"/>
```

### partnerships.xml — enable PGP per outbound partnership

```xml
<attribute name="pgp_encrypt" value="true"/>
<attribute name="pgp_receiver_key_alias" value="partnera"/>
```

The alias maps to a file: `<public_keys_dir>/<alias>.asc`. Inbound decryption requires no partnership attributes — it is triggered automatically when the payload is detected as PGP-encrypted.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No matching private key found in secret keyring` | Public key sent to partner doesn't match the private keyring | Regenerate keys and re-run both commands in Step 1 in order |
| `PGP key factory loaded` not in logs | `<pgpkeys>` element missing from config.xml or keyring file path wrong | Verify config.xml has the `<pgpkeys>` block and the `.gpg` file exists |
| MDN returns `decryption-failed` | Key mismatch or wrong passphrase | Check container logs for the specific Java exception |
| File stays in outbox | Partnership `pgp_encrypt=true` but `PGPKeyFactory` not registered | Ensure both `<pgpkeys>` in config.xml and keys on disk are present |
| Stored file is binary (not EDI) | `isPGPEncrypted` returned false — decryption skipped | Confirm the first byte of the received payload is an OpenPGP packet tag |
