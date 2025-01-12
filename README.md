# Node.js MLS

> This project is not ready for use. Any help on inplementation/interpretation of the specification(s) is appreciated.

```text
DAVE → RFC9420 (MLS) → RFC9180 (HPKE)
             ↑
```

**Experimental** implementation of Messaging Layer Security primarily for use with an implementation of Discord's DAVE protocol ([shipgirlproject/node-dave](https://github.com/shipgirlproject/node-dave/)), so not all of the MLS specification is implemented.

## Status
Target: Partial [RFC9420](https://datatracker.ietf.org/doc/html/rfc9420) (MLS v1)

### HPKE
```text
DAVE → RFC9420 (MLS) → RFC9180 (HPKE)
                             ↑
```

Target: Partial [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html) with [MLS considerations](https://www.rfc-editor.org/rfc/rfc9420.html#name-cryptographic-objects)

Underlying cryptographic operations relies on the [noble cryptography](https://paulmillr.com/noble/) libraries.

Notes/deviations from spec:
- Byte strings are represented as buffers (to get a byte/hex string, use `<Key>.raw.toString('hex')`)
- No serialization/deserialization
- Maximum context sequence number is `Number.MAX_SAFE_INTEGER` for practical reasons
- Single shot APIs are not implemented

#### AEAD
- [x] AES-128-GCM
  - NOTE: non-standard errors, FIXME

#### KEM
- [x] DHKEM(P-256, HKDF-SHA256)
  - NOTE: non-standard errors, FIXME

#### KDF
- [x] HKDF-SHA256
  - NOTE: non-standard errors, FIXME

### Cipher Suite
- [ ] DHKEMP256_AES128GCM_SHA256_P256

### Credential
- [ ] Basic

### Extensions
- Group
  - [ ] External Senders
