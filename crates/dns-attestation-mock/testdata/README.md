# DKIM key record fixtures

`records.json` holds DKIM key records (the strings of one DNS `TXT` RR each)
for throwaway test keys. TEST ONLY: the domains are the launch providers', but
the keys and selectors are not theirs, and no private key was kept.

| Record | Shape | Expected |
| --- | --- | --- |
| `rsa2048-a` | `v=DKIM1; k=rsa; p=<SubjectPublicKeyInfo>`, split into 255-byte character-strings | RSA-2048 key |
| `rsa2048-b` | no `v=` or `k=` (both default), extra `t=`, `h=`, `n=` tags, whitespace inside `p=` | RSA-2048 key |
| `rsa2048-c` | `p=` holds a bare `RSAPublicKey` | RSA-2048 key |
| `rsa2048-a-blanked` | `rsa2048-a`'s selector with an empty `p=` | revoked |
| `rsa1024`, `rsa4096` | other RSA sizes | parsed; refused by the registry |
| `ed25519` | `k=ed25519` (RFC 8463) | refused: not RSA |
| `wrong-version`, `version-not-first`, `duplicate-tag`, `no-p` | malformed tag-lists | refused |

The formats followed: RFC 6376 §3.2 (tag-lists), §3.6.1 (key tags), and
§3.6.2.2 (character-strings are concatenated with no separator). For `k=rsa`,
§3.6.1's text names a DER `RSAPublicKey`, while its Appendix C procedure
(`openssl rsa -pubout`) produces a DER `SubjectPublicKeyInfo`; reported RFC
6376 erratum 6674 (<https://www.rfc-editor.org/errata/eid6674>) notes that
providers publish the latter. The mock accepts both.

The keys were generated with OpenSSL 4.0.3:

```sh
openssl genrsa -out k.pem 2048                                  # 1024 and 4096 for those records
openssl rsa -in k.pem -pubout -outform DER | base64             # SubjectPublicKeyInfo
openssl rsa -in k.pem -RSAPublicKey_out -outform DER | base64   # RSAPublicKey (rsa2048-c)
openssl genpkey -algorithm ed25519                              # its raw 32-byte public key
```

`src/test.rs` checks the first 16 bytes of each RSA-2048 modulus against
`openssl rsa -noout -modulus` output recorded at generation.
