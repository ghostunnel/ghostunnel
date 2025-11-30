# JCEKS

Package jceks reads and writes JCEKS (Java Cryptogaphy Extension Key Store) files containing private keys and certificates.
This module implements only a fraction of the JCEKS cryptographic protocols.
In particular, it implements the SHA1 signature verification of the keystore and the PBEWithMD5AndDES3CBC cipher for encrypting private keys.
