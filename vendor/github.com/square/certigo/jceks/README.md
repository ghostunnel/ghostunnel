# JCEKS

Package jceks parses JCEKS (Java Cryptogaphy Extension Key Store)
files and extracts keys and certificates. This module only implements
a fraction of the JCEKS cryptographic protocols. In particular, it
implements the SHA1 signature verification of the key store and the
PBEWithMD5AndDES3CBC cipher for encrypting private keys.
