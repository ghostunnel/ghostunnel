.PHONY: all
all: root-combined.pem root-key.pem server-combined.pem server-keystore.p12 client-combined.pem client-keystore.p12 server-pkcs8.pem server-key.pem client-pkcs8.pem client-key.pem cacert.pem
	rm -f *.srl *-csr.pem

%-key.pem:
	openssl genrsa -out $@ 2048

%-csr.pem: %-key.pem
	openssl req -new -key $< -out $@ -subj /CN=$(@:-csr.pem=)

root-cert.pem: openssl.ext root-csr.pem root-key.pem
	openssl x509 -req -sha256 -in $< -signkey $(word 2,$^) -out $@ -days 5000 -extfile openssl.ext -extensions root

cacert.pem: root-cert.pem
	cp $< $@

server-cert.pem: openssl.ext server-csr.pem root-combined.pem
	openssl x509 -req -sha256 -in $< -CA $(word 2,$^) -CAkey $(word 2,$^) -CAcreateserial -out $@ -days 5000 -extfile openssl.ext -extensions server

client-cert.pem: openssl.ext client-csr.pem root-combined.pem
	openssl x509 -req -sha256 -in $< -CA $(word 2,$^) -CAkey $(word 2,$^) -CAcreateserial -out $@ -days 5000 -extfile openssl.ext -extensions client

# Combined certificate/key file
%-combined.pem: %-cert.pem %-key.pem
	cat $^ > $@

# Keystore in PKCS#12 format
%-keystore.p12: %-combined.pem
	openssl pkcs12 -export -out $@ -in $< -inkey $< -password pass:

# Private key in PKCS#8 format (for SoftHSM testing)
%-pkcs8.pem: %-key.pem
	openssl pkcs8 -topk8 -inform PEM -outform PEM -in $< -out $@ -nocrypt
