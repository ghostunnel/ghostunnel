Generate test keys
==================

The certificates and keys contained in this directory have been generated for
test/development purposes only. Do not use these files in production
deployments! See below for instructions on how these keys were generated.

You must first generate a root certificate:

    openssl genrsa -out root.key 1024
    openssl req -x509 -new -key root.key -days 5 -out root.crt -subj /C=US/ST=CA/O=ghostunnel/OU=root

Configure OpenSSL to set extensions and subject alt names:

    cat >openssl.ext <<EOF
    extendedKeyUsage = clientAuth, serverAuth
    subjectAltName = IP:127.0.0.1,IP:::1
    EOF

Finally you can sign server and client certificates:

    openssl genrsa -out server.key 1024
    openssl req -new -key server.key -out server.csr -subj /C=US/ST=CA/O=ghostunnel/OU=server
    openssl x509 -req -in server.csr -CA root.crt -CAkey root.key -CAcreateserial -out server.crt -days 5 -extfile openssl.ext
    openssl pkcs12 -export -out server.p12 -in server.crt -inkey server.key -password pass:

    openssl genrsa -out client.key 1024
    openssl req -new -key client.key -out client.csr -subj /C=US/ST=CA/O=ghostunnel/OU=client
    openssl x509 -req -in client.csr -CA root.crt -CAkey root.key -CAcreateserial -out client.crt -days 5 -extfile openssl.ext
    openssl pkcs12 -export -out client.p12 -in client.crt -inkey client.key -password pass:

