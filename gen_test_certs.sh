#!/bin/sh

key=`mktemp /tmp/tmp.XXXXXXXXX`
crt=`mktemp /tmp/tmp.XXXXXXXXX`
ext=`mktemp /tmp/tmp.XXXXXXXXX`
csr=`mktemp /tmp/tmp.XXXXXXXXX`

cat >$ext <<EOF
[ extensions ]
basicConstraints = CA:true
keyUsage = digitalSignature, keyEncipherment, keyAgreement, keyCertSign
extendedKeyUsage = clientAuth, serverAuth
subjectAltName = IP:127.0.0.1,IP:::1
EOF

openssl genrsa -out $key 2048
openssl req -key $key -new -out $csr -sha256 -nodes -subj '/CN=localhost/'
openssl x509 -req -days 365 -in $csr -signkey $key -out $crt -extfile $ext -extensions extensions

cp $key server.key
cp $crt server.crt
cp $crt ca-bundle.crt
