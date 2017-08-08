all: root client server

root:
	openssl genrsa -out root.key 2048
	openssl req -new -key root.key -out root.csr -subj /C=US/ST=CA/O=ghostunnel/OU=root
	openssl x509 -req -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -sha256 -in root.csr -signkey root.key -out root.crt -days 1000 -extfile openssl.ext -extensions root

server:
	openssl genrsa -out server.key 2048
	openssl req -new -key server.key -out server.csr -subj /C=US/ST=CA/O=ghostunnel/OU=server/CN=server
	openssl x509 -req -sha256 -in server.csr -CA root.crt -CAkey root.key -CAcreateserial -out server.crt -days 1000 -extfile openssl.ext -extensions leaf
	openssl pkcs12 -export -out server.p12 -in server.crt -inkey server.key -password pass:
	openssl pkcs8 -topk8 -inform PEM -outform PEM -in server.key -out server.pkcs8.key -nocrypt

client:
	openssl genrsa -out client.key 2048
	openssl req -new -key client.key -out client.csr -subj /C=US/ST=CA/O=ghostunnel/OU=client/CN=client
	openssl x509 -req -sha256 -in client.csr -CA root.crt -CAkey root.key -CAcreateserial -out client.crt -days 1000 -extfile openssl.ext -extensions leaf
	openssl pkcs12 -export -out client.p12 -in client.crt -inkey client.key -password pass:
	openssl pkcs8 -topk8 -inform PEM -outform PEM -in client.key -out client.pkcs8.key -nocrypt
