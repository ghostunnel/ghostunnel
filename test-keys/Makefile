all: root client server

root:
	openssl genrsa -out root.key 1024
	openssl req -x509 -new -key root.key -days 1000 -out root.crt -subj /C=US/ST=CA/O=ghostunnel/OU=root

server:
	openssl genrsa -out server.key 1024
	openssl req -new -key server.key -out server.csr -subj /C=US/ST=CA/O=ghostunnel/OU=server
	openssl x509 -req -in server.csr -CA root.crt -CAkey root.key -CAcreateserial -out server.crt -days 1000 -extfile openssl.ext
	openssl pkcs12 -export -out server.p12 -in server.crt -inkey server.key -password pass:

client:
	openssl genrsa -out client.key 1024
	openssl req -new -key client.key -out client.csr -subj /C=US/ST=CA/O=ghostunnel/OU=client
	openssl x509 -req -in client.csr -CA root.crt -CAkey root.key -CAcreateserial -out client.crt -days 1000 -extfile openssl.ext
	openssl pkcs12 -export -out client.p12 -in client.crt -inkey client.key -password pass:
