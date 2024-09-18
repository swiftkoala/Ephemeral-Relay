#!/bin/bash

# Directory for storing certificates
CERT_DIR="../certificates"

# Check if the certificates directory exists
if [ ! -d "$CERT_DIR" ]; then
    mkdir -p "$CERT_DIR"
fi

# Generate the server private key
openssl genpkey -algorithm RSA -out $CERT_DIR/server.key

# Generate the Certificate Signing Request (CSR)
openssl req -new -key $CERT_DIR/server.key -out $CERT_DIR/server.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=example.com"

# Generate the self-signed certificate
openssl x509 -req -days 365 -in $CERT_DIR/server.csr -signkey $CERT_DIR/server.key -out $CERT_DIR/server.crt

# Generate a CA Certificate (Optional)
openssl req -new -x509 -days 365 -key $CERT_DIR/server.key -out $CERT_DIR/ca.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=example.com"

# Clean up the CSR
rm $CERT_DIR/server.csr

echo "Certificates generated in the $CERT_DIR directory."