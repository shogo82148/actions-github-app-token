#!/bin/bash

set -euxo pipefail

KMS_KEY_ID=$1
IMPORT_KEY=$2

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Get the wrapping public key and import token from AWS KMS.
PARAMS=$(aws kms get-parameters-for-import \
  --key-id "$KMS_KEY_ID" \
  --wrapping-algorithm RSA_AES_KEY_WRAP_SHA_256 \
  --wrapping-key-spec RSA_4096 \
  --output json)
echo "$PARAMS" | jq -r '.PublicKey' | base64 --decode > "$TMP_DIR/WrappingPublicKey.bin"
echo "$PARAMS" | jq -r '.ImportToken' | base64 --decode > "$TMP_DIR/ImportToken.bin"

# Encrypt the key material using the wrapping public key.

# Generate a 32-byte AES symmetric encryption key.
openssl rand -out "$TMP_DIR/aes-key.bin" 32

# Encrypt your key material with the AES symmetric encryption key.
openssl pkcs8 -topk8 -inform PEM -outform DER \
  -in "$IMPORT_KEY" -out "$TMP_DIR/PrivateKey.der" -nocrypt
openssl enc -id-aes256-wrap-pad \
  -K "$(xxd -p < "$TMP_DIR/aes-key.bin" | tr -d '\n')" \
  -iv A65959A6 \
  -in "$TMP_DIR/PrivateKey.der" \
  -out "$TMP_DIR/key-material-wrapped.bin"

# Encrypt your AES symmetric encryption key with the downloaded public key.
openssl pkeyutl \
  -encrypt \
  -in "$TMP_DIR/aes-key.bin" \
  -out "$TMP_DIR/aes-key-wrapped.bin" \
  -inkey "$TMP_DIR/WrappingPublicKey.bin" \
  -keyform DER \
  -pubin \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256

# Combine the encrypted AES key and encrypted key material in a file
cat "$TMP_DIR/aes-key-wrapped.bin" "$TMP_DIR/key-material-wrapped.bin" > "$TMP_DIR/EncryptedKeyMaterial.bin"

# Import the encrypted key material into AWS KMS.
aws kms import-key-material \
  --key-id "$KMS_KEY_ID" \
  --encrypted-key-material "fileb://$TMP_DIR/EncryptedKeyMaterial.bin" \
  --import-token "fileb://$TMP_DIR/ImportToken.bin" \
  --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE
