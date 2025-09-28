# Remote Attestation: Remote Verifier

This is the code of the Remote Verifier counterpart for the Remote Attestation TA. A `Dockerfile` is provided for easy deployment and configuration

## Build

Building the Docker image is as easy as executing `docker build -t <name>:<tag> .` (with an adequate name & tag).


## Configuration

For running the image, using a `docker-compose.yml` is advised. An example is provided.

This container requires two certificates (with private key) and a binary file to run. The path is flexible and must be specified using an environment variable:

- `CA_CERT_PATH`: path to the certificate used for signing the mTLS client certificates
- `CA_KEY_PATH` path to the key used for signing the mTLS client certs
- `SSL_CERT_PATH`: path to the TLS certificate used for the server
- `SSL_KEY_PATH`: path to the key for the TLS server certificate
- `TARGET_VALUE_PATH`: path to the file which contains the content of the memory as it should be to get a positive attestation result
- `NONCE_DB_PATH`: path to the file which keeps track of already used nonces to prevent reuse (must be provided as an initially empty file)

How the volumes are mounted can be arbitrary as long as the environment variables are adjusted.

The required certificates and keys can be created using the provided `create_keys.py` script. Alternatively, OpenSSL can be used.
