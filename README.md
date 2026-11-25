# PKI Certificate Verification System

A local Public Key Infrastructure (PKI) web application for issuing,
verifying and revoking X.509 certificates.

## PKI Hierarchy

Root CA
   |
   | signs
   v
Intermediate CA
   |
   | signs
   v
End-Entity Certificate

The Root CA acts as the trust anchor.

The Intermediate CA issues server and user certificates.

## Main Features

- RSA key generation
- Self-signed Root CA
- Intermediate CA
- X.509 certificate issuance
- Server certificates
- User certificates
- Subject Alternative Names
- SHA-256 signatures
- SHA-256 fingerprints
- Certificate trust-chain verification
- Trusted-root verification
- Certificate revocation
- Signed X.509 CRLs
- Security Test Lab
- OpenSSL cross-validation
- Verification history
- Audit events
- Automated pytest testing

## Technology Stack

- Python 3
- Flask
- Python cryptography
- MySQL
- MySQL Workbench
- mysql-connector-python
- python-dotenv
- HTML5
- CSS3
- Bootstrap
- Vanilla JavaScript
- OpenSSL
- pytest

## Security

Private keys are stored only on the local filesystem.

Private keys are never displayed through the web interface.

Database credentials are stored in a local .env file.

The .env file and generated cryptographic material are excluded from Git.