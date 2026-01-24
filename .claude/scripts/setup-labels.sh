#!/bin/bash
# Setup GitHub labels for AWS Encryption SDK project
# Run this script once to create all project labels

set -e

echo "Creating category labels..."

# Category labels (mutually exclusive)
gh label create "feature" --color "0E8A16" --description "New functionality" --force
gh label create "bug" --color "D73A4A" --description "Something broken" --force
gh label create "improvement" --color "A2EEEF" --description "Enhancement to existing functionality" --force
gh label create "refactor" --color "FEF2C0" --description "Cleanup, refactoring, performance" --force
gh label create "documentation" --color "0075CA" --description "Docs, comments, guides" --force
gh label create "research" --color "D4C5F9" --description "Investigation, spikes" --force

echo "Creating area labels..."

# Area labels (can have multiple)
gh label create "keyring" --color "FBCA04" --description "Keyring implementations (Raw AES, Raw RSA, KMS, Multi)" --force
gh label create "cmm" --color "FBCA04" --description "Cryptographic materials manager" --force
gh label create "crypto" --color "FBCA04" --description "Cryptographic operations (AES-GCM, HKDF, ECDSA)" --force
gh label create "format" --color "FBCA04" --description "Message format serialization (header, body, footer)" --force
gh label create "client-api" --color "FBCA04" --description "Public encrypt/decrypt API" --force
gh label create "testing" --color "FBCA04" --description "Test infrastructure, test vectors" --force
gh label create "aws-integration" --color "FBCA04" --description "AWS KMS integration" --force

echo "Labels created successfully!"
echo ""
echo "Category labels: feature, bug, improvement, refactor, documentation, research"
echo "Area labels: keyring, cmm, crypto, format, client-api, testing, aws-integration"
