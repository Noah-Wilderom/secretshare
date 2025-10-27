#!/bin/bash

# Generate GPG key if it doesn't exist
if ! gpg --list-secret-keys | grep -q "client@test.local"; then
    echo "Generating GPG key for Docker client..."

    cat > /tmp/gpg-key-config <<EOF
%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: Docker Test Client
Name-Email: client@test.local
Expire-Date: 0
EOF

    gpg --batch --gen-key /tmp/gpg-key-config
    rm /tmp/gpg-key-config

    echo "GPG key generated successfully!"
    gpg --list-secret-keys
else
    echo "GPG key already exists"
fi

# Execute the command passed to docker run
exec "$@"