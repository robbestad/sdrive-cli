#!/bin/bash

# Read version number from Cargo.toml
VERSION=$(grep '^version' Cargo.toml | awk -F '= ' '{ print $2 }' | tr -d '"' | tr -d '\r' )

if [ -z "$VERSION" ]; then
    echo "Error: Failed to read version number from Cargo.toml"
    exit 1
fi

# Get platform information
PLATFORM=$(uname)

echo "Building sdrive version $VERSION for $PLATFORM"

rm -rf output
cargo build --release
cd target/release || exit

rm -rf output
mkdir -p output

cp ../../sdrive.toml .
cp ../../README.md .
zip "sdrive_${VERSION}_${PLATFORM}.zip" sdrive sdrive.toml README.md

# Assuming the fingerprint binary is in the PATH
fingerprint "sdrive_${VERSION}_${PLATFORM}.zip" > "output/SHA256_${VERSION}_${PLATFORM}.txt"

mv "sdrive_${VERSION}_${PLATFORM}.zip" output

mv output ../../

