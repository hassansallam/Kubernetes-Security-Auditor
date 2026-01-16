#!/bin/bash

# K8s Security Auditor - Cross-platform Build Script
# Builds binaries for Linux, macOS, and Windows

set -e

VERSION=${VERSION:-"v1.0.0"}
BINARY_NAME="k8s-security-auditor"
OUTPUT_DIR="dist"

echo "Building K8s Security Auditor ${VERSION}"
echo "========================================="

# Clean previous builds
rm -rf ${OUTPUT_DIR}
mkdir -p ${OUTPUT_DIR}

# Ensure dependencies are tidy
echo "Tidying dependencies..."
go mod tidy

# Get dependencies
echo "Downloading dependencies..."
go mod download

# Build for Linux amd64
echo "Building for Linux amd64..."
GOOS=linux GOARCH=amd64 go build -o ${OUTPUT_DIR}/${BINARY_NAME}-linux-amd64 \
    -ldflags "-X main.version=${VERSION}" \
    .

# Build for Linux arm64
echo "Building for Linux arm64..."
GOOS=linux GOARCH=arm64 go build -o ${OUTPUT_DIR}/${BINARY_NAME}-linux-arm64 \
    -ldflags "-X main.version=${VERSION}" \
    .

# Build for macOS amd64
echo "Building for macOS amd64..."
GOOS=darwin GOARCH=amd64 go build -o ${OUTPUT_DIR}/${BINARY_NAME}-darwin-amd64 \
    -ldflags "-X main.version=${VERSION}" \
    .

# Build for macOS arm64 (Apple Silicon)
echo "Building for macOS arm64..."
GOOS=darwin GOARCH=arm64 go build -o ${OUTPUT_DIR}/${BINARY_NAME}-darwin-arm64 \
    -ldflags "-X main.version=${VERSION}" \
    .

# Build for Windows amd64
echo "Building for Windows amd64..."
GOOS=windows GOARCH=amd64 go build -o ${OUTPUT_DIR}/${BINARY_NAME}-windows-amd64.exe \
    -ldflags "-X main.version=${VERSION}" \
    .

echo ""
echo "Build complete! Binaries:"
echo "========================"
ls -lh ${OUTPUT_DIR}/

# Calculate checksums
echo ""
echo "Generating checksums..."
cd ${OUTPUT_DIR}
sha256sum * > checksums.txt
cd ..

echo ""
echo "Checksums:"
cat ${OUTPUT_DIR}/checksums.txt

echo ""
echo "Build artifacts saved to: ${OUTPUT_DIR}/"
