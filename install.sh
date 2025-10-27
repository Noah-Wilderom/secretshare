#!/bin/bash

set -e

go install github.com/Noah-Wilderom/secretshare@latest

echo "Code signing binary for macOS firewall compatibility..."
codesign --deep --sign - ~/go/bin/secretshare

echo "Installation complete!"