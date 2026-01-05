#!/bin/bash
# Build macOS .app bundle for PMACS VPN
set -e

APP_NAME="PMACS VPN"
VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)

echo "Building PMACS VPN v${VERSION} for macOS..."

# Build release binary
cargo build --release

# Create bundle structure
APP_DIR="target/release/${APP_NAME}.app"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

# Copy binary
cp target/release/pmacs-vpn "$APP_DIR/Contents/MacOS/"

# Copy Info.plist and update version
sed "s/0\.1\.0/${VERSION}/g" assets/macos/Info.plist > "$APP_DIR/Contents/Info.plist"

# Copy icons if they exist
if [ -f assets/macos/AppIcon.icns ]; then
    cp assets/macos/AppIcon.icns "$APP_DIR/Contents/Resources/"
fi

echo ""
echo "Built: $APP_DIR"
echo ""
echo "To test locally:"
echo "  open \"$APP_DIR\" --args tray"
echo ""
echo "To install:"
echo "  cp -r \"$APP_DIR\" /Applications/"
echo ""
echo "Notes:"
echo "  - LSUIElement=true hides app from Dock (menu bar only)"
echo "  - First run may require allowing in System Preferences > Security"
