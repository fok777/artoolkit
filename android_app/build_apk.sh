#!/bin/bash
set -e

PROJECT_DIR="/workspace/ar_mcp"
APP_DIR="$PROJECT_DIR/app"
BUILD_DIR="$APP_DIR/build"
INTERMEDIATE_DIR="$BUILD_DIR/intermediates"
DEX_DIR="$BUILD_DIR/intermediates/dex"
CLASSES_DIR="$BUILD_DIR/intermediates/classes"
COMPILED_RESOURCES="$BUILD_DIR/intermediates/compiled_resources"
OUTPUT_DIR="$BUILD_DIR/outputs/apk"
FINAL_DIR="$BUILD_DIR/outputs/final"

ANDROID_SDK="/opt/android-sdk"
BUILD_TOOLS="$ANDROID_SDK/build-tools/35.0.0"
PLATFORM="$ANDROID_SDK/platforms/android-34"

AAPT2="$BUILD_TOOLS/aapt2"
D8="$BUILD_TOOLS/d8"
ZIPALIGN="$BUILD_TOOLS/zipalign"
APKSIGNER="$BUILD_TOOLS/apksigner"

ANDROID_JAR="$PLATFORM/android.jar"

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$INTERMEDIATE_DIR" "$DEX_DIR" "$CLASSES_DIR" "$COMPILED_RESOURCES" "$OUTPUT_DIR" "$FINAL_DIR"

echo "=== Step 1: Compile resources with aapt2 ==="
$AAPT2 compile \
    -o "$COMPILED_RESOURCES" \
    --base "$APP_DIR/src/main/res" \
    --base "$COMPILED_RESOURCES" \
    --java "$COMPILED_RESOURCES" \
    2>&1 | tail -5

echo "=== Step 2: Generate R.java ==="
$AAPT2 link \
    --java "$COMPILED_RESOURCES/R.java" \
    --manifest "$APP_DIR/src/main/AndroidManifest.xml" \
    --resources "$COMPILED_RESOURCES" \
    --platform "$PLATFORM" \
    --auto-add-overlay \
    -o "$COMPILED_RESOURCES/merged_resources.apk" \
    2>&1 | tail -5

echo "=== Step 3: Compile Java sources ==="
javac \
    -cp "$ANDROID_JAR" \
    -d "$CLASSES_DIR" \
    -sourcepath "$APP_DIR/src/main/java" \
    "$APP_DIR/src/main/java/com/tmx/armcp/MainActivity.java" \
    "$APP_DIR/src/main/java/com/tmx/armcp/ToolsActivity.java" \
    "$APP_DIR/src/main/java/com/tmx/armcp/ToolActivity.java" \
    "$COMPILED_RESOURCES/R.java" \
    2>&1

echo "=== Step 4: Convert to DEX ==="
$D8 \
    --output "$DEX_DIR" \
    --lib "$ANDROID_JAR" \
    "$CLASSES_DIR"/*.class \
    2>&1 | tail -5

echo "=== Step 5: Package APK ==="
# Create initial APK with resources and DEX
$AAPT2 link \
    --java "$COMPILED_RESOURCES/R.java" \
    --manifest "$APP_DIR/src/main/AndroidManifest.xml" \
    --resources "$COMPILED_RESOURCES" \
    --platform "$PLATFORM" \
    --auto-add-overlay \
    -o "$OUTPUT_DIR/app-unaligned.apk" \
    2>&1 | tail -5

# Add DEX files to APK
cd "$OUTPUT_DIR"
zip -q app-unaligned.apk classes.dex
cd - > /dev/null

echo "=== Step 6: Align APK ==="
$ZIPALIGN -f 4 "$OUTPUT_DIR/app-unaligned.apk" "$OUTPUT_DIR/app-aligned.apk"

echo "=== Step 7: Sign APK ==="
# Create a debug keystore
keytool -genkeypair \
    -keystore "$FINAL_DIR/debug.keystore" \
    -storepass android \
    -alias androiddebugkey \
    -keypass android \
    -keyalg RSA \
    -keysize 2048 \
    -validity 365 \
    -dname "CN=Android Debug,O=Android,C=US" \
    2>&1 | tail -3

$APKSIGNER sign \
    --ks "$FINAL_DIR/debug.keystore" \
    --storepass android \
    --ks-pass pass:android \
    --key-pass pass:android \
    --ks-key-alias androiddebugkey \
    "$OUTPUT_DIR/app-aligned.apk" \
    -o "$FINAL_DIR/逆向MCP.apk" \
    2>&1 | tail -5

echo "=== Build complete ==="
ls -la "$FINAL_DIR/逆向MCP.apk"