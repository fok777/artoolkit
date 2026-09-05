#!/bin/bash
set -e

PROJECT_DIR="/workspace/ar_mcp"
APP_DIR="$PROJECT_DIR/app"
BUILD_DIR="$APP_DIR/build"
OUTPUT_DIR="$BUILD_DIR/outputs/apk"
FINAL_DIR="$BUILD_DIR/outputs/final"

ANDROID_SDK="/opt/android-sdk"
BUILD_TOOLS="$ANDROID_SDK/build-tools/35.0.0"
PLATFORM="$ANDROID_SDK/platforms/android-34"

AAPT="$BUILD_TOOLS/aapt"
D8="$BUILD_TOOLS/d8"
ZIPALIGN="$BUILD_TOOLS/zipalign"
APKSIGNER="$BUILD_TOOLS/apksigner"
ANDROID_JAR="$PLATFORM/android.jar"

# Clean
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/gen" "$BUILD_DIR/obj" "$OUTPUT_DIR" "$FINAL_DIR"

echo "=== Step 1: Generate R.java with aapt ==="
$AAPT package -f \
    -S "$APP_DIR/src/main/res" \
    -M "$APP_DIR/src/main/AndroidManifest.xml" \
    -I "$ANDROID_JAR" \
    -m "com.tmx.armcp" \
    -J "$BUILD_DIR/gen" \
    -O "$BUILD_DIR/compiled_res.aid" \
    2>&1 | tail -10

echo "=== Step 2: Compile Java ==="
javac -cp "$ANDROID_JAR" -d "$BUILD_DIR/obj" \
    -sourcepath "$APP_DIR/src/main/java:$BUILD_DIR/gen" \
    "$BUILD_DIR/gen/com/tmx/armcp/R.java" \
    "$APP_DIR/src/main/java/com/tmx/armcp/MainActivity.java" \
    "$APP_DIR/src/main/java/com/tmx/armcp/ToolsActivity.java" \
    "$APP_DIR/src/main/java/com/tmx/armcp/ToolActivity.java" \
    2>&1 | tail -10

echo "=== Step 3: Convert to DEX ==="
$D8 --output "$BUILD_DIR/dex" --lib "$ANDROID_JAR" "$BUILD_DIR/obj"/*.class 2>&1 | tail -5

echo "=== Step 4: Package APK ==="
# Create resources.arsc
$AAPT package -f \
    -S "$APP_DIR/src/main/res" \
    -M "$APP_DIR/src/main/AndroidManifest.xml" \
    -I "$ANDROID_JAR" \
    -m "com.tmx.armcp" \
    -J "$BUILD_DIR/gen" \
    -F "$OUTPUT_DIR/resources.arsc" \
    2>&1 | tail -5

# Add DEX to APK
cd "$OUTPUT_dir"
cp "$BUILD_DIR/dex/classes.dex" .
zip -q app-unaligned.apk classes.dex
cd - > /dev/null

echo "=== Step 5: Align and Sign ==="
$ZIPALIGN -f 4 "$OUTPUT_DIR/app-unaligned.apk" "$OUTPUT_DIR/app-aligned.apk"

# Create debug keystore
keytool -genkeypair -keystore "$FINAL_DIR/debug.keystore" -storepass android \
    -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 \
    -validity 365 -dname "CN=Android Debug,O=Android,C=US" 2>&1 | tail -3

$APKSIGNER sign --ks "$FINAL_DIR/debug.keystore" --storepass android \
    --ks-pass pass:android --key-pass pass:android \
    --ks-key-alias androiddebugkey \
    "$OUTPUT_DIR/app-aligned.apk" -o "$FINAL_DIR/逆向MCP.apk" 2>&1 | tail -5

echo "=== Build complete ==="
ls -la "$FINAL_DIR/逆向MCP.apk"