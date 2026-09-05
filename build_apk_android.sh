#!/system/bin/sh
# ============================================================================
# artoolkit APK 构建脚本
# 在 Android 设备上构建 artoolkit APK
# 依赖: Termux, Python, Java JDK
# ============================================================================
# 用法:
#   在 Termux 中: ./build_apk.sh
#   或: sh build_apk.sh
# ============================================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  artoolkit APK 构建脚本 v1.0.0${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# 检查环境
check_env() {
    local errors=0

    # Python
    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${RED}[✗] python3 未安装${NC}"
        errors=$((errors + 1))
    else
        echo -e "${GREEN}[✓] python3: $(python3 --version)${NC}"
    fi

    # Java
    if ! command -v java >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] java 未安装，尝试安装...${NC}"
        pkg install -y openjdk-17 2>/dev/null || echo -e "${RED}[✗] 无法安装 Java${NC}"
        errors=$((errors + 1))
    else
        echo -e "${GREEN}[✓] java: $(java -version 2>&1 | head -1)${NC}"
    fi

    # Gradle
    if ! command -v gradle >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] gradle 未安装，尝试安装...${NC}"
        pkg install -y gradle 2>/dev/null || true
    fi

    # SDK
    if [ -z "$ANDROID_HOME" ]; then
        export ANDROID_HOME=/data/data/com.termux/files/home
        if [ ! -d "$ANDROID_HOME/sdk" ]; then
            echo -e "${YELLOW}[*] 正在下载 Android SDK...${NC}"
            pkg install -y android-sdk 2>/dev/null || true
        fi
    fi

    # Buildozer
    if ! command -v buildozer >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] 正在安装 buildozer...${NC}"
        pip3 install buildozer 2>/dev/null || pip install buildozer 2>/dev/null || true
    fi

    if [ $errors -gt 0 ]; then
        echo -e "${RED}[!] 环境检查失败，请安装上述依赖${NC}"
        return 1
    fi
    return 0
}

# 创建项目结构
create_project() {
    local project_dir="$1"
    echo -e "${YELLOW}[*] 创建项目结构...${NC}"

    mkdir -p "$project_dir"
    cd "$project_dir" || return 1

    # 复制 artoolkit 源码
    local src_dir="$(cd "$(dirname "$0")" && pwd)"
    cp -r "$src_dir/modules" . 2>/dev/null || true
    cp "$src_dir/artoolkit.py" . 2>/dev/null || true
    cp "$src_dir/web_ui.py" . 2>/dev/null || true
    cp "$src_dir/android_run.sh" . 2>/dev/null || true

    # 创建 buildozer.spec
    cat > buildozer.spec << 'SPECEOF'
[app]
title = artoolkit
package.name = artoolkit
package.domain = org.artoolkit
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0.0
description = Android Reverse Engineering Toolkit
author.name = artoolkit
author.email = artoolkit@example.com
orientation = landscape
android.api = 34
android.min_api = 21
android.sdk = 34
android.ndk = 25b
android.build_tools = 34.0.0
p4a.source.symlinks = True
requirements = python3,kivy
android.add_src = $(src.dir)
android.add_assets = assets
android.add_native_libraries = armeabi-v7a,arm64-v8a

[buildozer]
warn_on_root = 1
log_level = 2

[app]
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE
SPECEOF

    echo -e "${GREEN}[✓] 项目结构已创建${NC}"
}

# 构建 APK
build_apk() {
    local project_dir="$1"
    echo -e "${YELLOW}[*] 开始构建 APK...${NC}"
    cd "$project_dir" || return 1

    # 初始化 buildozer
    buildozer init 2>/dev/null || true

    # 构建
    buildozer -v android debug 2>&1 | tail -30

    if [ -f "bin/artoolkit*.apk" ]; then
        echo -e "${GREEN}[✓] APK 构建成功!${NC}"
        echo -e "  路径: $project_dir/bin/artoolkit*.apk"
        return 0
    else
        echo -e "${RED}[✗] APK 构建失败${NC}"
        return 1
    fi
}

# 主流程
main() {
    local project_dir="${1:-/data/local/tmp/artoolkit_build}"

    echo -e "${YELLOW}[*] 检查环境...${NC}"
    if ! check_env; then
        echo -e "${RED}[!] 环境不满足要求，请先安装依赖${NC}"
        exit 1
    fi

    echo ""
    echo -e "${YELLOW}[*] 创建项目...${NC}"
    if ! create_project "$project_dir"; then
        echo -e "${RED}[!] 项目创建失败${NC}"
        exit 1
    fi

    echo ""
    echo -e "${YELLOW}[*] 构建 APK...${NC}"
    if build_apk "$project_dir"; then
        echo ""
        echo -e "${GREEN}============================================${NC}"
        echo -e "${GREEN}  构建完成!${NC}"
        echo -e "${GREEN}============================================${NC}"
        echo ""
        echo "APK 位置: $project_dir/bin/"
        echo ""
        echo "安装方法:"
        echo "  pm install -r $project_dir/bin/artoolkit*.apk"
        echo ""
        echo "或者使用 adb:"
        echo "  adb install -r $project_dir/bin/artoolkit*.apk"
    else
        echo -e "${RED}[!] 构建失败，请检查日志${NC}"
        exit 1
    fi
}

main "$@"