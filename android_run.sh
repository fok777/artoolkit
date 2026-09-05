#!/system/bin/sh
# ============================================================================
# artoolkit Android 启动脚本 (Termux 兼容)
# 在 Android 设备上通过 Termux 运行 artoolkit
# ============================================================================
# 用法:
#   在 Termux 中: ./android_run.sh
#   或: sh android_run.sh
# ============================================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  artoolkit - Android Reverse Engineering Toolkit${NC}"
echo -e "${GREEN}  Version: 1.0.0${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# 检查 Python
if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[!] 未找到 python3，请先在 Termux 中安装: pkg install python3${NC}"
    exit 1
fi

# 检查 Java
if ! command -v java >/dev/null 2>&1; then
    echo -e "${YELLOW}[*] 未找到 java，部分功能可能不可用${NC}"
    echo -e "${YELLOW}    安装: pkg install openjdk-17${NC}"
fi

# 检查必要工具
check_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        echo -e "  ${GREEN}[✓]${NC} $1"
    else
        echo -e "  ${RED}[✗]${NC} $1 (未安装)"
    fi
}

echo -e "${YELLOW}[*] 检查工具链...${NC}"
check_tool aapt
check_tool apktool
check_tool baksmali
check_tool strings
check_tool nm
check_tool objdump
check_tool node
echo ""

# 设置环境变量
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
export PATH="$SCRIPT_DIR:$PATH"

# 检查 artoolkit.py
if [ ! -f "$SCRIPT_DIR/artoolkit.py" ]; then
    echo -e "${RED}[!] 未找到 artoolkit.py${NC}"
    exit 1
fi

# 显示菜单
show_menu() {
    echo -e "${YELLOW}请选择操作:${NC}"
    echo "  1) 综合分析 APK"
    echo "  2) APK 基本信息"
    echo "  3) 加密检测"
    echo "  4) 加固检测"
    echo "  5) Frida 脚本生成"
    echo "  6) SO 分析"
    echo "  7) 资源提取"
    echo "  8) 项目管理"
    echo "  9) 工具状态"
    echo "  0) 退出"
    echo ""
    printf "输入选项 [0-9]: "
}

# 主循环
while true; do
    show_menu
    read -r choice
    case $choice in
        1)
            printf "APK 路径: "
            read -r apk_path
            if [ -f "$apk_path" ]; then
                python3 "$SCRIPT_DIR/artoolkit.py" analyze full --apk "$apk_path"
            else
                echo -e "${RED}[!] 文件不存在: $apk_path${NC}"
            fi
            ;;
        2)
            printf "APK 路径: "
            read -r apk_path
            if [ -f "$apk_path" ]; then
                python3 "$SCRIPT_DIR/artoolkit.py" apk info --apk "$apk_path"
            else
                echo -e "${RED}[!] 文件不存在: $apk_path${NC}"
            fi
            ;;
        3)
            printf "APK 路径: "
            read -r apk_path
            if [ -f "$apk_path" ]; then
                python3 "$SCRIPT_DIR/artoolkit.py" crypto detect --target "$apk_path"
            else
                echo -e "${RED}[!] 文件不存在: $apk_path${NC}"
            fi
            ;;
        4)
            printf "APK 路径: "
            read -r apk_path
            if [ -f "$apk_path" ]; then
                python3 "$SCRIPT_DIR/artoolkit.py" shell detect --apk "$apk_path"
            else
                echo -e "${RED}[!] 文件不存在: $apk_path${NC}"
            fi
            ;;
        5)
            printf "类名 (如 com.example.Main): "
            read -r class_name
            printf "方法名 (如 onCreate): "
            read -r method_name
            printf "输出文件 [frida_hook.js]: "
            read -r dest
            dest=${dest:-frida_hook.js}
            python3 "$SCRIPT_DIR/artoolkit.py" frida generate --class "$class_name" --method "$method_name" --dest "$dest"
            ;;
        6)
            printf "SO 路径: "
            read -r so_path
            if [ -f "$so_path" ]; then
                python3 "$SCRIPT_DIR/artoolkit.py" so info --so "$so_path"
            else
                echo -e "${RED}[!] 文件不存在: $so_path${NC}"
            fi
            ;;
        7)
            printf "APK 路径: "
            read -r apk_path
            printf "输出目录 [./resources]: "
            read -r dest
            dest=${dest:-./resources}
            if [ -f "$apk_path" ]; then
                python3 "$SCRIPT_DIR/artoolkit.py" resource --apk "$apk_path" --dest "$dest"
            else
                echo -e "${RED}[!] 文件不存在: $apk_path${NC}"
            fi
            ;;
        8)
            echo "项目管理:"
            echo "  c) 创建项目"
            echo "  l) 列出项目"
            echo "  b) 返回主菜单"
            printf "选择: "
            read -r proj_choice
            case $proj_choice in
                c)
                    printf "项目名: "
                    read -r proj_name
                    python3 "$SCRIPT_DIR/artoolkit.py" project create --name "$proj_name"
                    ;;
                l)
                    python3 "$SCRIPT_DIR/artoolkit.py" project list
                    ;;
                b) continue ;;
                *) echo "无效选项" ;;
            esac
            ;;
        9)
            python3 "$SCRIPT_DIR/artoolkit.py" tools check
            ;;
        0)
            echo -e "${GREEN}再见!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}无效选项${NC}"
            ;;
    esac
    echo ""
    echo -e "${YELLOW}按 Enter 继续...${NC}"
    read -r tmp
done