# artoolkit - Android Reverse Engineering Toolkit

## 概述

**artoolkit** 是一个功能齐全的安卓逆向工程工具箱，集成了 APK 分析、SO 逆向、Frida 脚本生成、网络捕获、加密识别等核心能力。基于 Python 3 构建，通过统一的 CLI 接口提供丰富的逆向工程功能。

## 📱 原生 Android 应用

我们提供了一个完整的原生 Android 应用，位于 `android_app/` 目录，提供图形化界面操作。

### 快速开始

```bash
# 使用 Gradle 构建
cd android_app
./gradlew assembleDebug

# 或使用手动构建脚本
bash build_apk.sh
```

### 应用特性

- 📦 APK 分析 - 分析 APK 结构、权限、组件
- 📄 SO 逆向 - 分析原生库架构和符号
- 🪝 Frida 脚本 - 生成 Hook/Trace/Intercept 脚本
- 🌐 网络抓包 - 捕获网络流量
- 🔐 加密识别 - 识别加密算法和硬编码密钥
- 🔓 字符串解密 - XOR/Base64/RC4 解密
- 🔍 DEX 反编译 - 反编译 DEX 文件
- 🛡️ Shell 检测 - 检测 Shell 环境
- 🤖 Unidbg 模拟 - 模拟执行分析
- 📦 资源提取 - 提取 APK 中的资源文件
- 🎨 Flutter 解析 - 解析 Flutter 应用
- 📋 会话管理 - 管理分析会话
- 📁 项目管理 - 管理逆向项目

## 快速入门

### 安装依赖

```bash
# 安装系统工具 (Termux)
pkg install python3 aapt apktool baksmali openjdk-17

# 安装 Python 依赖
pip install pyyaml
```

### 运行方式

```bash
# 方式1: CLI 命令行
python3 artoolkit.py --help

# 方式2: Android 交互式菜单 (Termux)
sh android_run.sh

# 方式3: Web UI 浏览器访问
python3 web_ui.py --port 8080
# 然后在浏览器中访问 http://localhost:8080

# 方式4: 构建独立 APK
python3 build_apk.py --output ./kivy_build --build
```

## 命令参考

### analyze - 综合分析

```bash
# 完整分析（加密、加固、SO、网络等）
python3 artoolkit.py analyze full --apk app.apk

# 快速分析
python3 artoolkit.py analyze quick --apk app.apk

# JSON 输出
python3 artoolkit.py analyze full --apk app.apk --json --output result.json
```

### apk - APK 基本分析

```bash
python3 artoolkit.py apk info --apk app.apk
python3 artoolkit.py apk manifest --apk app.apk
python3 artoolkit.py apk permissions --apk app.apk
```

### crypto - 加密检测

```bash
python3 artoolkit.py crypto detect --target app.apk
python3 artoolkit.py crypto keys --target app.apk
python3 artoolkit.py crypto libs --target libnative.so
```

### dex - DEX 分析

```bash
python3 artoolkit.py dex extract --apk app.apk --dest ./dex_output
python3 artoolkit.py dex info --apk app.apk
```

### so - SO 文件分析

```bash
python3 artoolkit.py so info --so libnative.so
python3 artoolkit.py so strings --so libnative.so
python3 artoolkit.py so unity --so libunity.so
python3 artoolkit.py so symbols --so libnative.so
```

### shell - 加固检测

```bash
python3 artoolkit.py shell detect --apk app.apk
python3 artoolkit.py shell dex --apk app.apk
python3 artoolkit.py shell frida --apk app.apk --dest frida_dump.js
```

### frida - Frida 脚本生成

```bash
python3 artoolkit.py frida generate --class com.example.Main --method onCreate --type hook
python3 artoolkit.py frida generate --class com.example.Main --method onCreate --type trace
python3 artoolkit.py frida generate --class com.example.Main --method onCreate --type intercept
python3 artoolkit.py frida list
```

### flutter - Flutter 分析

```bash
python3 artoolkit.py flutter detect --apk app.apk
python3 artoolkit.py flutter strings --apk app.apk
python3 artoolkit.py flutter methods --apk app.apk
```

### string - 字符串解密

```bash
python3 artoolkit.py string xor --data "encrypted" --key "mykey"
python3 artoolkit.py string base64 --data "SGVsbG8="
python3 artoolkit.py string rc4 --data "encrypted" --key "mykey"
python3 artoolkit.py string auto --target app.apk
```

### unidbg - Unidbg 模拟

```bash
python3 artoolkit.py unidbg java --so libnative.so --class com.example.Native
python3 artoolkit.py unidbg native --so libnative.so --function nativeFunction
python3 artoolkit.py unidbg signatures --so libnative.so
python3 artoolkit.py unidbg config --so libnative.so --type java --class com.example.Native --methods method1,method2
```

### network - 网络分析

```bash
python3 artoolkit.py network scan --apk app.apk
python3 artoolkit.py network urls --apk app.apk
python3 artoolkit.py network ports --apk app.apk
```

### resource - 资源提取

```bash
python3 artoolkit.py resource --apk app.apk --dest ./resources
```

### project - 项目管理

```bash
python3 artoolkit.py project create --name my-project --desc "项目描述"
python3 artoolkit.py project list
python3 artoolkit.py project switch --name my-project
python3 artoolkit.py project remove --name my-project
```

### session - 会话管理

```bash
python3 artoolkit.py session create --apk app.apk --name session1
python3 artoolkit.py session list
python3 artoolkit.py session switch --session_id xxx
python3 artoolkit.py session remove --session_id xxx
```

### tools - 工具状态

```bash
python3 artoolkit.py tools check
python3 artoolkit.py tools so
```

## 项目结构

```
artoolkit/
├── artoolkit.py          # CLI 入口与适配器
├── web_ui.py             # Web UI 包装器
├── android_run.sh        # Android 交互式菜单
├── build_apk.py          # APK 构建器
├── build_apk_android.sh  # Android APK 构建脚本
├── modules/              # 功能模块
│   ├── apk_analysis.py   # APK 分析
│   ├── crypto_detect.py  # 加密检测
│   ├── dex_decompile.py  # DEX 反编译
│   ├── flutter_parse.py  # Flutter 解析
│   ├── frida_gen.py      # Frida 脚本生成
│   ├── network_capture.py # 网络捕获
│   ├── project_manager.py # 项目管理
│   ├── resource_extract.py # 资源提取
│   ├── session_manager.py # 会话管理
│   ├── shell_detect.py   # 加固检测
│   ├── so_analysis.py    # SO 分析
│   ├── string_decrypt.py # 字符串解密
│   └── unidbg_sim.py     # Unidbg 模拟
└── projects/             # 项目数据
```

## 功能特性

### APK 分析
- 获取 APK 基本信息（包名、版本、文件大小等）
- 提取 AndroidManifest.xml 信息
- 提取 APK 权限列表
- DEX 文件提取与信息获取
- 资源文件提取

### 安全检测
- 加固方案检测（360、腾讯、百度、阿里等 19 种）
- DEX 完整性检查
- 加密算法检测（AES、DES、RSA、ECC 等 18 种）
- 硬编码密钥提取
- 加密库检测（OpenSSL、BouncyCastle 等 11 种）

### SO 逆向
- SO 文件基本信息（架构、类型、链接方式）
- Unity 引擎检测与 Il2CPP 符号提取
- 字符串提取与分类
- 函数签名提取

### Frida 脚本生成
- Hook 脚本生成
- Trace 脚本生成
- Intercept 脚本生成
- 内存 Dump 脚本（脱壳用）
- RPC 调用桩生成

### 字符串解密
- XOR 加密检测与解密
- Base64 编码检测与解密
- RC4 加密检测与解密
- 自动检测与批量解密

### Flutter 分析
- Flutter 框架检测
- Dart 字符串提取
- Dart 方法名提取

### Unidbg 模拟
- Java 模拟脚本生成
- Native 模拟脚本生成
- 函数签名提取
- 完整模拟配置生成

### 网络分析
- 网络请求特征扫描
- URL 和域名提取
- 网络端口检测

### 项目与会话管理
- 项目创建、切换、删除
- 会话创建、切换、删除

## Android 适配

### Termux 兼容
- `android_run.sh` 提供交互式菜单
- 自动检测工具链
- 支持所有 CLI 命令

### Web UI
- `web_ui.py` 提供 Web 界面
- 支持在 Android 浏览器中访问
- 图形化操作界面

### 独立 APK
- `build_apk.py` 使用 Kivy 构建
- `build_apk_android.sh` 在 Android 上直接构建
- 生成独立的 Android 应用

## 依赖

- Python 3.8+
- apktool
- baksmali
- aapt
- Java 8+
- Node.js (可选)
- PyYAML

## 许可证

MIT License