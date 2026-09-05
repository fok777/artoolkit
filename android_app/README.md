# 逆向MCP Android 应用

原生 Android 应用，基于 artoolkit 项目构建，提供完整的安卓逆向工程工具箱。

## 功能特性

- 📦 **APK 分析** - 分析 APK 结构、权限、组件
- 📄 **SO 逆向** - 分析原生库架构和符号
- 🪝 **Frida 脚本** - 生成 Hook/Trace/Intercept 脚本
- 🌐 **网络抓包** - 捕获网络流量
- 🔐 **加密识别** - 识别加密算法和硬编码密钥
- 🔓 **字符串解密** - XOR/Base64/RC4 解密
- 🔍 **DEX 反编译** - 反编译 DEX 文件
- 🛡️ **Shell 检测** - 检测 Shell 环境
- 🤖 **Unidbg 模拟** - 模拟执行分析
- 📦 **资源提取** - 提取 APK 中的资源文件
- 🎨 **Flutter 解析** - 解析 Flutter 应用
- 📋 **会话管理** - 管理分析会话
- 📁 **项目管理** - 管理逆向项目

## 构建方式

### 方式一：使用 Gradle（推荐）

```bash
cd android_app
./gradlew assembleDebug
```

生成的 APK 位于 `app/build/outputs/apk/debug/app-debug.apk`

### 方式二：使用手动构建脚本

```bash
cd android_app
bash build_apk.sh
```

生成的 APK 位于 `app/build/outputs/final/逆向MCP.apk`

### 方式三：使用 Android Studio

1. 打开 Android Studio
2. File -> Open -> 选择 android_app 目录
3. 等待 Gradle 同步完成
4. Build -> Generate Signed Bundle / APK

## 项目结构

```
android_app/
├── app/
│   ├── build.gradle          # 应用级构建配置
│   ├── proguard-rules.pro    # 代码混淆规则
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/com/tmx/armcp/
│       │   ├── MainActivity.java      # 主界面
│       │   ├── ToolsActivity.java     # 工具列表
│       │   └── ToolActivity.java      # 工具详情
│       └── res/
│           ├── layout/                # 界面布局
│           ├── drawable/             # 图标
│           ├── mipmap-*/            # 应用图标
│           └── values/               # 字符串、颜色、主题
├── build.gradle               # 根级构建配置
├── settings.gradle            # 项目设置
└── build_apk.sh               # 手动构建脚本
```

## 依赖

- Android SDK 34
- Android Gradle Plugin 8.2.2
- Kotlin 1.9.22
- AndroidX Components
- Google Material Components

## 许可证

MIT License