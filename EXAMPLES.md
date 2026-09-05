# artoolkit 使用示例

## 示例 1：分析 APK 基本信息

```bash
# 获取 APK 的包名、版本、文件大小等
python3 artoolkit.py apk info --apk /path/to/app.apk

# 输出示例：
# {
#   "success": true,
#   "apk": "/path/to/app.apk",
#   "size": 45678901,
#   "file_count": 1234,
#   "dex_files": ["classes.dex", "classes2.dex"],
#   "so_files": ["lib/armeabi-v7a/libnative.so", "lib/arm64-v8a/libnative.so"],
#   "resource_count": 567,
#   "manifest": {
#     "size": 12345,
#     "present": true
#   }
# }
```

## 示例 2：检测 APK 加固

```bash
# 检测 APK 使用了哪种加固方案
python3 artoolkit.py shell detect --apk /path/to/app.apk

# 输出示例：
# {
#   "detected": true,
#   "shell_type": "lib",
#   "shell_name": "360",
#   "confidence": 0.95,
#   "indicators": ["lib360so.so", "lib360dex.so"],
#   "description": "360加固 - 检测到360加固方案",
#   "all_detections": [...]
# }
```

## 示例 3：检测加密算法

```bash
# 检测 APK 中使用了哪些加密算法
python3 artoolkit.py crypto detect --apk /path/to/app.apk

# 提取硬编码的密钥
python3 artoolkit.py crypto keys --apk /path/to/app.apk

# 检测 SO 文件中使用的加密库
python3 artoolkit.py crypto libs --apk /path/to/libnative.so
```

## 示例 4：提取 DEX 文件

```bash
# 从 APK 中提取所有 DEX 文件
python3 artoolkit.py dex extract --apk /path/to/app.apk --dest ./dex_output

# 获取 DEX 文件信息
python3 artoolkit.py dex info --apk /path/to/app.apk
```

## 示例 5：生成 Frida 脚本

```bash
# 生成 Hook 脚本
python3 artoolkit.py frida generate \
  --class com.example.app.MainActivity \
  --method getData \
  --dest hook.js

# 生成 Trace 脚本
python3 artoolkit.py frida generate \
  --class com.example.app.MainActivity \
  --method getData \
  --type trace \
  --dest trace.js

# 生成 Intercept 脚本
python3 artoolkit.py frida generate \
  --class com.example.app.MainActivity \
  --method getData \
  --type intercept \
  --dest intercept.js

# 列出所有可用模板
python3 artoolkit.py frida list
```

## 示例 6：生成脱壳脚本

```bash
# 生成 Frida 内存 dump 脚本（用于脱壳）
python3 artoolkit.py shell frida \
  --apk /path/to/app.apk \
  --dest frida_dump.js
```

## 示例 7：SO 文件分析

```bash
# 获取 SO 文件基本信息
python3 artoolkit.py so info --apk /path/to/libnative.so

# 检测是否为 Unity 引擎
python3 artoolkit.py so unity --apk /path/to/libunity.so

# 提取 SO 中的字符串
python3 artoolkit.py so strings --apk /path/to/libnative.so

# 提取函数签名
python3 artoolkit.py so symbols --apk /path/to/libnative.so
```

## 示例 8：字符串解密

```bash
# XOR 解密
python3 artoolkit.py string xor "48656c6c6f" --file encrypted.bin

# Base64 解密
python3 artoolkit.py string base64 "SGVsbG8gV29ybGQ="

# RC4 解密
python3 artoolkit.py string rc4 "encrypted_data" --key mysecretkey

# 自动检测 APK 中的加密字符串
python3 artoolkit.py string auto --apk /path/to/app.apk
```

## 示例 9：Unidbg 模拟脚本生成

```bash
# 生成 Java 模拟脚本
python3 artoolkit.py unidbg java \
  --so /path/to/libnative.so \
  --class com.example.NativeHelper \
  --dest sim_java.py

# 生成 Native 模拟脚本
python3 artoolkit.py unidbg native \
  --so /path/to/libnative.so \
  --function nativeFunction \
  --dest sim_native.py

# 生成完整模拟配置
python3 artoolkit.py unidbg config \
  --so /path/to/libnative.so \
  --type java \
  --class com.example.NativeHelper \
  --methods getData,setData,calculate
```

## 示例 10：Flutter 分析

```bash
# 检测 APK 是否使用 Flutter
python3 artoolkit.py flutter detect --apk /path/to/app.apk

# 提取 Dart 字符串
python3 artoolkit.py flutter strings --apk /path/to/app.apk

# 提取 Dart 方法名
python3 artoolkit.py flutter methods --apk /path/to/app.apk
```

## 示例 11：网络分析

```bash
# 扫描 APK 中的网络请求特征
python3 artoolkit.py network scan --apk /path/to/app.apk

# 提取 URL 和域名
python3 artoolkit.py network urls --apk /path/to/app.apk

# 检测网络端口
python3 artoolkit.py network ports --apk /path/to/app.apk
```

## 示例 12：完整分析流程

```bash
# 1. 创建项目
python3 artoolkit.py project create --name my-analysis --path /workspace/my-analysis

# 2. 创建会话
python3 artoolkit.py session create --name session1 --apk /path/to/app.apk

# 3. 执行完整分析
python3 artoolkit.py analyze full --apk /path/to/app.apk --json --output analysis_result.json

# 4. 查看结果
cat analysis_result.json
```

## 示例 13：使用 JSON 输出进行脚本处理

```bash
# 以 JSON 格式输出，方便其他脚本处理
python3 artoolkit.py apk info --apk app.apk --json

# 保存到文件
python3 artoolkit.py apk info --apk app.apk --json --output result.json

# 在 Python 中读取
import json
with open('result.json') as f:
    data = json.load(f)
    print(f"Package: {data.get('package_name')}")
```

## 示例 14：批量分析多个 APK

```bash
#!/bin/bash
for apk in /path/to/apks/*.apk; do
    echo "Analyzing: $apk"
    python3 artoolkit.py analyze quick --apk "$apk" --json --output "${apk%.apk}_analysis.json"
done
```

## 常见工作流

### 工作流 1：APK 逆向分析

```bash
# 1. 获取基本信息
python3 artoolkit.py apk info --apk app.apk

# 2. 检查加固
python3 artoolkit.py shell detect --apk app.apk

# 3. 检测加密
python3 artoolkit.py crypto detect --apk app.apk

# 4. 提取 DEX
python3 artoolkit.py dex extract --apk app.apk --dest ./dex

# 5. 提取资源
python3 artoolkit.py resource extract --apk app.apk --dest ./resources

# 6. 分析 SO 文件
python3 artoolkit.py so info --apk lib/arm64-v8a/libnative.so
```

### 工作流 2：Frida 动态分析

```bash
# 1. 生成 Hook 脚本
python3 artoolkit.py frida generate --class com.example.Main --method getData --dest hook.js

# 2. 生成脱壳脚本（如果检测到加固）
python3 artoolkit.py shell frida --apk app.apk --dest dump.js

# 3. 在设备上运行 Frida
# frida -U -f com.example.app --no-pause -l hook.js
```

### 工作流 3：字符串解密

```bash
# 1. 从 APK 中提取字符串
python3 artoolkit.py string auto --apk app.apk

# 2. 手动解密特定字符串
python3 artoolkit.py string xor "encrypted_hex" --file encrypted.bin

# 3. 尝试 Base64 解码
python3 artoolkit.py string base64 "base64_string"
```

## 故障排除

### 问题：命令找不到

```bash
# 确保在 artoolkit 目录中运行
cd /path/to/artoolkit
python3 artoolkit.py --version
```

### 问题：缺少工具

```bash
# 检查系统依赖
which apktool baksmali aapt java

# 安装缺失的工具
# Ubuntu/Debian:
sudo apt-get install apktool baksmali

# macOS:
brew install apktool
```

### 问题：Python 模块导入失败

```bash
# 安装 Python 依赖
pip install pyyaml

# 如果使用虚拟环境，确保已激活
source venv/bin/activate
```