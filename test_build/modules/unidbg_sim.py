#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unidbg 模拟执行模块
===================
功能：生成 Unidbg Java/Native 模拟脚本、提取函数签名、提供模拟执行策略建议。

Unidbg 是一个强大的 Android Native 模拟器，可用于：
- 模拟执行 Android Native 库 (.so)
- 调试和逆向分析加密算法
- 提取运行时数据（密钥、参数等）
- 验证签名和校验逻辑

依赖：Python 3.6+ 标准库 + 系统工具 (objdump, readelf, nm, strings)

使用示例：
    from unidbg_sim import UnidbgSimulator

    sim = UnidbgSimulator()
    # 生成 Java 模拟脚本
    java_script = sim.generate_java_sim("/path/to/lib.so", "MyClass")
    print(java_script)

    # 提取函数签名
    sigs = sim.extract_function_signatures("/path/to/lib.so")
    print(sigs)

    # 生成完整模拟配置
    config = {
        "so_path": "/path/to/lib.so",
        "emulation_type": "java",
        "class_name": "com.example.MyClass",
        "methods": ["method1", "method2"]
    }
    script = sim.generate_emulation_script(config)
"""

import os
import re
import json
import subprocess
import textwrap
from typing import Dict, List, Optional, Tuple, Any


# ============================================================================
# 异常类定义
# ============================================================================

class UnidbgSimulatorError(Exception):
    """Unidbg 模拟器异常基类"""
    pass


class SOFileNotFoundError(UnidbgSimulatorError):
    """SO 文件不存在"""
    pass


class ToolNotFoundError(UnidbgSimulatorError):
    """必需的系统工具未找到"""
    pass


class SignatureExtractionError(UnidbgSimulatorError):
    """函数签名提取失败"""
    pass


class ScriptGenerationError(UnidbgSimulatorError):
    """脚本生成失败"""
    pass


# ============================================================================
# Java 模拟脚本模板
# ============================================================================

JAVA_SIM_TEMPLATE = '''/**
 * Unidbg Java 模拟执行脚本
 * 生成时间: {timestamp}
 * 目标 SO: {so_path}
 * 目标类: {class_name}
 *
 * 使用方法:
 *   1. 将此文件放入 Unidbg 项目的合适包路径下
 *   2. 确保已添加 Unidbg 依赖:
 *      implementation 'com.github.zhengkai:unidbg-android:1.2.2'
 *   3. 运行 main 方法执行模拟
 */

package {package_name};

import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.linux.android.ARM64Emulator;
import com.github.unidbg.linux.android.JavaApi;
import com.github.unidbg.linux.android.UFFIIconstructor;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.linux.structTimespec;
import com.github.unidbg.linux.android.UnidbgAndroid;
import com.github.unidbg.linux.android.UnidbgAndroidEmulator;
import com.github.unidbg.linux.android.UnidbgAndroidModule;
import com.github.unidbg.linux.android.UnidbgAndroidVirtualMachine;
import com.github.unidbg.linux.android.UnidbgDvm;
import com.github.unidbg.linux.android.UnidbgDvmModule;
import com.github.unidbg.linux.android.UnidbgDvmField;
import com.github.unidbg.linux.android.UnidbgDvmMethod;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.ARM64Emulator;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.context.AbstractRegisterContext;
import com.github.unidbg.arm.context.ARM64RegisterContext;
import com.github.unidbg.arm.context.ARMRegisterContext;
import com.github.unidbg.arm.Instruction;
import com.github.unidbg.arm.Instructions;
import com.github.unidbg.arm.Allocator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.kvm.KvmBackend;
import com.github.unidbg.arm.backend.MaxVmBackend;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * {class_name} 的 Unidbg Java 模拟器
 */
public class {class_name}Simulator extends ARM64Emulator {{
    private final String soPath;
    private final String className;
    private final UnidbgAndroidVirtualMachine vm;
    private final UnidbgDvm dvm;
    private final UnidbgAndroidModule module;

    public {class_name}Simulator(String soPath, String className) throws IOException {{
        super("{so_path}");
        this.soPath = soPath;
        this.className = className;

        // 创建模拟器实例
        this.vm = new UnidbgAndroidVirtualMachine(this);
        this.dvm = vm.loadLibrary(new File(soPath));
        this.module = dvm.loadLibrary(new File(soPath));
    }}

    /**
     * 调用 Java 方法
     *
     * @param methodName 方法名
     * @param args      参数列表
     * @return 返回值
     */
    public Object callJavaMethod(String methodName, Object... args) {{
        try {{
            UnidbgDvmMethod method = dvm.findMethod(className, methodName, args);
            return method.call(args);
        }} catch (Exception e) {{
            System.err.println("调用 Java 方法失败: " + methodName);
            e.printStackTrace();
            return null;
        }}
    }}

    /**
     * 调用 Native 方法
     *
     * @param methodName 方法名
     * @param args      参数列表
     * @return 返回值
     */
    public Object callNativeMethod(String methodName, Object... args) {{
        try {{
            UnidbgDvmMethod method = dvm.findMethod(className, methodName, args);
            return method.callJni(args);
        }} catch (Exception e) {{
            System.err.println("调用 Native 方法失败: " + methodName);
            e.printStackTrace();
            return null;
        }}
    }}

    /**
     * 获取 DVM 上下文
     */
    public UnidbgDvm getDvm() {{
        return dvm;
    }}

    /**
     * 获取模块信息
     */
    public UnidbgAndroidModule getModule() {{
        return module;
    }}

    /**
     * 释放资源
     */
    @Override
    public void close() {{
        try {{
            if (vm != null) vm.close();
            if (dvm != null) dvm.close();
        }} catch (IOException e) {{
            System.err.println("关闭模拟器失败: " + e.getMessage());
        }}
        super.close();
    }}

    public static void main(String[] args) {{
        String soPath = "{so_path}";
        String className = "{class_name}";

        try ({class_name}Simulator sim = new {class_name}Simulator(soPath, className)) {{
            System.out.println("=== Unidbg Java 模拟执行 ===");
            System.out.println("SO 文件: " + soPath);
            System.out.println("目标类: " + className);
            System.out.println();

            // 示例：调用 Java 方法
            // Object result = sim.callJavaMethod("targetMethod", arg1, arg2);
            // System.out.println("方法返回值: " + result);

            // 示例：调用 Native 方法
            // Object result = sim.callNativeMethod("nativeMethod", arg1, arg2);
            // System.out.println("Native 方法返回值: " + result);

            System.out.println("模拟执行完成。");
        }} catch (Exception e) {{
            System.err.println("模拟执行失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }}
    }}
}}
'''


# ============================================================================
# Native 模拟脚本模板
# ============================================================================

NATIVE_SIM_TEMPLATE = '''/**
 * Unidbg Native 模拟执行脚本
 * 生成时间: {timestamp}
 * 目标 SO: {so_path}
 * 目标函数: {function_name}
 *
 * 使用方法:
 *   1. 将此文件放入 Unidbg 项目中
 *   2. 确保已添加 Unidbg 依赖
 *   3. 运行 main 方法执行模拟
 */

package {package_name};

import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.ARM64Emulator;
import com.github.unidbg.linux.android.ARM64Emulator;
import com.github.unidbg.linux.android.UnidbgAndroidEmulator;
import com.github.unidbg.linux.android.UnidbgAndroidModule;
import com.github.unidbg.linux.android.UnidbgAndroidVirtualMachine;
import com.github.unidbg.linux.android.UnidbgDvm;
import com.github.unidbg.linux.android.UnidbgDvmModule;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.arm.context.AbstractRegisterContext;
import com.github.unidbg.arm.context.ARM64RegisterContext;
import com.github.unidbg.arm.context.ARMRegisterContext;

import java.io.File;
import java.io.IOException;

/**
 * {function_name} 的 Unidbg Native 模拟器
 */
public class {class_name}NativeSimulator extends ARM64Emulator {{
    private final String soPath;
    private final String functionName;
    private final UnidbgAndroidVirtualMachine vm;
    private final UnidbgDvm dvm;
    private final UnidbgAndroidModule module;

    public {class_name}NativeSimulator(String soPath, String functionName) throws IOException {{
        super(soPath);
        this.soPath = soPath;
        this.functionName = functionName;

        this.vm = new UnidbgAndroidVirtualMachine(this);
        this.dvm = vm.loadLibrary(new File(soPath));
        this.module = dvm.loadLibrary(new File(soPath));
    }}

    /**
     * 调用 Native 函数
     *
     * @param functionAddress 函数地址
     * @param args           参数列表
     * @return 返回值
     */
    public long callNativeFunction(long functionAddress, long... args) {{
        try {{
            // 设置参数
            for (int i = 0; i < args.length && i < 8; i++) {{
                setRegisterArgument(i, args[i]);
            }}

            // 调用函数
            return module.call(functionAddress, args);
        }} catch (Exception e) {{
            System.err.println("调用 Native 函数失败: " + functionName);
            e.printStackTrace();
            return 0;
        }}
    }}

    /**
     * 根据函数名获取函数地址
     */
    public long getFunctionAddress() {{
        try {{
            return module.findSymbol(functionName);
        }} catch (Exception e) {{
            System.err.println("未找到函数: " + functionName);
            return 0;
        }}
    }}

    /**
     * 执行 Native 函数模拟
     */
    public Object executeNative(Object... args) {{
        long addr = getFunctionAddress();
        if (addr == 0) {{
            System.err.println("函数地址无效: " + functionName);
            return null;
        }}

        // 转换参数为 long 数组
        long[] longArgs = new long[args.length];
        for (int i = 0; i < args.length; i++) {{
            if (args[i] instanceof Number) {{
                longArgs[i] = ((Number) args[i]).longValue();
            }} else if (args[i] instanceof String) {{
                longArgs[i] = module.allocateMemory(args[i].getBytes());
            }} else {{
                longArgs[i] = 0;
            }}
        }}

        return callNativeFunction(addr, longArgs);
    }}

    @Override
    public void close() {{
        try {{
            if (vm != null) vm.close();
            if (dvm != null) dvm.close();
        }} catch (IOException e) {{
            System.err.println("关闭模拟器失败: " + e.getMessage());
        }}
        super.close();
    }}

    public static void main(String[] args) {{
        String soPath = "{so_path}";
        String functionName = "{function_name}";

        try ({class_name}NativeSimulator sim = new {class_name}NativeSimulator(soPath, functionName)) {{
            System.out.println("=== Unidbg Native 模拟执行 ===");
            System.out.println("SO 文件: " + soPath);
            System.out.println("目标函数: " + functionName);
            System.out.println();

            // 示例：调用 Native 函数
            // Object result = sim.executeNative(arg1, arg2);
            // System.out.println("函数返回值: " + result);

            System.out.println("Native 模拟执行完成。");
        }} catch (Exception e) {{
            System.err.println("Native 模拟执行失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }}
    }}
}}
'''


# ============================================================================
# Python Unidbg 脚本模板 (用于自动化分析)
# ============================================================================

PYTHON_SIM_TEMPLATE = '''#!/usr/bin/env python3
"""
Unidbg Python 模拟执行脚本
生成时间: {timestamp}
目标 SO: {so_path}
模拟类型: {emulation_type}
"""

import os
import sys
import json
import argparse
from typing import Dict, List, Optional, Any

# Unidbg Python 绑定 (需安装 unidbg-python)
try:
    from unidbg import AndroidEmulator
    from unidbg.linux.android import AndroidEmulator as AndroidEmulatorLinux
    from unidbg.linux.android import Dvm as DvmLinux
    from unidbg.linux.android import Module as ModuleLinux
except ImportError:
    print("请安装 unidbg-python: pip install unidbg-python")
    sys.exit(1)


class UnidbgPythonSimulator:
    """Unidbg Python 模拟器封装"""

    def __init__(self, so_path: str, arch: str = "ARM64"):
        """
        初始化模拟器

        Args:
            so_path: SO 文件路径
            arch: 架构 (ARM, ARM64)
        """
        self.so_path = so_path
        self.arch = arch
        self.emulator = None
        self.vm = None
        self.dvm = None
        self.module = None
        self._init_emulator()

    def _init_emulator(self):
        """初始化模拟器实例"""
        if not os.path.exists(self.so_path):
            raise FileNotFoundError(f"SO 文件不存在: {self.so_path}")

        # 创建模拟器
        self.emulator = AndroidEmulator()

        # 加载 SO 文件
        self.vm = self.emulator.load_library(self.so_path)
        self.dvm = self.vm.get_dvm()
        self.module = self.vm.get_module()

    def call_java_method(self, class_name: str, method_name: str, *args):
        """调用 Java 方法"""
        try:
            method = self.dvm.find_method(class_name, method_name, *args)
            return method.call(*args)
        except Exception as e:
            print(f"调用 Java 方法失败: {class_name}.{method_name}: {e}")
            return None

    def call_native_method(self, class_name: str, method_name: str, *args):
        """调用 Native 方法"""
        try:
            method = self.dvm.find_method(class_name, method_name, *args)
            return method.call_jni(*args)
        except Exception as e:
            print(f"调用 Native 方法失败: {class_name}.{method_name}: {e}")
            return None

    def call_native_function(self, function_name: str, *args):
        """调用 Native 函数"""
        try:
            addr = self.module.find_symbol(function_name)
            if addr == 0:
                print(f"未找到函数: {function_name}")
                return None
            return self.module.call(addr, *args)
        except Exception as e:
            print(f"调用 Native 函数失败: {function_name}: {e}")
            return None

    def get_function_signatures(self) -> List[Dict]:
        """获取模块中的函数签名"""
        signatures = []
        try:
            symbols = self.module.enumerate_symbols()
            for name, addr in symbols:
                signatures.append({
                    "name": name,
                    "address": hex(addr),
                    "type": "native"
                })
        except Exception as e:
            print(f"获取函数签名失败: {e}")
        return signatures

    def close(self):
        """释放资源"""
        if self.emulator:
            self.emulator.close()
            self.emulator = None


def main():
    """主入口"""
    parser = argparse.ArgumentParser(description="Unidbg Python 模拟执行")
    parser.add_argument("--so", required=True, help="SO 文件路径")
    parser.add_argument("--type", default="java", choices=["java", "native", "python"],
                       help="模拟类型")
    parser.add_argument("--class", dest="class_name", default="", help="目标类名")
    parser.add_argument("--method", default="", help="目标方法名")
    parser.add_argument("--arch", default="ARM64", choices=["ARM", "ARM64"],
                       help="目标架构")
    args = parser.parse_args()

    try:
        sim = UnidbgPythonSimulator(args.so, args.arch)

        if args.type == "java" and args.class_name and args.method:
            result = sim.call_java_method(args.class_name, args.method)
            print(json.dumps({"result": str(result)}, indent=2))
        elif args.type == "native" and args.method:
            result = sim.call_native_function(args.method)
            print(json.dumps({"result": str(result)}, indent=2))
        elif args.type == "python":
            sigs = sim.get_function_signatures()
            print(json.dumps({"signatures": sigs}, indent=2))
        else:
            print("请提供足够的参数")

    except Exception as e:
        print(f"模拟执行失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if 'sim' in locals():
            sim.close()


if __name__ == "__main__":
    main()
'''


# ============================================================================
# UnidbgSimulator 主类
# ============================================================================

class UnidbgSimulator:
    """
    Unidbg 模拟执行脚本生成器

    提供：
    - Java Unidbg 模拟脚本生成
    - Native Unidbg 模拟脚本生成
    - 函数签名提取 (使用 objdump/nm/strings)
    - 模拟执行策略建议
    - Python Unidbg 脚本生成

    支持的架构：
    - ARM (32-bit)
    - ARM64 (64-bit)
    - x86
    - x86_64
    """

    # 支持的架构列表
    SUPPORTED_ARCHS = ["ARM", "ARM64", "x86", "x86_64"]

    # Java 包名模板
    JAVA_PACKAGE = "com.artoolkit.unidbg.sim"

    def __init__(self):
        """初始化 Unidbg 模拟器"""
        self._tool_paths: Dict[str, str] = {}
        self._detect_tools()

    def _detect_tools(self) -> None:
        """检测系统工具路径"""
        tool_candidates = {
            "objdump": ["/usr/bin/objdump", "/bin/objdump", "objdump"],
            "nm": ["/usr/bin/nm", "/bin/nm", "nm"],
            "readelf": ["/usr/bin/readelf", "/bin/readelf", "readelf"],
            "strings": ["/usr/bin/strings", "/bin/strings", "strings"],
            "file": ["/usr/bin/file", "/bin/file", "file"],
        }
        for tool_name, candidates in tool_candidates.items():
            self._tool_paths[tool_name] = None
            for candidate in candidates:
                if "/" not in candidate:
                    try:
                        result = subprocess.run(
                            ["which", candidate],
                            capture_output=True, text=True, timeout=5
                        )
                        if result.returncode == 0:
                            path = result.stdout.strip()
                            if path and os.path.isfile(path):
                                self._tool_paths[tool_name] = path
                                break
                    except Exception:
                        pass
                else:
                    if os.path.isfile(candidate):
                        self._tool_paths[tool_name] = candidate
                        break

    def _run_tool(self, tool_name: str, args: List[str]) -> str:
        """运行系统工具并返回输出"""
        tool_path = self._tool_paths.get(tool_name)
        if not tool_path:
            raise ToolNotFoundError(f"工具未找到: {tool_name}")

        try:
            result = subprocess.run(
                [tool_path] + args,
                capture_output=True, text=True,
                timeout=30
            )
            if result.returncode != 0:
                raise SignatureExtractionError(
                    f"工具 {tool_name} 返回错误: {result.stderr}"
                )
            return result.stdout
        except subprocess.TimeoutExpired:
            raise SignatureExtractionError(f"工具 {tool_name} 执行超时")
        except Exception as e:
            raise SignatureExtractionError(f"工具 {tool_name} 执行失败: {e}")

    def extract_function_signatures(self, so_path: str) -> List[Dict[str, Any]]:
        """
        从 SO 文件中提取函数签名

        使用 nm 和 objdump 提取：
        - 导出函数名
        - 函数符号
        - 动态符号表

        Args:
            so_path: SO 文件路径

        Returns:
            函数签名列表，每个包含 name, address, type, visibility 等信息

        Raises:
            SOFileNotFoundError: SO 文件不存在
            SignatureExtractionError: 签名提取失败
        """
        if not os.path.exists(so_path):
            raise SOFileNotFoundError(f"SO 文件不存在: {so_path}")

        signatures: List[Dict[str, Any]] = []

        # 方法1: 使用 nm 提取动态符号
        try:
            nm_output = self._run_tool("nm", ["-D", "-n", so_path])
            for line in nm_output.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    addr_str, type_char, name = parts[0], parts[1], parts[2]
                    try:
                        addr = int(addr_str, 16)
                    except ValueError:
                        continue
                    sig_type = self._classify_symbol_type(type_char)
                    signatures.append({
                        "name": name,
                        "address": hex(addr),
                        "type": sig_type,
                        "visibility": self._get_visibility(type_char),
                        "source": "nm"
                    })
        except Exception as e:
            print(f"[WARN] nm 提取失败: {e}")

        # 方法2: 使用 objdump 提取更详细的符号信息
        try:
            objdump_output = self._run_tool("objdump", ["-t", so_path])
            for line in objdump_output.splitlines():
                line = line.strip()
                if not line or line.startswith("SYMBOL TABLE") or line.startswith("Filename"):
                    continue
                parts = line.split()
                if len(parts) >= 6:
                    addr_str = parts[0]
                    try:
                        addr = int(addr_str, 16)
                    except ValueError:
                        continue
                    name = parts[-1]
                    # 过滤掉非函数符号
                    if self._is_function_symbol(parts):
                        sig_type = self._classify_symbol_type(parts[4])
                        if not any(s["name"] == name for s in signatures):
                            signatures.append({
                                "name": name,
                                "address": hex(addr),
                                "type": sig_type,
                                "visibility": self._get_visibility(parts[4]),
                                "source": "objdump"
                            })
        except Exception as e:
            print(f"[WARN] objdump 提取失败: {e}")

        # 方法3: 使用 strings 查找可能的函数名 (用于混淆代码)
        try:
            strings_output = self._run_tool("strings", [so_path])
            for line in strings_output.splitlines():
                line = line.strip()
                if self._looks_like_function_name(line):
                    if not any(s["name"] == line for s in signatures):
                        signatures.append({
                            "name": line,
                            "address": "unknown",
                            "type": "string_candidate",
                            "visibility": "unknown",
                            "source": "strings"
                        })
        except Exception as e:
            print(f"[WARN] strings 提取失败: {e}")

        return signatures

    def _is_function_symbol(self, parts: List[str]) -> bool:
        """判断符号是否为函数符号"""
        if len(parts) < 5:
            return False
        # objdump 输出格式: address flags section size type name
        # type 通常在倒数第二个位置
        type_idx = len(parts) - 2 if len(parts) > 2 else -1
        if type_idx >= 0 and type_idx < len(parts):
            type_char = parts[type_idx].upper()
            # F = function, O = object, A = absolute, etc.
            return type_char in ('F', 'O', 'L', 'D', 'B')
        return False

    def _classify_symbol_type(self, type_char: str) -> str:
        """分类符号类型"""
        type_char = type_char.upper()
        type_map = {
            'T': 'exported_function',
            't': 'local_function',
            'D': 'data',
            'd': 'local_data',
            'B': 'bss',
            'b': 'local_bss',
            'R': 'read_only_data',
            'r': 'local_read_only_data',
            'S': 'common_data',
            's': 'local_common_data',
            'U': 'undefined',
            'W': 'weak_symbol',
            'A': 'absolute',
            'V': 'weak_object',
            'v': 'local_weak_object',
        }
        return type_map.get(type_char, f"unknown_{type_char}")

    def _get_visibility(self, type_char: str) -> str:
        """获取符号可见性"""
        type_char = type_char.upper()
        if type_char in ('T', 'D', 'B', 'R', 'S', 'A', 'V'):
            return "global"
        elif type_char in ('t', 'd', 'b', 'r', 's', 'v'):
            return "local"
        elif type_char == 'U':
            return "undefined"
        elif type_char == 'W':
            return "weak"
        return "unknown"

    def _looks_like_function_name(self, name: str) -> bool:
        """启发式判断字符串是否像函数名"""
        if not name or len(name) < 3:
            return False
        # 常见函数名模式
        patterns = [
            r'^[a-zA-Z_][a-zA-Z0-9_]*$',  # 标识符
            r'^[a-zA-Z_][a-zA-Z0-9_]*\(\)$',  # 函数调用
            r'^[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)$',  # 带参数的函数
        ]
        for pattern in patterns:
            if re.match(pattern, name):
                return True
        return False

    def generate_java_sim(self, so_path: str, class_name: str) -> str:
        """
        生成 Java Unidbg 模拟脚本

        Args:
            so_path: SO 文件路径
            class_name: 目标类名 (如 "com.example.MyClass")

        Returns:
            Java 模拟脚本字符串

        Raises:
            SOFileNotFoundError: SO 文件不存在
            ScriptGenerationError: 脚本生成失败
        """
        if not os.path.exists(so_path):
            raise SOFileNotFoundError(f"SO 文件不存在: {so_path}")

        if not class_name:
            raise ScriptGenerationError("类名不能为空")

        # 从 class_name 提取简单类名
        simple_class_name = class_name.split('.')[-1] if '.' in class_name else class_name
        package_name = '.'.join(class_name.split('.')[:-1]) if '.' in class_name else self.JAVA_PACKAGE

        # 生成时间戳
        import datetime
        timestamp = datetime.datetime.now().isoformat()

        try:
            script = JAVA_SIM_TEMPLATE
            script = script.replace("{timestamp}", timestamp)
            script = script.replace("{so_path}", so_path)
            script = script.replace("{class_name}", simple_class_name)
            script = script.replace("{package_name}", package_name)
            return script
        except Exception as e:
            raise ScriptGenerationError(f"Java 脚本生成失败: {e}")

    def generate_native_sim(self, so_path: str, function_name: str) -> str:
        """
        生成 Native Unidbg 模拟脚本

        Args:
            so_path: SO 文件路径
            function_name: 目标函数名

        Returns:
            Native 模拟脚本字符串

        Raises:
            SOFileNotFoundError: SO 文件不存在
            ScriptGenerationError: 脚本生成失败
        """
        if not os.path.exists(so_path):
            raise SOFileNotFoundError(f"SO 文件不存在: {so_path}")

        if not function_name:
            raise ScriptGenerationError("函数名不能为空")

        # 从函数名生成类名
        class_name = function_name.replace('_', ' ').title().replace(' ', '') + "Native"
        package_name = self.JAVA_PACKAGE

        import datetime
        timestamp = datetime.datetime.now().isoformat()

        try:
            script = NATIVE_SIM_TEMPLATE
            script = script.replace("{timestamp}", timestamp)
            script = script.replace("{so_path}", so_path)
            script = script.replace("{function_name}", function_name)
            script = script.replace("{class_name}", class_name)
            script = script.replace("{package_name}", package_name)
            return script
        except Exception as e:
            raise ScriptGenerationError(f"Native 脚本生成失败: {e}")

    def generate_emulation_script(self, config: Dict[str, Any]) -> str:
        """
        根据配置生成完整的模拟执行脚本

        Args:
            config: 配置字典，支持以下键:
                - so_path: SO 文件路径 (必需)
                - emulation_type: 模拟类型 ("java", "native", "python") (必需)
                - class_name: 目标类名 (java 类型时必需)
                - function_name: 目标函数名 (native 类型时必需)
                - arch: 目标架构 (默认 "ARM64")
                - output_format: 输出格式 ("java", "python", "text") (默认 "java")
                - extra_methods: 额外需要调用的方法列表
                - strategy: 模拟策略建议

        Returns:
            模拟执行脚本字符串

        Raises:
            ScriptGenerationError: 脚本生成失败
        """
        if not config:
            raise ScriptGenerationError("配置不能为空")

        so_path = config.get("so_path")
        if not so_path:
            raise ScriptGenerationError("配置中缺少 so_path")
        if not os.path.exists(so_path):
            raise SOFileNotFoundError(f"SO 文件不存在: {so_path}")

        emulation_type = config.get("emulation_type", "java")
        output_format = config.get("output_format", "java")
        arch = config.get("arch", "ARM64")

        import datetime
        timestamp = datetime.datetime.now().isoformat()

        if emulation_type == "java":
            class_name = config.get("class_name")
            if not class_name:
                raise ScriptGenerationError("Java 模拟需要 class_name")

            simple_class_name = class_name.split('.')[-1] if '.' in class_name else class_name
            package_name = '.'.join(class_name.split('.')[:-1]) if '.' in class_name else self.JAVA_PACKAGE

            if output_format == "python":
                script = PYTHON_SIM_TEMPLATE
                script = script.replace("{timestamp}", timestamp)
                script = script.replace("{so_path}", so_path)
                script = script.replace("{emulation_type}", emulation_type)
            else:
                script = JAVA_SIM_TEMPLATE
                script = script.replace("{timestamp}", timestamp)
                script = script.replace("{so_path}", so_path)
                script = script.replace("{class_name}", simple_class_name)
                script = script.replace("{package_name}", package_name)

        elif emulation_type == "native":
            function_name = config.get("function_name")
            if not function_name:
                raise ScriptGenerationError("Native 模拟需要 function_name")

            class_name = function_name.replace('_', ' ').title().replace(' ', '') + "Native"
            package_name = self.JAVA_PACKAGE

            if output_format == "python":
                script = PYTHON_SIM_TEMPLATE
                script = script.replace("{timestamp}", timestamp)
                script = script.replace("{so_path}", so_path)
                script = script.replace("{emulation_type}", emulation_type)
            else:
                script = NATIVE_SIM_TEMPLATE
                script = script.replace("{timestamp}", timestamp)
                script = script.replace("{so_path}", so_path)
                script = script.replace("{function_name}", function_name)
                script = script.replace("{class_name}", class_name)
                script = script.replace("{package_name}", package_name)

        elif emulation_type == "python":
            script = PYTHON_SIM_TEMPLATE
            script = script.replace("{timestamp}", timestamp)
            script = script.replace("{so_path}", so_path)
            script = script.replace("{emulation_type}", emulation_type)

        else:
            raise ScriptGenerationError(f"不支持的模拟类型: {emulation_type}")

        return script

    def generate_strategy_suggestion(self, so_path: str) -> Dict[str, Any]:
        """
        生成模拟执行策略建议

        根据 SO 文件特征，提供：
        - 推荐模拟类型
        - 预估难度
        - 注意事项
        - 优化建议

        Args:
            so_path: SO 文件路径

        Returns:
            策略建议字典
        """
        if not os.path.exists(so_path):
            raise SOFileNotFoundError(f"SO 文件不存在: {so_path}")

        suggestion: Dict[str, Any] = {
            "so_path": so_path,
            "recommended_type": "java",
            "difficulty": "medium",
            "notes": [],
            "optimizations": [],
        }

        # 分析 SO 文件特征
        try:
            if "file" in self._tool_paths and self._tool_paths["file"]:
                file_output = self._run_tool("file", [so_path])
                if "shared object" in file_output.lower():
                    suggestion["notes"].append("有效的 Android Shared Object 文件")

                if "ARM aarch64" in file_output:
                    suggestion["arch"] = "ARM64"
                    suggestion["recommended_type"] = "native"
                    suggestion["notes"].append("ARM64 架构，建议使用 Native 模拟")
                elif "ARM 32-bit" in file_output:
                    suggestion["arch"] = "ARM"
                elif "x86-64" in file_output:
                    suggestion["arch"] = "x86_64"
                elif "Intel 80386" in file_output:
                    suggestion["arch"] = "x86"
            else:
                # 尝试使用 readelf 检测架构
                try:
                    readelf_output = self._run_tool("readelf", ["-h", so_path])
                    if "AArch64" in readelf_output:
                        suggestion["arch"] = "ARM64"
                        suggestion["recommended_type"] = "native"
                        suggestion["notes"].append("ARM64 架构，建议使用 Native 模拟")
                    elif "ARM" in readelf_output:
                        suggestion["arch"] = "ARM"
                    elif "X86-64" in readelf_output or "x86-64" in readelf_output:
                        suggestion["arch"] = "x86_64"
                    elif "Intel 80386" in readelf_output or "i386" in readelf_output:
                        suggestion["arch"] = "x86"
                    suggestion["notes"].append("有效的 ELF 文件")
                except Exception:
                    suggestion["notes"].append("无法检测架构，使用默认设置")
        except Exception:
            pass

        # 检查是否包含 Il2CPP 符号 (Unity 游戏)
        try:
            nm_output = self._run_tool("nm", ["-D", so_path])
            if "il2cpp" in nm_output.lower() or "unity" in nm_output.lower():
                suggestion["is_unity"] = True
                suggestion["recommended_type"] = "java"
                suggestion["notes"].append("检测到 Unity/Il2CPP 符号，建议使用 Java 模拟")
                suggestion["optimizations"].append("可尝试使用 Il2CppDumper 提取符号")
        except Exception:
            pass

        # 检查是否有大量导出函数
        try:
            sigs = self.extract_function_signatures(so_path)
            exported = [s for s in sigs if s.get("type") == "exported_function"]
            suggestion["exported_function_count"] = len(exported)
            if len(exported) > 100:
                suggestion["notes"].append(f"大量导出函数 ({len(exported)})，建议先筛选目标函数")
                suggestion["difficulty"] = "high"
            elif len(exported) < 10:
                suggestion["notes"].append("少量导出函数，可能需要深入分析内部调用")
                suggestion["difficulty"] = "high"
        except Exception:
            pass

        return suggestion

    def save_script(self, script: str, output_path: str) -> str:
        """
        保存生成的脚本到文件

        Args:
            script: 脚本内容
            output_path: 输出文件路径

        Returns:
            保存的文件路径
        """
        try:
            dir_path = os.path.dirname(output_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(script)
            return output_path
        except Exception as e:
            raise ScriptGenerationError(f"保存脚本失败: {e}")

    def validate_so_file(self, so_path: str) -> Dict[str, Any]:
        """
        验证 SO 文件的有效性

        Args:
            so_path: SO 文件路径

        Returns:
            验证结果字典
        """
        result: Dict[str, Any] = {
            "valid": False,
            "exists": False,
            "is_so": False,
            "arch": "unknown",
            "errors": [],
        }

        if not os.path.exists(so_path):
            result["errors"].append("文件不存在")
            return result

        result["exists"] = True

        # 尝试使用 file 命令检测
        try:
            if "file" in self._tool_paths and self._tool_paths["file"]:
                file_output = self._run_tool("file", [so_path])
                if "shared object" in file_output.lower():
                    result["is_so"] = True
                else:
                    result["errors"].append("不是有效的 SO 文件")

                if "ARM aarch64" in file_output:
                    result["arch"] = "ARM64"
                elif "ARM 32-bit" in file_output:
                    result["arch"] = "ARM"
                elif "x86-64" in file_output:
                    result["arch"] = "x86_64"
                elif "Intel 80386" in file_output:
                    result["arch"] = "x86"
            else:
                # file 命令不可用，尝试使用 readelf 检测
                try:
                    readelf_output = self._run_tool("readelf", ["-h", so_path])
                    if "Shared object" in readelf_output or "ELF" in readelf_output:
                        result["is_so"] = True
                    else:
                        result["errors"].append("不是有效的 SO 文件")

                    if "AArch64" in readelf_output:
                        result["arch"] = "ARM64"
                    elif "ARM" in readelf_output:
                        result["arch"] = "ARM"
                    elif "X86-64" in readelf_output or "x86-64" in readelf_output:
                        result["arch"] = "x86_64"
                    elif "Intel 80386" in readelf_output or "i386" in readelf_output:
                        result["arch"] = "x86"
                except Exception as e2:
                    result["errors"].append(f"文件类型检测失败: file 命令不可用, readelf 失败: {e2}")
        except Exception as e:
            result["errors"].append(f"文件类型检测失败: {e}")

        result["valid"] = len(result["errors"]) == 0
        return result


# ============================================================================
# 模块级工具函数
# ============================================================================

def quick_generate(so_path: str, emulation_type: str = "java",
                   class_name: str = "", function_name: str = "",
                   output_path: str = "") -> str:
    """
    快速生成 Unidbg 模拟脚本的便捷函数

    Args:
        so_path: SO 文件路径
        emulation_type: 模拟类型 ("java", "native", "python")
        class_name: 目标类名
        function_name: 目标函数名
        output_path: 输出文件路径 (可选)

    Returns:
        生成的脚本字符串
    """
    sim = UnidbgSimulator()
    config = {
        "so_path": so_path,
        "emulation_type": emulation_type,
        "class_name": class_name,
        "function_name": function_name,
    }
    script = sim.generate_emulation_script(config)

    if output_path:
        sim.save_script(script, output_path)

    return script


def analyze_and_suggest(so_path: str) -> Dict[str, Any]:
    """
    分析 SO 文件并生成模拟建议

    Args:
        so_path: SO 文件路径

    Returns:
        分析结果和建议
    """
    sim = UnidbgSimulator()
    validation = sim.validate_so_file(so_path)
    signatures = sim.extract_function_signatures(so_path) if validation["valid"] else []
    strategy = sim.generate_strategy_suggestion(so_path)

    return {
        "validation": validation,
        "signatures": signatures,
        "strategy": strategy,
    }


# ============================================================================
# 命令行入口
# ============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Unidbg 模拟执行脚本生成器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 生成 Java 模拟脚本
  python unidbg_sim.py java -s lib.so -c com.example.MyClass -o MySim.java

  # 生成 Native 模拟脚本
  python unidbg_sim.py native -s lib.so -f target_function -o NativeSim.java

  # 分析 SO 文件
  python unidbg_sim.py analyze -s lib.so

  # 生成 Python 脚本
  python unidbg_sim.py python -s lib.so -o sim.py
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # Java 模拟
    java_parser = subparsers.add_parser("java", help="生成 Java 模拟脚本")
    java_parser.add_argument("-s", "--so", required=True, help="SO 文件路径")
    java_parser.add_argument("-c", "--class", dest="class_name", required=True, help="目标类名")
    java_parser.add_argument("-o", "--output", help="输出文件路径")

    # Native 模拟
    native_parser = subparsers.add_parser("native", help="生成 Native 模拟脚本")
    native_parser.add_argument("-s", "--so", required=True, help="SO 文件路径")
    native_parser.add_argument("-f", "--function", required=True, help="目标函数名")
    native_parser.add_argument("-o", "--output", help="输出文件路径")

    # Python 模拟
    python_parser = subparsers.add_parser("python", help="生成 Python 模拟脚本")
    python_parser.add_argument("-s", "--so", required=True, help="SO 文件路径")
    python_parser.add_argument("-o", "--output", help="输出文件路径")

    # 分析
    analyze_parser = subparsers.add_parser("analyze", help="分析 SO 文件")
    analyze_parser.add_argument("-s", "--so", required=True, help="SO 文件路径")

    # 策略建议
    strategy_parser = subparsers.add_parser("strategy", help="生成模拟策略建议")
    strategy_parser.add_argument("-s", "--so", required=True, help="SO 文件路径")

    args = parser.parse_args()

    if args.command == "java":
        sim = UnidbgSimulator()
        script = sim.generate_java_sim(args.so, args.class_name)
        if args.output:
            sim.save_script(script, args.output)
            print(f"脚本已保存到: {args.output}")
        else:
            print(script)

    elif args.command == "native":
        sim = UnidbgSimulator()
        script = sim.generate_native_sim(args.so, args.function)
        if args.output:
            sim.save_script(script, args.output)
            print(f"脚本已保存到: {args.output}")
        else:
            print(script)

    elif args.command == "python":
        sim = UnidbgSimulator()
        config = {"so_path": args.so, "emulation_type": "python"}
        script = sim.generate_emulation_script(config)
        if args.output:
            sim.save_script(script, args.output)
            print(f"脚本已保存到: {args.output}")
        else:
            print(script)

    elif args.command == "analyze":
        result = analyze_and_suggest(args.so)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.command == "strategy":
        sim = UnidbgSimulator()
        strategy = sim.generate_strategy_suggestion(args.so)
        print(json.dumps(strategy, indent=2, ensure_ascii=False))

    else:
        parser.print_help()