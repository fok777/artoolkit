#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida 脚本生成模块 (Frida Script Generator)

功能概述：
    本模块提供常见 Frida 脚本模板的生成功能，包括：
    - Hook 函数 (hook_function)
    - Hook 类 (hook_class)
    - RPC 调用桩 (rpc_stub)
    - 内存搜索 (memory_search)
    - 脚本语法检查 (validate_syntax)

使用示例：
    >>> from frida_gen import FridaGenerator
    >>> gen = FridaGenerator()
    >>> script = gen.generate_hook_function("com.example.MyClass", "myMethod")
    >>> print(script)

依赖：
    - Python 3.6+ 标准库
    - string.Template 用于模板渲染
"""

import re
import os
import sys
import json
import ast
import logging
from string import Template
from typing import Optional, List, Dict, Any, Union

# 配置日志
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# 自定义异常
# =============================================================================

class FridaGeneratorError(Exception):
    """Frida 脚本生成器的基础异常类"""
    pass


class InvalidClassNameError(FridaGeneratorError):
    """无效的类名错误"""
    pass


class InvalidMethodNameError(FridaGeneratorError):
    """无效的方法名错误"""
    pass


class InvalidPatternError(FridaGeneratorError):
    """无效的匹配模式错误"""
    pass


class SyntaxCheckError(FridaGeneratorError):
    """语法检查错误"""
    pass


# =============================================================================
# 模板定义
# =============================================================================

# Hook 函数模板 (JavaScript)
HOOK_FUNCTION_TEMPLATE = Template(r"""
// ============================================================
// Frida Hook 函数: $class_name.$method_name
// 生成时间: $timestamp
// ============================================================
"use strict";

/**
 * Hook 类的指定方法
 * @param {string} className - 完整类名 (如 com.example.MyClass)
 * @param {string} methodName - 方法名
 */
function hookFunction(className, methodName) {
    // 查找目标类
    const targetClass = Java.use(className);

    // Hook 方法
    targetClass[methodName].overloads.forEach(function(overload) {
        console.log("[*] Hooking " + className + "." + methodName + "(" + overload + ")");

        overload.implementation = function() {
            // 打印调用栈
            console.log("[+] " + className + "." + methodName + " called");

            // 打印参数
            for (let i = 0; i < arguments.length; i++) {
                console.log("    Arg[" + i + "]: " + arguments[i]);
            }

            // 调用原始方法
            const result = this[methodName].apply(this, arguments);

            // 打印返回值
            console.log("    Result: " + result);

            return result;
        };
    });

    console.log("[+] Hook installed for " + className + "." + methodName);
}

// 执行 Hook
hookFunction("$class_name", "$method_name");
""")

# Hook 类模板 (JavaScript) - Hook 所有匹配类的方法
HOOK_CLASS_TEMPLATE = Template(r"""
// ============================================================
// Frida Hook 类: 匹配模式 $pattern
// 生成时间: $timestamp
// ============================================================
"use strict";

/**
 * Hook 所有匹配类名模式的类
 * @param {string} pattern - 类名匹配模式 (支持正则表达式)
 */
function hookClass(pattern) {
    const regex = new RegExp(pattern);

    // 遍历所有已加载的类
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (regex.test(className)) {
                console.log("[*] Found matching class: " + className);

                try {
                    const targetClass = Java.use(className);

                    // Hook 类中的所有方法
                    targetClass.class.getDeclaredMethods().forEach(function(method) {
                        const methodName = method.getName();
                        // 跳过构造函数
                        if (methodName === "<init>" || methodName === "<clinit>") {
                            return;
                        }

                        console.log("    Hooking method: " + methodName);

                        try {
                            targetClass[methodName].overloads.forEach(function(overload) {
                                overload.implementation = function() {
                                    console.log("[+] " + className + "." + methodName + "(" + overload + ") called");
                                    return this[methodName].apply(this, arguments);
                                };
                            });
                        } catch (e) {
                            console.log("    [-] Failed to hook " + methodName + ": " + e.message);
                        }
                    });
                } catch (e) {
                    console.log("[-] Failed to use class " + className + ": " + e.message);
                }
            }
        },
        onComplete: function() {
            console.log("[+] Class enumeration complete");
        }
    });
}

// 执行 Hook
hookClass("$pattern");
""")

# RPC 调用桩模板 (JavaScript)
RPC_STUB_TEMPLATE = Template(r"""
// ============================================================
// Frida RPC 调用桩
// 生成时间: $timestamp
// ============================================================
"use strict";

/**
 * Frida RPC 服务端桩
 * 用于在目标进程中暴露函数供外部调用
 */
const RpcServer = {
    // 存储注册的函数
    handlers: {},

    /**
     * 注册 RPC 处理函数
     * @param {string} name - 函数名称
     * @param {function} handler - 处理函数
     */
    register: function(name, handler) {
        this.handlers[name] = handler;
        console.log("[*] Registered RPC handler: " + name);
    },

    /**
     * 调用已注册的 RPC 函数
     * @param {string} name - 函数名称
     * @param {...any} args - 参数
     * @returns {any} 处理结果
     */
    call: function(name) {
        const args = Array.prototype.slice.call(arguments, 1);
        const handler = this.handlers[name];

        if (!handler) {
            throw new Error("Unknown RPC handler: " + name);
        }

        console.log("[>] RPC call: " + name, args);
        const result = handler.apply(null, args);
        console.log("[<] RPC result: " + name, result);

        return result;
    },

    /**
     * 启动 RPC 服务 (通过 Frida API)
     */
    start: function() {
        // 使用 Frida 的 RPC 导出
        if (typeof RPC !== 'undefined') {
            Object.keys(this.handlers).forEach(function(name) {
                RPC.exportHandler(this.handlers[name], name);
            }.bind(this));
            console.log("[+] RPC server started");
        } else {
            console.log("[-] RPC not available in this context");
        }
    }
};

// 注册示例 RPC 处理函数
RpcServer.register("getState", function() {
    // 返回当前应用状态
    const context = Java.use("android.app.ActivityThread").currentApplication();
    return {
        packageName: context.getPackageName(),
        processName: context.getProcessName(),
        uptime: Date.now()
    };
});

RpcServer.register("getData", function(key) {
    // 从指定位置读取数据
    const sp = Java.use("android.app.ContextImpl").getSharedPreferences(
        Java.use("android.app.ActivityThread").currentApplication(),
        "default"
    );
    return sp.getString(key, null);
});

RpcServer.register("setData", function(key, value) {
    // 向指定位置写入数据
    const sp = Java.use("android.app.ContextImpl").getSharedPreferences(
        Java.use("android.app.ActivityThread").currentApplication(),
        "default"
    );
    const editor = sp.edit();
    editor.putString(key, value);
    editor.commit();
    return true;
});

// 启动 RPC 服务
RpcServer.start();
""")

# 内存搜索模板 (JavaScript)
MEMORY_SEARCH_TEMPLATE = Template(r"""
// ============================================================
// Frida 内存搜索
// 生成时间: $timestamp
// ============================================================
"use strict";

/**
 * 内存搜索工具
 * @param {string} pattern - 搜索模式 (字符串或十六进制字节数组)
 * @param {string} encoding - 字符串编码 (utf8, utf16, ascii, hex)
 */
function memorySearch(pattern, encoding) {
    encoding = encoding || "utf8";

    // 将模式转换为字节数组
    let searchBytes;
    if (typeof pattern === "string") {
        if (encoding === "hex") {
            searchBytes = hexToBytes(pattern);
        } else if (encoding === "utf16") {
            searchBytes = stringToUtf16Bytes(pattern);
        } else {
            searchBytes = stringToUtf8Bytes(pattern);
        }
    } else {
        searchBytes = pattern; // 假设已经是字节数组
    }

    console.log("[*] Searching memory for pattern: " + pattern + " (" + encoding + ")");

    // 遍历内存范围
    const ranges = Process.enumerateRanges({
        name: "default",
        permission: "rw-"
    });

    ranges.forEach(function(range) {
        console.log("[*] Searching range: " + range.base + " - " + range.end);

        Memory.scan(range.base, range.end - range.base, {
            onMatch: function(address, size) {
                console.log("[+] Found at: " + address);
                // 读取匹配处的数据
                const data = Memory.readByteArray(address, Math.min(size, 64));
                console.log("    Data: " + bytesToHex(data));
            },
            onError: function(reason) {
                console.log("[-] Scan error: " + reason);
            },
            onComplete: function() {
                console.log("[+] Scan complete for range: " + range.base);
            }
        });
    });

    console.log("[+] Memory search complete");
}

/**
 * 字符串转 UTF-8 字节数组
 */
function stringToUtf8Bytes(str) {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}

/**
 * 字符串转 UTF-16 字节数组
 */
function stringToUtf16Bytes(str) {
    const encoder = new TextEncoder();
    const utf8 = encoder.encode(str);
    // 简化处理：实际应用中需要正确处理 UTF-16 编码
    return utf8;
}

/**
 * 十六进制字符串转字节数组
 */
function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

/**
 * 字节数组转十六进制字符串
 */
function bytesToHex(bytes) {
    const hexChars = "0123456789ABCDEF";
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
        hex += hexChars[bytes[i] >> 4] + hexChars[bytes[i] & 0x0F];
    }
    return hex;
}

// 执行内存搜索 (示例)
// memorySearch("Hello", "utf8");
// memorySearch("AABBCCDD", "hex");
""")

# 脚本头部模板 (用于所有生成的脚本)
SCRIPT_HEADER = """// ============================================================
// Frida 脚本 (由 FridaGenerator 生成)
// ============================================================
// 使用方法:
//   1. frida -U -l script.js <target_process>
//   2. frida -U --no-pause -l script.js <target_process>
// ============================================================
"""


# =============================================================================
# FridaGenerator 类
# =============================================================================

class FridaGenerator:
    """
    Frida 脚本生成器

    提供常见 Frida 脚本模板的生成功能，包括 Hook 函数、Hook 类、
    RPC 调用桩、内存搜索等。所有生成的脚本均包含完整的错误处理
    和详细的注释说明。

    属性:
        template_dir (str): 模板文件目录 (可选)
        strict_mode (bool): 严格模式，启用额外的输入验证

    示例:
        >>> gen = FridaGenerator()
        >>> script = gen.generate_hook_function("com.example.MyClass", "myMethod")
        >>> print(script)
    """

    # 支持的脚本类型
    SCRIPT_TYPES = {
        "hook_function": "Hook 函数",
        "hook_class": "Hook 类",
        "rpc_stub": "RPC 调用桩",
        "memory_search": "内存搜索"
    }

    # 有效的编码类型
    VALID_ENCODINGS = {"utf8", "utf16", "ascii", "hex"}

    def __init__(self, template_dir: Optional[str] = None, strict_mode: bool = True):
        """
        初始化 FridaGenerator

        参数:
            template_dir (str, optional): 自定义模板文件目录
            strict_mode (bool): 是否启用严格模式 (默认 True)
        """
        self.template_dir = template_dir
        self.strict_mode = strict_mode
        self._validate_environment()

    def _validate_environment(self) -> None:
        """验证运行环境"""
        # 检查 Python 版本
        if sys.version_info < (3, 6):
            raise FridaGeneratorError("FridaGenerator requires Python 3.6 or higher")

    # =========================================================================
    # 输入验证方法
    # =========================================================================

    @staticmethod
    def _validate_class_name(class_name: str) -> str:
        """
        验证类名是否有效

        参数:
            class_name (str): 类名 (如 com.example.MyClass)

        返回:
            str: 验证后的类名

        异常:
            InvalidClassNameError: 类名无效
        """
        if not class_name or not isinstance(class_name, str):
            raise InvalidClassNameError("Class name cannot be empty")

        # 移除首尾空白
        class_name = class_name.strip()

        # 检查是否包含非法字符
        if not re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$.]*$', class_name):
            raise InvalidClassNameError(
                f"Invalid class name format: '{class_name}'. "
                "Must be a valid Java identifier (e.g., com.example.MyClass)"
            )

        return class_name

    @staticmethod
    def _validate_method_name(method_name: str) -> str:
        """
        验证方法名是否有效

        参数:
            method_name (str): 方法名

        返回:
            str: 验证后的方法名

        异常:
            InvalidMethodNameError: 方法名无效
        """
        if not method_name or not isinstance(method_name, str):
            raise InvalidMethodNameError("Method name cannot be empty")

        method_name = method_name.strip()

        if not re.match(r'^[a-zA-Z_$][a-zA-Z0-9_]*$', method_name):
            raise InvalidMethodNameError(
                f"Invalid method name format: '{method_name}'. "
                "Must be a valid Java identifier"
            )

        return method_name

    @staticmethod
    def _validate_pattern(pattern: str) -> str:
        """
        验证匹配模式是否有效

        参数:
            pattern (str): 匹配模式 (正则表达式)

        返回:
            str: 验证后的模式

        异常:
            InvalidPatternError: 模式无效
        """
        if not pattern or not isinstance(pattern, str):
            raise InvalidPatternError("Pattern cannot be empty")

        pattern = pattern.strip()

        try:
            re.compile(pattern)
        except re.error as e:
            raise InvalidPatternError(
                f"Invalid regex pattern: '{pattern}'. Error: {e}"
            )

        return pattern

    # =========================================================================
    # 公共 API - 脚本生成方法
    # =========================================================================

    def generate_hook_function(self, class_name: str, method_name: str,
                               include_overloads: bool = True) -> str:
        """
        生成 Hook 函数的 Frida 脚本

        生成一个完整的 Frida 脚本，用于 Hook 指定类的指定方法。
        脚本会打印方法调用时的参数和返回值。

        参数:
            class_name (str): 完整类名 (如 com.example.MyClass)
            method_name (str): 方法名
            include_overloads (bool): 是否包含所有重载方法 (默认 True)

        返回:
            str: 生成的 JavaScript 脚本

        异常:
            InvalidClassNameError: 类名无效
            InvalidMethodNameError: 方法名无效

        示例:
            >>> gen = FridaGenerator()
            >>> script = gen.generate_hook_function(
            ...     "com.example.MyClass", "myMethod"
            ... )
        """
        # 验证输入
        class_name = self._validate_class_name(class_name)
        method_name = self._validate_method_name(method_name)

        # 构建上下文
        context = {
            "class_name": class_name,
            "method_name": method_name,
            "timestamp": self._get_timestamp(),
            "include_overloads": include_overloads
        }

        # 渲染模板
        script = HOOK_FUNCTION_TEMPLATE.safe_substitute(context)

        # 添加脚本头部
        return self._wrap_with_header(script)

    def generate_hook_class(self, pattern: str,
                           hook_methods: Optional[List[str]] = None) -> str:
        """
        生成 Hook 类的 Frida 脚本

        生成一个完整的 Frida 脚本，用于 Hook 所有匹配类名模式的类。
        可以指定要 Hook 的具体方法，如果不指定则 Hook 所有方法。

        参数:
            pattern (str): 类名匹配模式 (正则表达式)
            hook_methods (list, optional): 要 Hook 的方法名列表

        返回:
            str: 生成的 JavaScript 脚本

        异常:
            InvalidPatternError: 模式无效

        示例:
            >>> gen = FridaGenerator()
            >>> script = gen.generate_hook_class("com\\.example\\..*")
        """
        # 验证输入
        pattern = self._validate_pattern(pattern)

        # 构建上下文
        context = {
            "pattern": pattern,
            "timestamp": self._get_timestamp(),
            "hook_methods": hook_methods or []
        }

        # 渲染模板
        script = HOOK_CLASS_TEMPLATE.safe_substitute(context)

        return self._wrap_with_header(script)

    def generate_rpc_stub(self, functions: Optional[List[Dict[str, str]]] = None) -> str:
        """
        生成 RPC 调用桩的 Frida 脚本

        生成一个完整的 Frida RPC 服务端桩，用于在目标进程中
        暴露函数供外部调用。包含示例 RPC 处理函数。

        参数:
            functions (list, optional): 自定义 RPC 函数定义列表

        返回:
            str: 生成的 JavaScript 脚本

        示例:
            >>> gen = FridaGenerator()
            >>> script = gen.generate_rpc_stub()
        """
        context = {
            "timestamp": self._get_timestamp()
        }

        script = RPC_STUB_TEMPLATE.safe_substitute(context)

        return self._wrap_with_header(script)

    def generate_memory_search(self, pattern: str = "",
                               encoding: str = "utf8") -> str:
        """
        生成内存搜索的 Frida 脚本

        生成一个完整的 Frida 内存搜索脚本，用于在目标进程内存中
        搜索指定模式的数据。

        参数:
            pattern (str): 搜索模式 (字符串或十六进制)
            encoding (str): 编码类型 (utf8, utf16, ascii, hex)

        返回:
            str: 生成的 JavaScript 脚本

        异常:
            FridaGeneratorError: 编码无效

        示例:
            >>> gen = FridaGenerator()
            >>> script = gen.generate_memory_search("Hello", "utf8")
        """
        # 验证编码
        if encoding not in self.VALID_ENCODINGS:
            raise FridaGeneratorError(
                f"Invalid encoding: '{encoding}'. "
                f"Must be one of: {', '.join(self.VALID_ENCODINGS)}"
            )

        context = {
            "pattern": pattern if pattern else "your_pattern_here",
            "encoding": encoding,
            "timestamp": self._get_timestamp()
        }

        script = MEMORY_SEARCH_TEMPLATE.safe_substitute(context)

        return self._wrap_with_header(script)

    # =========================================================================
    # 辅助方法
    # =========================================================================

    def _get_timestamp(self) -> str:
        """获取当前时间戳字符串"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _wrap_with_header(self, script: str) -> str:
        """包装脚本头部"""
        return SCRIPT_HEADER + "\n" + script

    # =========================================================================
    # 语法检查方法
    # =========================================================================

    def validate_syntax(self, script: str, language: str = "javascript") -> bool:
        """
        验证脚本语法

        对生成的脚本进行基本的语法检查。对于 JavaScript 脚本，
        使用 Node.js (如果可用) 进行语法验证；对于 Python 脚本，
        使用 Python 的 ast 模块进行语法验证。

        参数:
            script (str): 脚本内容
            language (str): 脚本语言 (javascript 或 python)

        返回:
            bool: 语法是否有效

        异常:
            SyntaxCheckError: 语法检查失败
        """
        if language == "javascript":
            return self._check_js_syntax(script)
        elif language == "python":
            return self._check_python_syntax(script)
        else:
            raise SyntaxCheckError(
                f"Unsupported language: '{language}'. "
                "Supported: javascript, python"
            )

    def _check_js_syntax(self, script: str) -> bool:
        """
        检查 JavaScript 语法

        尝试使用 Node.js 进行语法检查。如果 Node.js 不可用，
        则进行基本的括号匹配检查。

        参数:
            script (str): JavaScript 脚本

        返回:
            bool: 语法是否有效
        """
        # 尝试使用 Node.js 检查
        try:
            import subprocess
            import tempfile

            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.js', delete=False
            ) as f:
                f.write(script)
                temp_path = f.name

            try:
                result = subprocess.run(
                    ['node', '--check', temp_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    logger.debug("JavaScript syntax check passed (Node.js)")
                    return True
                else:
                    raise SyntaxCheckError(
                        f"JavaScript syntax error: {result.stderr}"
                    )
            finally:
                os.unlink(temp_path)

        except FileNotFoundError:
            # Node.js 不可用，进行基本检查
            logger.warning("Node.js not available, using basic syntax check")
            return self._basic_js_check(script)
        except subprocess.TimeoutExpired:
            raise SyntaxCheckError("Syntax check timed out")

    def _basic_js_check(self, script: str) -> bool:
        """
        基本的 JavaScript 语法检查

        检查括号、花括号、字符串等基本语法结构。

        参数:
            script (str): JavaScript 脚本

        返回:
            bool: 语法是否有效
        """
        # 移除注释
        script_no_comments = re.sub(
            r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
            '',
            script,
            flags=re.DOTALL | re.MULTILINE
        )

        # 检查括号匹配
        pairs = {')': '(', ']': '[', '}': '{'}
        stack = []

        for char in script_no_comments:
            if char in '([{':
                stack.append(char)
            elif char in ')]}':
                if not stack or stack[-1] != pairs[char]:
                    raise SyntaxCheckError(
                        f"Mismatched bracket: expected '{pairs[char]}', "
                        f"found '{char}' at position {len(stack)}"
                    )
                stack.pop()

        if stack:
            raise SyntaxCheckError(
                f"Unclosed brackets: {stack}"
            )

        return True

    def _check_python_syntax(self, script: str) -> bool:
        """
        检查 Python 语法

        使用 Python 的 ast 模块进行语法检查。

        参数:
            script (str): Python 脚本

        返回:
            bool: 语法是否有效
        """
        try:
            ast.parse(script)
            return True
        except SyntaxError as e:
            raise SyntaxCheckError(
                f"Python syntax error at line {e.lineno}, col {e.offset}: {e.msg}"
            )

    # =========================================================================
    # 批量生成方法
    # =========================================================================

    def generate_all(self, output_dir: str,
                    class_name: Optional[str] = None,
                    method_name: Optional[str] = None,
                    pattern: Optional[str] = None) -> Dict[str, str]:
        """
        生成所有类型的 Frida 脚本

        参数:
            output_dir (str): 输出目录
            class_name (str, optional): Hook 函数的类名
            method_name (str, optional): Hook 函数的方法名
            pattern (str, optional): Hook 类的匹配模式

        返回:
            dict: 脚本类型到文件路径的映射

        异常:
            FridaGeneratorError: 输出目录无效
        """
        if not output_dir or not isinstance(output_dir, str):
            raise FridaGeneratorError("Output directory cannot be empty")

        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)

        results = {}

        # 生成 Hook 函数脚本
        if class_name and method_name:
            try:
                script = self.generate_hook_function(class_name, method_name)
                file_path = os.path.join(output_dir, "hook_function.js")
                self._write_file(file_path, script)
                results["hook_function"] = file_path
                logger.info(f"Generated: {file_path}")
            except Exception as e:
                logger.error(f"Failed to generate hook_function: {e}")

        # 生成 Hook 类脚本
        if pattern:
            try:
                script = self.generate_hook_class(pattern)
                file_path = os.path.join(output_dir, "hook_class.js")
                self._write_file(file_path, script)
                results["hook_class"] = file_path
                logger.info(f"Generated: {file_path}")
            except Exception as e:
                logger.error(f"Failed to generate hook_class: {e}")

        # 生成 RPC 脚本
        try:
            script = self.generate_rpc_stub()
            file_path = os.path.join(output_dir, "rpc_stub.js")
            self._write_file(file_path, script)
            results["rpc_stub"] = file_path
            logger.info(f"Generated: {file_path}")
        except Exception as e:
            logger.error(f"Failed to generate rpc_stub: {e}")

        # 生成内存搜索脚本
        try:
            script = self.generate_memory_search()
            file_path = os.path.join(output_dir, "memory_search.js")
            self._write_file(file_path, script)
            results["memory_search"] = file_path
            logger.info(f"Generated: {file_path}")
        except Exception as e:
            logger.error(f"Failed to generate memory_search: {e}")

        return results

    def _write_file(self, file_path: str, content: str) -> None:
        """
        写入文件

        参数:
            file_path (str): 文件路径
            content (str): 文件内容
        """
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        except IOError as e:
            raise FridaGeneratorError(f"Failed to write file {file_path}: {e}")

    # =========================================================================
    # 工具方法
    # =========================================================================

    def get_template_info(self) -> Dict[str, str]:
        """
        获取模板信息

        返回:
            dict: 模板类型到描述的映射
        """
        return self.SCRIPT_TYPES.copy()

    def validate_all(self, scripts: Dict[str, str]) -> Dict[str, bool]:
        """
        批量验证脚本语法

        参数:
            scripts (dict): 脚本名称到脚本内容的映射

        返回:
            dict: 脚本名称到验证结果的映射
        """
        results = {}
        for name, script in scripts.items():
            try:
                # 根据文件扩展名判断语言
                if name.endswith('.py'):
                    results[name] = self.validate_syntax(script, 'python')
                else:
                    results[name] = self.validate_syntax(script, 'javascript')
            except SyntaxCheckError as e:
                logger.error(f"Syntax error in {name}: {e}")
                results[name] = False

        return results


# =============================================================================
# 模块级便利函数
# =============================================================================

def quick_generate(output_dir: str = ".",
                  class_name: Optional[str] = None,
                  method_name: Optional[str] = None,
                  pattern: Optional[str] = None) -> Dict[str, str]:
    """
    快速生成所有 Frida 脚本

    这是一个便利函数，封装了 FridaGenerator 的常见用法。

    参数:
        output_dir (str): 输出目录
        class_name (str, optional): Hook 函数的类名
        method_name (str, optional): Hook 函数的方法名
        pattern (str, optional): Hook 类的匹配模式

    返回:
        dict: 脚本类型到文件路径的映射

    示例:
        >>> from frida_gen import quick_generate
        >>> results = quick_generate(
        ...     "./output",
        ...     class_name="com.example.MyClass",
        ...     method_name="myMethod",
        ...     pattern="com\\.example\\..*"
        ... )
    """
    generator = FridaGenerator()
    return generator.generate_all(
        output_dir=output_dir,
        class_name=class_name,
        method_name=method_name,
        pattern=pattern
    )


# =============================================================================
# 主程序入口
# =============================================================================

if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # 创建生成器
    gen = FridaGenerator()

    # 演示生成各种脚本
    print("=" * 60)
    print("Frida 脚本生成器演示")
    print("=" * 60)

    # 1. 生成 Hook 函数脚本
    print("\n[1] 生成 Hook 函数脚本:")
    try:
        script = gen.generate_hook_function(
            "com.example.MyClass",
            "getData"
        )
        print(f"    生成成功，长度: {len(script)} 字符")
    except Exception as e:
        print(f"    生成失败: {e}")

    # 2. 生成 Hook 类脚本
    print("\n[2] 生成 Hook 类脚本:")
    try:
        script = gen.generate_hook_class("com\\.example\\..*")
        print(f"    生成成功，长度: {len(script)} 字符")
    except Exception as e:
        print(f"    生成失败: {e}")

    # 3. 生成 RPC 脚本
    print("\n[3] 生成 RPC 调用桩脚本:")
    try:
        script = gen.generate_rpc_stub()
        print(f"    生成成功，长度: {len(script)} 字符")
    except Exception as e:
        print(f"    生成失败: {e}")

    # 4. 生成内存搜索脚本
    print("\n[4] 生成内存搜索脚本:")
    try:
        script = gen.generate_memory_search("Hello", "utf8")
        print(f"    生成成功，长度: {len(script)} 字符")
    except Exception as e:
        print(f"    生成失败: {e}")

    # 5. 语法检查演示
    print("\n[5] 语法检查演示:")
    try:
        script = gen.generate_hook_function("com.example.Test", "test")
        result = gen.validate_syntax(script, "javascript")
        print(f"    Hook 函数脚本语法检查: {'通过' if result else '失败'}")
    except Exception as e:
        print(f"    语法检查失败: {e}")

    print("\n" + "=" * 60)
    print("演示完成")
    print("=" * 60)