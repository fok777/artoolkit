#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
artoolkit - Android Reverse Engineering Toolkit
==============================================
功能齐全的安卓逆向工程工具箱，集成 APK 分析、SO 逆向、Frida 脚本生成、
网络捕获、加密识别等核心能力。

用法：
    python3 artoolkit.py --help
    python3 artoolkit.py apk info --apk app.apk
    python3 artoolkit.py analyze full --apk app.apk
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# 确保模块可导入
sys.path.insert(0, str(Path(__file__).parent))

from modules.apk_analysis import APKAnalyzer, ApkAnalysisResult
from modules.crypto_detect import CryptoDetector
from modules.dex_decompile import DexDecompiler
from modules.flutter_parse import FlutterParser
from modules.frida_gen import FridaGenerator
from modules.network_capture import NetworkAnalyzer
from modules.project_manager import ProjectManager
from modules.resource_extract import ResourceExtractor
from modules.session_manager import SessionManager
from modules.shell_detect import ShellDetector
from modules.so_analysis import SOAnalyzer
from modules.string_decrypt import StringDecryptor
from modules.unidbg_sim import UnidbgSimulator

__version__ = "1.0.0"


# ============================================================================
# 工具函数
# ============================================================================

def print_json(data: Any, output_file: Optional[str] = None) -> None:
    """输出 JSON 格式数据"""
    text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"[+] 结果已保存到: {output_file}")
    else:
        print(text)


def print_table(rows: List[List[str]], headers: List[str]) -> None:
    """打印表格"""
    if not rows:
        return
    # 计算列宽
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))
    # 打印表头
    header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    print(header_line)
    print("  ".join("-" * col_widths[i] for i in range(len(headers))))
    # 打印数据行
    for row in rows:
        line = "  ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
        print(line)


def check_tools() -> Dict[str, bool]:
    """检查系统工具可用性"""
    tools = ["aapt", "apktool", "baksmali", "java", "node", "strings", "nm", "objdump"]
    result = {}
    for tool in tools:
        path = os.popen(f"which {tool} 2>/dev/null").read().strip()
        result[tool] = bool(path)
    return result


# ============================================================================
# 命令处理器
# ============================================================================

class ArToolkitCLI:
    """artoolkit CLI 主类"""

    def __init__(self):
        self.apk_analyzer = APKAnalyzer()
        self.crypto_detector = CryptoDetector()
        self.dex_compiler = DexDecompiler()
        self.flutter_parser = FlutterParser()
        self.frida_gen = FridaGenerator()
        self.network_analyzer = NetworkAnalyzer()
        self.project_mgr = ProjectManager()
        self.resource_extractor = ResourceExtractor()
        self.session_mgr = SessionManager()
        self.shell_detector = ShellDetector()
        self.so_analyzer = SOAnalyzer()
        self.string_decryptor = StringDecryptor()
        self.unidbg_sim = UnidbgSimulator()

    # ---- analyze 命令 ----
    def cmd_analyze(self, args: argparse.Namespace) -> int:
        """综合分析"""
        apk_path = args.apk
        if not os.path.exists(apk_path):
            print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
            return 1

        print(f"[*] 开始分析: {apk_path}")
        results: Dict[str, Any] = {"apk": apk_path, "analyses": {}}

        # APK 基本信息
        print("[*] 分析 APK 基本信息...")
        try:
            apk_result = self.apk_analyzer.analyze(apk_path)
            results["analyses"]["apk_info"] = apk_result.to_dict()
        except Exception as e:
            results["analyses"]["apk_info"] = {"error": str(e)}

        # 加固检测
        print("[*] 检测加固方案...")
        try:
            shell_result = self.shell_detector.analyze_all(apk_path)
            results["analyses"]["shell_detection"] = shell_result
        except Exception as e:
            results["analyses"]["shell_detection"] = {"error": str(e)}

        # 加密检测
        print("[*] 检测加密算法...")
        try:
            crypto_result = self.crypto_detector.analyze(apk_path)
            results["analyses"]["crypto"] = crypto_result
        except Exception as e:
            results["analyses"]["crypto"] = {"error": str(e)}

        # 网络分析
        print("[*] 分析网络特征...")
        try:
            network_result = self.network_analyzer.extract_endpoints(apk_path)
            results["analyses"]["network"] = network_result
        except Exception as e:
            results["analyses"]["network"] = {"error": str(e)}

        # SO 分析
        print("[*] 分析 SO 文件...")
        try:
            import zipfile
            with zipfile.ZipFile(apk_path) as zf:
                so_files = [n for n in zf.namelist() if n.endswith('.so')]
            if so_files:
                so_results = []
                with zipfile.ZipFile(apk_path) as zf:
                    for so_name in so_files[:5]:  # 最多分析5个
                        zf.extract(so_name, "/tmp/artoolkit_so")
                        so_path = os.path.join("/tmp/artoolkit_so", so_name)
                        try:
                            so_info = self.so_analyzer.analyze(so_path)
                            so_results.append(so_info)
                        except Exception:
                            pass
                results["analyses"]["so_analysis"] = so_results
        except Exception as e:
            results["analyses"]["so_analysis"] = {"error": str(e)}

        # 输出
        if args.json:
            print_json(results, args.output)
        else:
            self._print_analyze_summary(results)

        return 0

    def _print_analyze_summary(self, results: Dict[str, Any]) -> None:
        """打印分析摘要"""
        print("\n" + "=" * 60)
        print("  APK 逆向分析报告")
        print("=" * 60)

        analyses = results.get("analyses", {})

        # APK 信息
        apk_info = analyses.get("apk_info", {})
        if apk_info and "error" not in apk_info:
            meta = apk_info.get("metadata", {})
            print(f"\n📦 APK 基本信息")
            print(f"  包名: {meta.get('package_name', 'N/A')}")
            print(f"  版本: {meta.get('version_name', 'N/A')} ({meta.get('version_code', 'N/A')})")
            print(f"  最低 SDK: Android {meta.get('min_sdk', 'N/A')}")
            print(f"  目标 SDK: Android {meta.get('target_sdk', 'N/A')}")

            perms = apk_info.get("permissions", [])
            if perms:
                print(f"\n  权限 ({len(perms)}):")
                for p in perms[:10]:
                    print(f"    - {p.get('name', 'N/A')}")

        # 加固检测
        shell = analyses.get("shell_detection", {})
        if shell and "error" not in shell:
            print(f"\n🛡️ 加固检测")
            shells = shell.get("shells", [])
            if shells:
                for s in shells:
                    print(f"  - {s.get('name', 'Unknown')}: {s.get('confidence', 'N/A')}")
            else:
                print("  未检测到常见加固")

        # 加密检测
        crypto = analyses.get("crypto", {})
        if crypto and "error" not in crypto:
            print(f"\n🔐 加密检测")
            algos = crypto.get("algorithms", [])
            if algos:
                for a in algos:
                    print(f"  - {a.get('name', 'Unknown')}: {a.get('risk', 'N/A')}")
            keys = crypto.get("keys", [])
            if keys:
                print(f"  发现 {len(keys)} 个潜在密钥")

        # 网络分析
        network = analyses.get("network", {})
        if network and "error" not in network:
            print(f"\n🌐 网络分析")
            endpoints = network.get("endpoints", [])
            if endpoints:
                urls = set()
                for ep in endpoints:
                    for u in ep.get("urls", []):
                        urls.add(u)
                print(f"  发现 {len(urls)} 个唯一 URL")
                for u in list(urls)[:5]:
                    print(f"  - {u}")

        print("\n" + "=" * 60)

    # ---- apk 命令 ----
    def cmd_apk(self, args: argparse.Namespace) -> int:
        """APK 分析"""
        action = args.apk_action
        apk_path = args.apk

        if action == "info":
            if not os.path.exists(apk_path):
                print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
                return 1
            result = self.apk_analyzer.analyze(apk_path)
            if args.json:
                print_json(result.to_dict(), args.output)
            else:
                meta = result.metadata
                print(f"📦 APK 信息")
                print(f"  包名: {meta.package_name}")
                print(f"  版本: {meta.version_name} (v{meta.version_code})")
                print(f"  最低 SDK: Android {meta.min_sdk}")
                print(f"  目标 SDK: Android {meta.target_sdk}")
                print(f"  文件大小: {os.path.getsize(apk_path) / 1024:.1f} KB")
                if result.permissions:
                    print(f"\n  权限 ({len(result.permissions)}):")
                    for p in result.permissions:
                        danger = "⚠️" if p.is_dangerous else "  "
                        print(f"    {danger} {p.name}")
                if result.warnings:
                    print(f"\n  警告:")
                    for w in result.warnings:
                        print(f"    - {w}")
            return 0

        elif action == "manifest":
            if not os.path.exists(apk_path):
                print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
                return 1
            manifest = self.apk_analyzer.get_manifest(apk_path)
            if manifest is None:
                print("[-] 无法解析 AndroidManifest.xml", file=sys.stderr)
                return 1
            # 简单输出
            import xml.etree.ElementTree as ET
            print(ET.tostring(manifest, encoding='unicode'))
            return 0

        elif action == "permissions":
            if not os.path.exists(apk_path):
                print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
                return 1
            perms = self.apk_analyzer.get_permissions(apk_path)
            if args.json:
                print_json([p.to_dict() for p in perms], args.output)
            else:
                print(f"📋 权限列表 ({len(perms)}):")
                for p in perms:
                    danger = "⚠️ 危险" if p.is_dangerous else ""
                    deprecated = " (已废弃)" if p.is_deprecated else ""
                    print(f"  - {p.name} {danger}{deprecated}")
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- crypto 命令 ----
    def cmd_crypto(self, args: argparse.Namespace) -> int:
        """加密检测"""
        action = args.crypto_action
        target = args.target

        if action == "detect":
            if not os.path.exists(target):
                print(f"[-] 文件不存在: {target}", file=sys.stderr)
                return 1
            result = self.crypto_detector.detect_algorithms(target)
            if args.json:
                print_json(result, args.output)
            else:
                print("🔐 加密算法检测")
                algos = result.get("algorithms", [])
                if algos:
                    for a in algos:
                        print(f"  - {a.get('name')}: {a.get('risk')} ({a.get('count', 0)} 处)")
                else:
                    print("  未检测到已知加密算法")
            return 0

        elif action == "keys":
            if not os.path.exists(target):
                print(f"[-] 文件不存在: {target}", file=sys.stderr)
                return 1
            result = self.crypto_detector.extract_keys(target)
            if args.json:
                print_json(result, args.output)
            else:
                print("🔑 硬编码密钥")
                keys = result.get("keys", [])
                if keys:
                    for k in keys:
                        print(f"  - {k.get('type', 'Unknown')}: {k.get('value', '')[:40]}...")
                else:
                    print("  未发现硬编码密钥")
            return 0

        elif action == "libs":
            if not os.path.exists(target):
                print(f"[-] 文件不存在: {target}", file=sys.stderr)
                return 1
            result = self.crypto_detector.detect_crypto_libraries(target)
            if args.json:
                print_json(result, args.output)
            else:
                print("📚 加密库检测")
                libs = result.get("libraries", [])
                if libs:
                    for lib in libs:
                        print(f"  - {lib.get('name')}: {lib.get('confidence')}")
                else:
                    print("  未检测到已知加密库")
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- dex 命令 ----
    def cmd_dex(self, args: argparse.Namespace) -> int:
        """DEX 分析"""
        action = args.dex_action
        apk_path = args.apk

        if action == "extract":
            if not os.path.exists(apk_path):
                print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
                return 1
            dest = args.dest or "./dex_output"
            result = self.dex_compiler.decompile(apk_path, dest)
            if args.json:
                print_json(result, args.output)
            else:
                print(f"📄 DEX 提取完成")
                print(f"  输出目录: {dest}")
                print(f"  DEX 数量: {result.get('dex_count', 0)}")
            return 0

        elif action == "info":
            if not os.path.exists(apk_path):
                print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
                return 1
            result = self.dex_compiler.decompile(apk_path, None)
            if args.json:
                print_json(result, args.output)
            else:
                print("📄 DEX 信息")
                print(f"  DEX 数量: {result.get('dex_count', 0)}")
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- so 命令 ----
    def cmd_so(self, args: argparse.Namespace) -> int:
        """SO 分析"""
        action = args.so_action
        so_path = args.so

        if action == "info":
            if not os.path.exists(so_path):
                print(f"[-] 文件不存在: {so_path}", file=sys.stderr)
                return 1
            result = self.so_analyzer.analyze(so_path)
            if args.json:
                print_json(result, args.output)
            else:
                print("📄 SO 文件信息")
                info = result.get("file_info", {})
                print(f"  架构: {info.get('architecture', 'N/A')}")
                print(f"  类型: {info.get('file_type', 'N/A')}")
                print(f"  大小: {info.get('size', 0) / 1024:.1f} KB")
            return 0

        elif action == "strings":
            if not os.path.exists(so_path):
                print(f"[-] 文件不存在: {so_path}", file=sys.stderr)
                return 1
            result = self.so_analyzer.extract_strings(so_path)
            if args.json:
                print_json(result, args.output)
            else:
                print("📄 SO 字符串")
                strings = result.get("strings", [])
                print(f"  提取 {len(strings)} 个字符串")
                for s in strings[:20]:
                    print(f"  - {s}")
            return 0

        elif action == "unity":
            if not os.path.exists(so_path):
                print(f"[-] 文件不存在: {so_path}", file=sys.stderr)
                return 1
            result = self.so_analyzer.detect_unity(so_path)
            if args.json:
                print_json(result, args.output)
            else:
                print("🎮 Unity 检测")
                if result.get("is_unity"):
                    print("  是 Unity 工程")
                    symbols = result.get("il2cpp_symbols", [])
                    print(f"  Il2CPP 符号: {len(symbols)} 个")
                else:
                    print("  非 Unity 工程")
            return 0

        elif action == "symbols":
            if not os.path.exists(so_path):
                print(f"[-] 文件不存在: {so_path}", file=sys.stderr)
                return 1
            result = self.so_analyzer.extract_il2cpp_symbols(so_path)
            if args.json:
                print_json(result, args.output)
            else:
                print("📄 函数符号")
                symbols = result if isinstance(result, list) else result.get("symbols", [])
                print(f"  提取 {len(symbols)} 个符号")
                for s in symbols[:20]:
                    print(f"  - {s}")
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- crypto 命令 ----
    def cmd_shell(self, args: argparse.Namespace) -> int:
        """加固检测"""
        action = args.shell_action
        apk_path = args.apk

        if action == "detect":
            if not os.path.exists(apk_path):
                print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
                return 1
            result = self.shell_detector.analyze_all(apk_path)
            if args.json:
                print_json(result, args.output)
            else:
                print("🛡️ 加固检测结果")
                shells = result.get("shells", [])
                if shells:
                    for s in shells:
                        print(f"  - {s.get('name')}: 置信度 {s.get('confidence')}")
                else:
                    print("  未检测到常见加固方案")
            return 0

        elif action == "dex":
            if not os.path.exists(apk_path):
                print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
                return 1
            result = self.shell_detector.check_dex_integrity(apk_path)
            if args.json:
                print_json(result, args.output)
            else:
                print("📄 DEX 完整性检查")
                issues = result.get("issues", [])
                if issues:
                    for i in issues:
                        print(f"  - {i.get('type')}: {i.get('description')}")
                else:
                    print("  DEX 文件完整")
            return 0

        elif action == "frida":
            if not os.path.exists(apk_path):
                print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
                return 1
            script = self.shell_detector.generate_dump_script(apk_path)
            dest = args.dest or "frida_dump.js"
            with open(dest, 'w') as f:
                f.write(script)
            print(f"[+] Frida dump 脚本已生成: {dest}")
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- frida 命令 ----
    def cmd_frida(self, args: argparse.Namespace) -> int:
        """Frida 脚本生成"""
        action = args.frida_action

        if action == "generate":
            cls = args.class_name
            method = args.method
            gen_type = args.type or "hook"
            dest = args.dest or "./frida_script.js"

            if gen_type == "hook":
                script = self.frida_gen.generate_hook_function(cls, method)
            elif gen_type == "trace":
                script = self.frida_gen.generate_hook_class(cls, method)
            elif gen_type == "intercept":
                script = self.frida_gen.generate_hook_function(cls, method, intercept=True)
            elif gen_type == "rpc":
                script = self.frida_gen.generate_rpc_stub()
            elif gen_type == "memory":
                script = self.frida_gen.generate_memory_search()
            else:
                print(f"[-] 未知类型: {gen_type}", file=sys.stderr)
                return 1

            with open(dest, 'w') as f:
                f.write(script)
            print(f"[+] Frida 脚本已生成: {dest}")
            return 0

        elif action == "list":
            info = self.frida_gen.get_template_info()
            print("📋 可用模板:")
            for name, desc in info.items():
                print(f"  - {name}: {desc}")
            return 0

        elif action == "all":
            cls = args.class_name or "com.example"
            method = args.method or "onCreate"
            output_dir = args.dest or "./frida_output"
            os.makedirs(output_dir, exist_ok=True)
            self.frida_gen.generate_all(output_dir, cls, method)
            print(f"[+] 所有脚本已生成到: {output_dir}")
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- flutter 命令 ----
    def cmd_flutter(self, args: argparse.Namespace) -> int:
        """Flutter 分析"""
        apk_path = args.apk
        action = args.flutter_action

        if not os.path.exists(apk_path):
            print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
            return 1

        if action == "detect":
            result = self.flutter_parser.detect_flutter(apk_path)
            if args.json:
                print_json(result, args.output)
            else:
                print("🎮 Flutter 检测")
                print(f"  是 Flutter 工程: {result.get('is_flutter', False)}")
                print(f"  置信度: {result.get('confidence', 'N/A')}")
                if result.get("flutter_version"):
                    print(f"  Flutter 版本: {result['flutter_version']}")
                if result.get("dart_version"):
                    print(f"  Dart 版本: {result['dart_version']}")
                indicators = result.get("indicators", [])
                if indicators:
                    print("  特征:")
                    for i in indicators:
                        print(f"    - {i}")
            return 0

        elif action == "strings":
            result = self.flutter_parser.extract_dart_strings(apk_path)
            if args.json:
                print_json(result, args.output)
            else:
                print("📄 Dart 字符串")
                strings = result.get("strings", [])
                print(f"  提取 {len(strings)} 个字符串")
                for s in strings[:30]:
                    print(f"  - {s}")
            return 0

        elif action == "methods":
            result = self.flutter_parser.extract_dart_methods(apk_path)
            if args.json:
                print_json(result, args.output)
            else:
                print("📄 Dart 方法名")
                methods = result.get("methods", [])
                print(f"  提取 {len(methods)} 个方法名")
                for m in methods[:30]:
                    print(f"  - {m}")
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- string 命令 ----
    def cmd_string(self, args: argparse.Namespace) -> int:
        """字符串解密"""
        action = args.string_action

        if action == "xor":
            data = args.data
            key = args.key or "0x00"
            decoded = self.string_decryptor.xor_decrypt(data, key)
            print(f"🔓 XOR 解密: {decoded}")
            return 0

        elif action == "base64":
            data = args.data
            try:
                decoded = self.string_decryptor.base64_decrypt(data)
                print(f"🔓 Base64 解密: {decoded}")
            except Exception as e:
                print(f"[-] Base64 解密失败: {e}", file=sys.stderr)
                return 1
            return 0

        elif action == "rc4":
            data = args.data
            key = args.key
            if not key:
                print("[-] RC4 需要密钥 (--key)", file=sys.stderr)
                return 1
            decoded = self.string_decryptor.rc4_decrypt(data, key)
            print(f"🔓 RC4 解密: {decoded}")
            return 0

        elif action == "auto":
            if args.target:
                if not os.path.exists(args.target):
                    print(f"[-] 文件不存在: {args.target}", file=sys.stderr)
                    return 1
                result = self.string_decryptor.auto_detect_file(args.target)
                if args.json:
                    print_json(result, args.output)
                else:
                    print(f"🔍 自动检测: {result['file']}")
                    print(f"  总字符串: {result['total_strings']}")
                    print(f"  检测到加密: {result['detected_count']}")
                    for r in result['results'][:10]:
                        print(f"  [{r['type']}] {r['original'][:30]}... -> {r['decrypted'][:30]}...")
            elif args.data:
                results = self.string_decryptor.auto_decrypt(args.data)
                if args.json:
                    print_json(results, args.output)
                else:
                    for r in results:
                        print(f"  [{r['type']}] {r['decoded'][:50]}...")
            else:
                print("[-] 请提供 --data 或 --target 参数", file=sys.stderr)
                return 1
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- unidbg 命令 ----
    def cmd_unidbg(self, args: argparse.Namespace) -> int:
        """Unidbg 模拟"""
        action = args.unidbg_action
        so_path = args.so

        if not os.path.exists(so_path):
            print(f"[-] 文件不存在: {so_path}", file=sys.stderr)
            return 1

        if action == "java":
            class_name = args.class_name or "com.example.Native"
            script = self.unidbg_sim.generate_java_sim(so_path, class_name)
            dest = args.dest or "unidbg_java_sim.py"
            with open(dest, 'w') as f:
                f.write(script)
            print(f"[+] Java 模拟脚本已生成: {dest}")
            return 0

        elif action == "native":
            func_name = args.function or "nativeFunction"
            script = self.unidbg_sim.generate_native_sim(so_path, func_name)
            dest = args.dest or "unidbg_native_sim.py"
            with open(dest, 'w') as f:
                f.write(script)
            print(f"[+] Native 模拟脚本已生成: {dest}")
            return 0

        elif action == "signatures":
            result = self.unidbg_sim.extract_function_signatures(so_path)
            if args.json:
                print_json(result, args.output)
            else:
                print("📄 函数签名")
                sigs = result if isinstance(result, list) else result.get("signatures", [])
                print(f"  提取 {len(sigs)} 个签名")
                for s in sigs[:20]:
                    print(f"  - {s}")
            return 0

        elif action == "config":
            class_name = args.class_name or "com.example.Native"
            methods = args.methods or "method1,method2"
            config = {
                "so_path": so_path,
                "type": args.type or "java",
                "class_name": class_name,
                "methods": methods.split(","),
            }
            script = self.unidbg_sim.generate_emulation_script(config)
            dest = args.dest or "unidbg_config.py"
            with open(dest, 'w') as f:
                f.write(script)
            print(f"[+] 模拟配置已生成: {dest}")
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- network 命令 ----
    def cmd_network(self, args: argparse.Namespace) -> int:
        """网络分析"""
        action = args.network_action
        apk_path = args.apk

        if action == "scan":
            if not os.path.exists(apk_path):
                print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
                return 1
            result = self.network_analyzer.extract_endpoints(apk_path)
            if args.json:
                print_json(result, args.output)
            else:
                print("🌐 网络端点扫描")
                endpoints = result.get("endpoints", [])
                print(f"  发现 {len(endpoints)} 个端点")
                for ep in endpoints[:10]:
                    print(f"  - {ep.get('url', 'N/A')}")
            return 0

        elif action == "urls":
            if not os.path.exists(apk_path):
                print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
                return 1
            result = self.network_analyzer.extract_endpoints(apk_path)
            endpoints = result.get("endpoints", [])
            urls = set()
            for ep in endpoints:
                for u in ep.get("urls", []):
                    urls.add(u)
            if args.json:
                print_json({"urls": list(urls)}, args.output)
            else:
                print(f"🔗 URL 列表 ({len(urls)}):")
                for u in sorted(urls):
                    print(f"  - {u}")
            return 0

        elif action == "ports":
            if not os.path.exists(apk_path):
                print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
                return 1
            # 简单端口检测
            import subprocess
            result = subprocess.run(
                ["strings", apk_path],
                capture_output=True, text=True
            )
            import re
            ports = set()
            for match in re.finditer(r':(\d{2,5})', result.stdout):
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    ports.add(port)
            if args.json:
                print_json({"ports": sorted(ports)}, args.output)
            else:
                print(f"🔌 检测到的端口: {sorted(ports)}")
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- resource 命令 ----
    def cmd_resource(self, args: argparse.Namespace) -> int:
        """资源提取"""
        apk_path = args.apk
        dest = args.dest or "./resources"

        if not os.path.exists(apk_path):
            print(f"[-] 文件不存在: {apk_path}", file=sys.stderr)
            return 1

        result = self.resource_extractor.extract_all(apk_path, dest)
        if args.json:
            print_json(result, args.output)
        else:
            print(f"📦 资源提取完成")
            print(f"  输出目录: {dest}")
            stats = result.get("statistics", {})
            for k, v in stats.items():
                print(f"  {k}: {v}")
        return 0

    # ---- project 命令 ----
    def cmd_project(self, args: argparse.Namespace) -> int:
        """项目管理"""
        action = args.project_action

        if action == "create":
            name = args.name
            desc = args.description or ""
            result = self.project_mgr.create(name, desc)
            print(f"[+] 项目已创建: {name}")
            return 0

        elif action == "list":
            projects = self.project_mgr.list_projects()
            if args.json:
                print_json([p for p in projects], args.output)
            else:
                print("📋 项目列表")
                if not projects:
                    print("  (无项目)")
                for p in projects:
                    print(f"  - {p.get('name')}: {p.get('description', '')}")
            return 0

        elif action == "switch":
            name = args.name
            result = self.project_mgr.switch(name)
            if result.get("success"):
                print(f"[+] 已切换到项目: {name}")
            else:
                print(f"[-] 切换失败: {result.get('error', '未知错误')}", file=sys.stderr)
                return 1
            return 0

        elif action == "remove":
            name = args.name
            force = args.force or False
            result = self.project_mgr.remove(name, force)
            if result.get("success"):
                print(f"[+] 项目已删除: {name}")
            else:
                print(f"[-] 删除失败: {result.get('error', '未知错误')}", file=sys.stderr)
                return 1
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- session 命令 ----
    def cmd_session(self, args: argparse.Namespace) -> int:
        """会话管理"""
        action = args.session_action

        if action == "create":
            apk_path = args.apk
            name = args.name or "session"
            sid = self.session_mgr.create_session(apk_path, name)
            if sid:
                print(f"[+] 会话已创建: {sid}")
            else:
                print("[-] 会话创建失败", file=sys.stderr)
                return 1
            return 0

        elif action == "list":
            sessions = self.session_mgr.list_sessions()
            if args.json:
                print_json(sessions, args.output)
            else:
                print("📋 会话列表")
                if not sessions:
                    print("  (无会话)")
                for s in sessions:
                    print(f"  - {s.get('id')}: {s.get('name')} ({s.get('apk', 'N/A')})")
            return 0

        elif action == "switch":
            sid = args.session_id
            if self.session_mgr.switch_session(sid):
                print(f"[+] 已切换到会话: {sid}")
            else:
                print(f"[-] 切换失败: {sid}", file=sys.stderr)
                return 1
            return 0

        elif action == "remove":
            sid = args.session_id
            if self.session_mgr.delete_session(sid):
                print(f"[+] 会话已删除: {sid}")
            else:
                print(f"[-] 删除失败: {sid}", file=sys.stderr)
                return 1
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- tools 命令 ----
    def cmd_tools(self, args: argparse.Namespace) -> int:
        """工具状态"""
        action = args.tools_action

        if action == "check":
            tools = check_tools()
            if args.json:
                print_json(tools, args.output)
            else:
                print("🔧 工具状态")
                for tool, available in tools.items():
                    status = "✅" if available else "❌"
                    print(f"  {status} {tool}")
            return 0

        elif action == "so":
            result = self.so_analyzer.get_tool_status()
            if args.json:
                print_json(result, args.output)
            else:
                print("🔧 SO 分析工具状态")
                for tool, available in result.items():
                    status = "✅" if available else "❌"
                    print(f"  {status} {tool}")
            return 0

        print(f"[-] 未知操作: {action}", file=sys.stderr)
        return 1

    # ---- version 命令 ----
    def cmd_version(self, args: argparse.Namespace) -> int:
        """版本信息"""
        print(f"artoolkit v{__version__}")
        print("Android Reverse Engineering Toolkit")
        print(f"Python: {sys.version}")
        tools = check_tools()
        available = sum(1 for v in tools.values() if v)
        print(f"可用工具: {available}/{len(tools)}")
        return 0


# ============================================================================
# 主入口
# ============================================================================

def create_parser() -> argparse.ArgumentParser:
    """创建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog="artoolkit",
        description="artoolkit - Android Reverse Engineering Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s apk info --apk app.apk
  %(prog)s analyze full --apk app.apk --json --output result.json
  %(prog)s crypto detect --apk app.apk
  %(prog)s shell detect --apk app.apk
  %(prog)s frida generate --class com.example.Main --method onCreate --type hook
  %(prog)s so info --apk lib/armeabi-v7a/libnative.so
  %(prog)s project create --name my-project
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # ---- analyze ----
    p = subparsers.add_parser("analyze", help="综合分析")
    p.add_argument("--apk", required=True, help="APK 文件路径")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")
    p.add_argument("--quick", action="store_true", help="快速分析")

    # ---- apk ----
    p = subparsers.add_parser("apk", help="APK 分析")
    p.add_argument("apk_action", choices=["info", "manifest", "permissions"], help="操作")
    p.add_argument("--apk", required=True, help="APK 文件路径")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- crypto ----
    p = subparsers.add_parser("crypto", help="加密检测")
    p.add_argument("crypto_action", choices=["detect", "keys", "libs"], help="操作")
    p.add_argument("--target", required=True, help="目标文件")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- dex ----
    p = subparsers.add_parser("dex", help="DEX 分析")
    p.add_argument("dex_action", choices=["extract", "info"], help="操作")
    p.add_argument("--apk", required=True, help="APK 文件路径")
    p.add_argument("--dest", default=None, help="输出目录")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- so ----
    p = subparsers.add_parser("so", help="SO 分析")
    p.add_argument("so_action", choices=["info", "strings", "unity", "symbols"], help="操作")
    p.add_argument("--so", required=True, help="SO 文件路径")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- shell ----
    p = subparsers.add_parser("shell", help="加固检测")
    p.add_argument("shell_action", choices=["detect", "dex", "frida"], help="操作")
    p.add_argument("--apk", required=True, help="APK 文件路径")
    p.add_argument("--dest", default=None, help="输出文件")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- frida ----
    p = subparsers.add_parser("frida", help="Frida 脚本生成")
    p.add_argument("frida_action", choices=["generate", "list", "all"], help="操作")
    p.add_argument("--class", dest="class_name", default=None, help="类名")
    p.add_argument("--method", default=None, help="方法名")
    p.add_argument("--type", default="hook", choices=["hook", "trace", "intercept", "rpc", "memory"], help="脚本类型")
    p.add_argument("--dest", default=None, help="输出路径")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- flutter ----
    p = subparsers.add_parser("flutter", help="Flutter 分析")
    p.add_argument("flutter_action", choices=["detect", "strings", "methods"], help="操作")
    p.add_argument("--apk", required=True, help="APK 文件路径")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- string ----
    p = subparsers.add_parser("string", help="字符串解密")
    p.add_argument("string_action", choices=["xor", "base64", "rc4", "auto"], help="操作")
    p.add_argument("--data", default=None, help="要解密的数据")
    p.add_argument("--target", default=None, help="目标文件（auto 模式）")
    p.add_argument("--key", default=None, help="密钥")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- unidbg ----
    p = subparsers.add_parser("unidbg", help="Unidbg 模拟")
    p.add_argument("unidbg_action", choices=["java", "native", "signatures", "config"], help="操作")
    p.add_argument("--so", required=True, help="SO 文件路径")
    p.add_argument("--class", dest="class_name", default=None, help="类名")
    p.add_argument("--function", default=None, help="函数名")
    p.add_argument("--methods", default=None, help="方法列表（逗号分隔）")
    p.add_argument("--type", default="java", choices=["java", "native"], help="模拟类型")
    p.add_argument("--dest", default=None, help="输出路径")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- network ----
    p = subparsers.add_parser("network", help="网络分析")
    p.add_argument("network_action", choices=["scan", "urls", "ports"], help="操作")
    p.add_argument("--apk", required=True, help="APK 文件路径")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- resource ----
    p = subparsers.add_parser("resource", help="资源提取")
    p.add_argument("--apk", required=True, help="APK 文件路径")
    p.add_argument("--dest", default="./resources", help="输出目录")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- project ----
    p = subparsers.add_parser("project", help="项目管理")
    p.add_argument("project_action", choices=["create", "list", "switch", "remove"], help="操作")
    p.add_argument("--name", default=None, help="项目名")
    p.add_argument("--description", default=None, help="项目描述")
    p.add_argument("--force", action="store_true", help="强制删除")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- session ----
    p = subparsers.add_parser("session", help="会话管理")
    p.add_argument("session_action", choices=["create", "list", "switch", "remove"], help="操作")
    p.add_argument("--apk", default=None, help="APK 文件路径")
    p.add_argument("--name", default=None, help="会话名")
    p.add_argument("--session_id", default=None, help="会话 ID")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- tools ----
    p = subparsers.add_parser("tools", help="工具状态")
    p.add_argument("tools_action", choices=["check", "so"], help="操作")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--output", default=None, help="输出文件")

    # ---- version ----
    subparsers.add_parser("version", help="显示版本信息")

    return parser


def main() -> int:
    """主入口"""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    cli = ArToolkitCLI()

    try:
        if args.command == "analyze":
            return cli.cmd_analyze(args)
        elif args.command == "apk":
            return cli.cmd_apk(args)
        elif args.command == "crypto":
            return cli.cmd_crypto(args)
        elif args.command == "dex":
            return cli.cmd_dex(args)
        elif args.command == "so":
            return cli.cmd_so(args)
        elif args.command == "shell":
            return cli.cmd_shell(args)
        elif args.command == "frida":
            return cli.cmd_frida(args)
        elif args.command == "flutter":
            return cli.cmd_flutter(args)
        elif args.command == "string":
            return cli.cmd_string(args)
        elif args.command == "unidbg":
            return cli.cmd_unidbg(args)
        elif args.command == "network":
            return cli.cmd_network(args)
        elif args.command == "resource":
            return cli.cmd_resource(args)
        elif args.command == "project":
            return cli.cmd_project(args)
        elif args.command == "session":
            return cli.cmd_session(args)
        elif args.command == "tools":
            return cli.cmd_tools(args)
        elif args.command == "version":
            return cli.cmd_version(args)
        else:
            print(f"[-] 未知命令: {args.command}", file=sys.stderr)
            return 1
    except KeyboardInterrupt:
        print("\n[!] 用户中断", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"[-] 错误: {e}", file=sys.stderr)
        if "--json" in sys.argv:
            print(json.dumps({"error": str(e)}, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())