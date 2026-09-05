#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SO (Shared Object) 逆向分析模块
==============================
功能：对 Android native 库 (.so) 进行逆向分析，提取文件信息、Il2CPP 符号、
      Unity 引擎识别、字符串、函数签名等。

依赖：Python 3.6+ 标准库 + 系统工具 (file, strings, objdump, readelf, nm)

使用示例：
    from so_analysis import SOAnalyzer

    analyzer = SOAnalyzer()
    result = analyzer.analyze("/path/to/libunity.so")
    print(result)  # 结构化 JSON 结果
"""

import os
import re
import json
import subprocess
from typing import Dict, List, Optional, Any


class SOAnalyzerError(Exception):
    """SO 分析异常基类"""
    pass


class SOFileNotFoundError(SOAnalyzerError):
    """SO 文件不存在"""
    pass


class SOToolNotFoundError(SOAnalyzerError):
    """必需的系统工具未找到"""
    pass


class SOAnalysisError(SOAnalyzerError):
    """分析过程中的通用错误"""
    pass


class SOAnalyzer:
    """
    SO 文件逆向分析器

    提供对 Android .so 文件的综合逆向分析能力，包括：
    - 文件基本信息 (架构、类型、链接方式等)
    - Il2CPP 符号解析 (Unity 游戏常用)
    - Unity 引擎自动识别
    - 字符串提取
    - 函数签名识别

    所有方法返回结构化 dict，可直接序列化为 JSON。
    """

    TOOL_CANDIDATES = {
        "file": ["/usr/bin/file", "/bin/file", "file"],
        "strings": ["/usr/bin/strings", "/bin/strings", "strings"],
        "objdump": ["/usr/bin/objdump", "/bin/objdump", "objdump"],
        "readelf": ["/usr/bin/readelf", "/bin/readelf", "readelf"],
        "nm": ["/usr/bin/nm", "/bin/nm", "nm"],
    }

    UNITY_SIGNATURES = [
        "il2cpp", "Il2Cpp", "IL2CPP",
        "globalmetadata", "UnityPlayer", "libunity",
        "UnityVersion", "UnityEditor",
        "MonoBehaviour", "Transform", "GameObject", "Camera", "Light",
        "Animator", "Canvas", "Text", "Image", "Button", "Shader",
        "Material", "AssetBundle", "Scene", "Network", "WWW",
        "Unity__", "il2cpp_",
    ]

    IL2CPP_SYMBOL_PATTERNS = [
        r'^(il2cpp_|Unity__)',
        r'il2cpp_(?:method|object|field|property|type|class|namespace|assembly|image|runtime|gc|vm|thread|time|io|signal)',
        r'Unity__',
    ]

    def __init__(self):
        self._tool_paths: Dict[str, str] = {}
        self._detect_tools()

    def _detect_tools(self) -> None:
        for tool_name, candidates in self.TOOL_CANDIDATES.items():
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
                    except (subprocess.TimeoutExpired, OSError):
                        continue
                else:
                    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                        self._tool_paths[tool_name] = candidate
                        break

    def _run_tool(self, tool_name: str, args: List[str], timeout: int = 30) -> str:
        tool_path = self._tool_paths.get(tool_name)
        if not tool_path:
            raise SOToolNotFoundError(
                f"系统工具 '{tool_name}' 未找到。请确保已安装。"
                f"Linux: apt install {tool_name} 或 yum install {tool_name}"
            )
        try:
            result = subprocess.run(
                [tool_path] + args, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            raise SOAnalysisError(f"工具 '{tool_name}' 执行超时 ({timeout}s)")
        except OSError as e:
            raise SOAnalysisError(f"运行工具 '{tool_name}' 失败: {e}")

    def _validate_so_file(self, so_path: str) -> str:
        if not so_path:
            raise SOFileNotFoundError("SO 文件路径不能为空")
        abs_path = os.path.abspath(so_path)
        if not os.path.exists(abs_path):
            raise SOFileNotFoundError(f"SO 文件不存在: {abs_path}")
        if not os.path.isfile(abs_path):
            raise SOAnalysisError(f"路径不是文件: {abs_path}")
        if not os.access(abs_path, os.R_OK):
            raise SOAnalysisError(f"SO 文件不可读: {abs_path}")
        try:
            with open(abs_path, "rb") as f:
                magic = f.read(4)
            if magic != b'\x7fELF':
                raise SOAnalysisError(
                    f"文件不是有效的 ELF 格式: {abs_path} (magic: {magic.hex()})"
                )
        except IOError as e:
            raise SOAnalysisError(f"读取文件失败: {e}")
        return abs_path

    def _get_file_info(self, so_path: str) -> Dict[str, Any]:
        try:
            output = self._run_tool("file", ["-b", so_path])
            info = {"raw": output.strip()}
            arch_patterns = {
                "ARM (32-bit)": r'ARM (?:EABI)?(?:\s+\d+)?-bit',
                "ARM64": r'aarch64|ARM (?:EABI)?\s+64-bit',
                "x86": r'i[3-6]86|x86',
                "x86_64": r'x86-64|amd64',
                "MIPS": r'MIPS',
                "RISC-V": r'RISC-V|riscv',
            }
            for label, pattern in arch_patterns.items():
                if re.search(pattern, output, re.IGNORECASE):
                    info["architecture"] = label
                    break
            if "shared library" in output.lower():
                info["type"] = "shared library"
            elif "executable" in output.lower():
                info["type"] = "executable"
            elif "relocatable" in output.lower():
                info["type"] = "relocatable"
            else:
                info["type"] = "unknown"
            if "not stripped" in output.lower():
                info["stripped"] = False
            elif "stripped" in output.lower():
                info["stripped"] = True
            else:
                info["stripped"] = None
            return info
        except (SOToolNotFoundError, SOAnalysisError) as e:
            return {"error": str(e), "architecture": "unknown", "type": "unknown"}

    def _get_elf_info(self, so_path: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        try:
            output = self._run_tool("readelf", ["-h", so_path])
            for key, pattern in [
                ("elf_class", r'Class:\s+(\S+)'),
                ("endian", r'Data:\s+(\S+)'),
                ("os_abi", r'OS/ABI:\s+(\S+)'),
                ("machine", r'Machine:\s+(\S+)'),
                ("entry_point", r'Entry point:\s+(0x\S+)'),
            ]:
                match = re.search(pattern, output)
                if match:
                    info[key] = match.group(1)
        except (SOToolNotFoundError, SOAnalysisError) as e:
            info["error"] = str(e)
        try:
            output = self._run_tool("readelf", ["-S", so_path])
            sections = []
            for line in output.splitlines():
                match = re.match(
                    r'\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)',
                    line
                )
                if match:
                    sections.append({
                        "index": int(match.group(1)),
                        "name": match.group(2),
                        "type": match.group(3),
                        "address": match.group(4),
                        "offset": match.group(5),
                        "size": match.group(6),
                    })
            if sections:
                info["sections"] = sections
        except (SOToolNotFoundError, SOAnalysisError):
            pass
        return info

    def _get_symbol_info(self, so_path: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {"total_symbols": 0, "functions": [], "symbols_by_type": {}}
        try:
            output = self._run_tool("nm", ["-D", so_path])
            symbols = []
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    symbols.append({"address": parts[0], "type": parts[1], "name": parts[2]})
                elif len(parts) == 2:
                    symbols.append({"address": parts[0], "type": "?", "name": parts[1]})
            info["total_symbols"] = len(symbols)
            info["symbols"] = symbols[:500]
            type_counts: Dict[str, int] = {}
            for sym in symbols:
                t = sym["type"]
                type_counts[t] = type_counts.get(t, 0) + 1
            info["symbols_by_type"] = type_counts
        except (SOToolNotFoundError, SOAnalysisError) as e:
            info["nm_error"] = str(e)
        try:
            output = self._run_tool("objdump", ["-t", so_path])
            functions = []
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 6 and ('F' in parts[1] or 'f' in parts[1]):
                    name = parts[-1]
                    section = next((p for p in parts if p.startswith('.')), "")
                    functions.append({"address": parts[0], "name": name, "section": section})
            if functions:
                info["functions"] = functions[:500]
        except (SOToolNotFoundError, SOAnalysisError) as e:
            info["objdump_error"] = str(e)
        return info

    def _extract_strings(self, so_path: str, min_length: int = 5) -> Dict[str, Any]:
        try:
            output = self._run_tool("strings", ["-n", str(min_length), so_path])
            strings = [line.strip() for line in output.splitlines() if line.strip()]
            categories = {"url": [], "path": [], "il2cpp": [], "unity": [], "error": [], "other": []}
            for s in strings:
                lower_s = s.lower()
                if re.match(r'^https?://', lower_s) or re.match(r'^ftp://', lower_s):
                    categories["url"].append(s)
                elif lower_s.startswith('/') or lower_s.startswith('./') or '\\' in s:
                    categories["path"].append(s)
                elif 'il2cpp' in lower_s:
                    categories["il2cpp"].append(s)
                elif 'unity' in lower_s:
                    categories["unity"].append(s)
                elif any(kw in lower_s for kw in ['error', 'fail', 'exception', 'warn', 'crash']):
                    categories["error"].append(s)
                else:
                    categories["other"].append(s)
            return {
                "total_strings": len(strings),
                "min_length": min_length,
                "categories": categories,
                "sample_strings": strings[:200],
            }
        except (SOToolNotFoundError, SOAnalysisError) as e:
            return {"error": str(e), "total_strings": 0}

    def _detect_unity_signatures(self, strings_result: Dict[str, Any]) -> Dict[str, Any]:
        all_strings = []
        if "categories" in strings_result:
            for cat_strings in strings_result["categories"].values():
                all_strings.extend(cat_strings)
        all_strings.extend(strings_result.get("sample_strings", []))
        all_lower = [s.lower() for s in all_strings]
        detected_signatures = [sig for sig in self.UNITY_SIGNATURES if sig.lower() in all_lower]
        il2cpp_markers = [s for s in all_strings if 'il2cpp' in s.lower()]
        version_match = None
        for s in all_strings:
            match = re.search(r'Unity(?:Version)?\s*[:\s]*(\d+\.\d+\.\d+[a-z0-9]*)', s, re.IGNORECASE)
            if match:
                version_match = match.group(1)
                break
        is_unity = len(detected_signatures) > 0 or len(il2cpp_markers) > 0
        return {
            "is_unity": is_unity,
            "unity_signatures_found": detected_signatures,
            "il2cpp_markers": il2cpp_markers[:50],
            "unity_version": version_match,
            "confidence": "high" if len(detected_signatures) > 3 else "medium" if is_unity else "low",
        }

    def _extract_il2cpp_symbols_from_strings(self, strings_result: Dict[str, Any]) -> List[str]:
        all_strings = []
        if "categories" in strings_result:
            all_strings.extend(strings_result["categories"].get("il2cpp", []))
        all_strings.extend(strings_result.get("sample_strings", []))
        il2cpp_symbols = []
        seen = set()
        for s in all_strings:
            for pattern in self.IL2CPP_SYMBOL_PATTERNS:
                if re.search(pattern, s, re.IGNORECASE):
                    if s not in seen:
                        il2cpp_symbols.append(s)
                        seen.add(s)
                    break
        return il2cpp_symbols

    def _extract_il2cpp_symbols_from_nm(self, so_path: str) -> List[Dict[str, str]]:
        symbols = []
        try:
            output = self._run_tool("nm", ["-D", so_path])
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                name = parts[-1]
                is_il2cpp = False
                for pattern in self.IL2CPP_SYMBOL_PATTERNS:
                    if re.search(pattern, name):
                        is_il2cpp = True
                        break
                if is_il2cpp:
                    sym = {"name": name}
                    if len(parts) >= 3:
                        sym["address"] = parts[0]
                        sym["type"] = parts[1]
                    symbols.append(sym)
        except (SOToolNotFoundError, SOAnalysisError):
            pass
        return symbols

    def extract_strings(self, so_path: str, min_length: int = 5) -> Dict[str, Any]:
        try:
            abs_path = self._validate_so_file(so_path)
            strings_data = self._extract_strings(abs_path, min_length)
            return {"success": True, "so_file": abs_path, "strings": strings_data}
        except SOAnalyzerError as e:
            return {"success": False, "so_file": so_path, "error": str(e)}

    def detect_unity(self, so_path: str) -> Dict[str, Any]:
        try:
            abs_path = self._validate_so_file(so_path)
            strings_data = self._extract_strings(abs_path, min_length=4)
            unity_data = self._detect_unity_signatures(strings_data)
            il2cpp_nm = self._extract_il2cpp_symbols_from_nm(abs_path)
            unity_data["il2cpp_symbols_from_nm"] = il2cpp_nm[:100]
            unity_data["il2cpp_symbols_count"] = len(il2cpp_nm)
            return {"success": True, "so_file": abs_path, "unity_detection": unity_data}
        except SOAnalyzerError as e:
            return {"success": False, "so_file": so_path, "error": str(e)}

    def extract_il2cpp_symbols(self, so_path: str) -> Dict[str, Any]:
        try:
            abs_path = self._validate_so_file(so_path)
            strings_data = self._extract_strings(abs_path, min_length=4)
            il2cpp_from_strings = self._extract_il2cpp_symbols_from_strings(strings_data)
            il2cpp_from_nm = self._extract_il2cpp_symbols_from_nm(abs_path)
            all_names = set()
            for sym in il2cpp_from_nm:
                all_names.add(sym["name"])
            all_names.update(il2cpp_from_strings)
            result = {
                "total_count": len(all_names),
                "from_strings": il2cpp_from_strings[:200],
                "from_symbol_table": il2cpp_from_nm[:200],
                "sample_names": sorted(list(all_names))[:100],
            }
            return {"success": True, "so_file": abs_path, "il2cpp_symbols": result}
        except SOAnalyzerError as e:
            return {"success": False, "so_file": so_path, "error": str(e)}

    def analyze(self, so_path: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"success": False, "so_file": so_path}
        try:
            abs_path = self._validate_so_file(so_path)
            result["so_file"] = abs_path
            result["file_info"] = self._get_file_info(abs_path)
            result["elf_info"] = self._get_elf_info(abs_path)
            result["symbol_info"] = self._get_symbol_info(abs_path)
            strings_data = self._extract_strings(abs_path, min_length=5)
            result["strings"] = strings_data
            unity_data = self._detect_unity_signatures(strings_data)
            il2cpp_nm = self._extract_il2cpp_symbols_from_nm(abs_path)
            unity_data["il2cpp_symbols_from_nm"] = il2cpp_nm[:100]
            unity_data["il2cpp_symbols_count"] = len(il2cpp_nm)
            result["unity_detection"] = unity_data
            il2cpp_from_strings = self._extract_il2cpp_symbols_from_strings(strings_data)
            all_names = set()
            for sym in il2cpp_nm:
                all_names.add(sym["name"])
            all_names.update(il2cpp_from_strings)
            result["il2cpp_symbols"] = {
                "total_count": len(all_names),
                "from_strings": il2cpp_from_strings[:200],
                "from_symbol_table": il2cpp_nm[:200],
                "sample_names": sorted(list(all_names))[:100],
            }
            result["success"] = True
        except SOFileNotFoundError as e:
            result["error"] = str(e)
        except SOAnalysisError as e:
            result["error"] = str(e)
        except SOToolNotFoundError as e:
            result["error"] = str(e)
        except Exception as e:
            result["error"] = f"未预期的错误: {e}"
        return result

    def analyze_batch(self, so_paths: List[str]) -> List[Dict[str, Any]]:
        return [self.analyze(so_path) for so_path in so_paths]

    def get_tool_status(self) -> Dict[str, Any]:
        return {
            "tools": self._tool_paths.copy(),
            "all_available": all(v is not None for v in self._tool_paths.values()),
        }

    def export_json(self, result: Dict[str, Any], output_path: str, indent: int = 2) -> None:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=indent)
        except IOError as e:
            raise SOAnalysisError(f"导出 JSON 失败: {e}")


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="so_analysis",
        description="SO (Shared Object) 逆向分析工具 - 分析 Android native 库",
    )
    subparsers = parser.add_subparsers(dest="command", help="子命令")

    analyze_parser = subparsers.add_parser("analyze", help="全面分析 SO 文件")
    analyze_parser.add_argument("so_path", help="SO 文件路径")
    analyze_parser.add_argument("--json", action="store_true", help="输出 JSON 格式")
    analyze_parser.add_argument("--output", "-o", help="输出到文件 (JSON)")

    unity_parser = subparsers.add_parser("detect-unity", help="检测 Unity 引擎")
    unity_parser.add_argument("so_path", help="SO 文件路径")
    unity_parser.add_argument("--json", action="store_true", help="输出 JSON 格式")

    il2cpp_parser = subparsers.add_parser("extract-il2cpp", help="提取 Il2CPP 符号")
    il2cpp_parser.add_argument("so_path", help="SO 文件路径")
    il2cpp_parser.add_argument("--json", action="store_true", help="输出 JSON 格式")

    strings_parser = subparsers.add_parser("extract-strings", help="提取字符串")
    strings_parser.add_argument("so_path", help="SO 文件路径")
    strings_parser.add_argument("--min-length", type=int, default=5, help="最小字符串长度")
    strings_parser.add_argument("--json", action="store_true", help="输出 JSON 格式")

    batch_parser = subparsers.add_parser("batch", help="批量分析")
    batch_parser.add_argument("so_paths", nargs="+", help="SO 文件路径列表")
    batch_parser.add_argument("--json", action="store_true", help="输出 JSON 格式")

    subparsers.add_parser("tools", help="检查系统工具可用性")

    parser.add_argument("--verbose", "-v", action="store_true", help="详细输出")
    parser.add_argument("--quiet", "-q", action="store_true", help="静默模式")

    args = parser.parse_args()
    analyzer = SOAnalyzer()

    try:
        if args.command == "analyze":
            result = analyzer.analyze(args.so_path)
            if args.output:
                analyzer.export_json(result, args.output)
                if not args.quiet:
                    print(f"✓ 结果已导出到: {args.output}")
            elif args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                if result.get("success"):
                    print(f"文件: {result.get('so_file', 'N/A')}")
                    print(f"成功: 是")
                    print(f"文件信息: {json.dumps(result.get('file_info', {}), ensure_ascii=False)}")
                    print(f"符号数: {result.get('symbol_info', {}).get('total_symbols', 0)}")
                    print(f"字符串数: {result.get('strings', {}).get('total_strings', 0)}")
                    ud = result.get('unity_detection', {})
                    print(f"Unity: {'是' if ud.get('is_unity') else '否'}")
                    print(f"Il2CPP符号数: {result.get('il2cpp_symbols', {}).get('total_count', 0)}")
                else:
                    print(f"✗ 分析失败: {result.get('error', '未知错误')}")

        elif args.command == "detect-unity":
            result = analyzer.detect_unity(args.so_path)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                if result.get("success"):
                    ud = result.get("unity_detection", {})
                    print(f"Unity: {'是' if ud.get('is_unity') else '否'}")
                    if ud.get("unity_version"):
                        print(f"版本: {ud['unity_version']}")
                    print(f"置信度: {ud.get('confidence', 'unknown')}")
                else:
                    print(f"✗ 失败: {result.get('error', '未知错误')}")

        elif args.command == "extract-il2cpp":
            result = analyzer.extract_il2cpp_symbols(args.so_path)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                if result.get("success"):
                    isym = result.get("il2cpp_symbols", {})
                    print(f"Il2CPP符号总数: {isym.get('total_count', 0)}")
                    for name in isym.get('sample_names', [])[:20]:
                        print(f"  - {name}")
                else:
                    print(f"✗ 失败: {result.get('error', '未知错误')}")

        elif args.command == "extract-strings":
            result = analyzer.extract_strings(args.so_path, args.min_length)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                if result.get("success"):
                    s = result.get("strings", {})
                    print(f"字符串总数: {s.get('total_strings', 0)}")
                else:
                    print(f"✗ 失败: {result.get('error', '未知错误')}")

        elif args.command == "batch":
            results = analyzer.analyze_batch(args.so_paths)
            if args.json:
                print(json.dumps(results, ensure_ascii=False, indent=2))
            else:
                for i, r in enumerate(results):
                    print(f"[{i+1}/{len(results)}] {r.get('so_file', 'N/A')}")
                    if r.get("success"):
                        print(f"  架构: {r.get('file_info', {}).get('architecture', 'unknown')}")
                        print(f"  Unity: {'是' if r.get('unity_detection', {}).get('is_unity') else '否'}")
                    else:
                        print(f"  ✗ {r.get('error', '未知错误')}")

        elif args.command == "tools":
            status = analyzer.get_tool_status()
            for tool, path in sorted(status["tools"].items()):
                icon = "✓" if path else "✗"
                print(f"  {icon} {tool}: {path or '未找到'}")

        else:
            parser.print_help()

    except KeyboardInterrupt:
        print("\n✗ 用户中断")
        sys.exit(130)
    except Exception as e:
        if args.verbose:
            import traceback
            traceback.print_exc()
        print(f"✗ 错误: {e}")
        sys.exit(1)
