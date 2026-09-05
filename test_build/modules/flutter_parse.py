#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flutter 解析模块
==============
功能：检测 APK 是否使用 Flutter 框架，提取 Dart 字符串和方法名
"""

import os
import re
import json
import subprocess
import zipfile
from typing import Dict, List, Any


class FlutterParserError(Exception):
    """Flutter 解析异常"""
    pass


class FlutterParser:
    """Flutter 解析器"""

    # Flutter 特征字符串
    FLUTTER_SIGNATURES = [
        "flutter",
        "dart:ui",
        "dart.isolate",
        "dart.async",
        "Package flutter",
        "io.flutter",
        "flutter.engine",
        "FlutterEngine",
        "FlutterJNI",
        "FlutterMethodChannel",
        "FlutterEventChannel",
        "FlutterBasicMessageChannel",
    ]

    def __init__(self):
        pass

    def detect_flutter(self, apk_path: str) -> Dict[str, Any]:
        """检测 APK 是否使用 Flutter 框架"""
        if not os.path.exists(apk_path):
            raise FlutterParserError(f"文件不存在: {apk_path}")

        result = {
            "is_flutter": False,
            "confidence": "low",
            "indicators": [],
            "flutter_version": None,
            "dart_version": None,
        }

        try:
            with zipfile.ZipFile(apk_path) as zf:
                entries = zf.namelist()

                # 检查 libflutter.so
                if any("libflutter.so" in e for e in entries):
                    result["is_flutter"] = True
                    result["indicators"].append("包含 libflutter.so")

                # 检查 Dart 快照
                if any("app.so" in e and "flutter" in e.lower() for e in entries):
                    result["is_flutter"] = True
                    result["indicators"].append("包含 Flutter Dart 快照")

                # 检查 Flutter 资源
                if any("flutter/" in e for e in entries):
                    result["is_flutter"] = True
                    result["indicators"].append("包含 Flutter 资源目录")

                # 提取字符串检查
                strings = self._extract_strings(apk_path)
                for sig in self.FLUTTER_SIGNATURES:
                    if sig.lower() in strings.lower():
                        result["is_flutter"] = True
                        result["indicators"].append(f"包含特征字符串: {sig}")

                # 检查版本信息
                version_match = re.search(r'Flutter\s*([\d.]+)', strings, re.IGNORECASE)
                if version_match:
                    result["flutter_version"] = version_match.group(1)

                dart_match = re.search(r'Dart\s*([\d.]+)', strings, re.IGNORECASE)
                if dart_match:
                    result["dart_version"] = dart_match.group(1)

                if result["indicators"]:
                    result["confidence"] = "high" if len(result["indicators"]) > 2 else "medium"

        except zipfile.BadZipFile:
            raise FlutterParserError(f"无效的 APK 文件: {apk_path}")

        return result

    def extract_dart_strings(self, apk_path: str) -> Dict[str, Any]:
        """提取 Dart 字符串"""
        if not os.path.exists(apk_path):
            raise FlutterParserError(f"文件不存在: {apk_path}")

        try:
            strings = self._extract_strings(apk_path)
            dart_strings = [
                line for line in strings.splitlines()
                if any(kw in line.lower() for kw in ['dart', 'flutter'])
            ]

            return {
                "count": len(dart_strings),
                "strings": dart_strings[:200],
            }
        except Exception as e:
            return {"count": 0, "strings": [], "error": str(e)}

    def extract_dart_methods(self, apk_path: str) -> Dict[str, Any]:
        """提取 Dart 方法名"""
        if not os.path.exists(apk_path):
            raise FlutterParserError(f"文件不存在: {apk_path}")

        try:
            strings = self._extract_strings(apk_path)
            # Dart 方法名通常包含 :: 或 . 分隔符
            method_patterns = re.findall(
                r'(?:[a-zA-Z_][a-zA-Z0-9_]*::[a-zA-Z_][a-zA-Z0-9_]*|[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*)',
                strings
            )
            # 过滤常见非方法名
            methods = [m for m in method_patterns if not m.startswith(('http', 'www', 'android', 'com.android'))]

            return {
                "count": len(methods),
                "methods": list(set(methods))[:100],
            }
        except Exception as e:
            return {"count": 0, "methods": [], "error": str(e)}

    def _extract_strings(self, apk_path: str) -> str:
        """提取 APK 中的字符串"""
        try:
            result = subprocess.run(
                ["strings", apk_path],
                capture_output=True, text=True, timeout=60
            )
            return result.stdout
        except Exception:
            return ""

    def analyze(self, apk_path: str) -> Dict[str, Any]:
        """综合 Flutter 分析"""
        result = {"apk": apk_path}
        try:
            result["detect"] = self.detect_flutter(apk_path)
            result["dart_strings"] = self.extract_dart_strings(apk_path)
            result["dart_methods"] = self.extract_dart_methods(apk_path)
        except Exception as e:
            result["error"] = str(e)
        return result


def main() -> int:
    """命令行入口"""
    import argparse
    parser = argparse.ArgumentParser(description="Flutter 解析工具")
    parser.add_argument("--apk", required=True, help="APK 文件路径")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    args = parser.parse_args()

    parser_tool = FlutterParser()
    result = parser_tool.analyze(args.apk)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        detect = result.get("detect", {})
        print(f"🎮 Flutter 检测: {'是' if detect.get('is_flutter') else '否'}")
        print(f"  置信度: {detect.get('confidence', 'N/A')}")
        if detect.get("flutter_version"):
            print(f"  Flutter 版本: {detect['flutter_version']}")
        if detect.get("dart_version"):
            print(f"  Dart 版本: {detect['dart_version']}")
        print(f"  Dart 字符串: {result.get('dart_strings', {}).get('count', 0)}")
        print(f"  Dart 方法: {result.get('dart_methods', {}).get('count', 0)}")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())