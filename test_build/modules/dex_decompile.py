#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DEX反编译模块 - Android逆向工具箱核心模块

本模块提供DEX文件提取、Smali反编译、字符串搜索和代码检索功能。
基于Python标准库 + subprocess调用系统已有工具（baksmali、apktool等），
输出结构化JSON结果，便于脚本化调用和CI集成。

依赖：
    - baksmali (系统工具，用于DEX→Smali反编译)
    - apktool (系统工具，用于APK资源解包)
    - java (运行时，baksmali依赖)

作者: Developer Tooling Engineer
版本: 1.0.0
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# 工具函数
# ============================================================

def _check_tool_available(tool_name: str) -> bool:
    """检查系统是否安装了指定工具。"""
    return shutil.which(tool_name) is not None


def _run_subprocess(
    cmd: List[str],
    cwd: Optional[str] = None,
    timeout: int = 300,
    capture_output: bool = True
) -> Tuple[int, str, str]:
    """
    执行子进程并返回结果。

    Args:
        cmd: 命令行参数列表
        cwd: 工作目录
        timeout: 超时秒数
        capture_output: 是否捕获stdout/stderr

    Returns:
        (exit_code, stdout, stderr) 元组

    Raises:
        FileNotFoundError: 命令不存在
        subprocess.TimeoutExpired: 命令超时
    """
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            check=False
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        raise FileNotFoundError(
            f"命令未找到: {cmd[0]}\n"
            f"请确保已安装该工具，或检查PATH环境变量。"
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError(
            f"命令执行超时 ({timeout}s): {' '.join(cmd)}\n"
            f"请尝试增加超时时间或检查输入文件是否有效。"
        )


def _find_dex_files(directory: str) -> List[str]:
    """
    在目录中递归查找所有 .dex 文件。

    Args:
        directory: 搜索目录

    Returns:
        DEX文件路径列表
    """
    dex_files = []
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith('.dex'):
                dex_files.append(os.path.join(root, f))
    return dex_files


def _extract_dex_from_apk(apk_path: str, output_dir: str) -> List[str]:
    """
    从APK文件中提取所有DEX文件。

    APK是一个ZIP压缩包，DEX文件通常位于根目录或 lib/ 子目录下。

    Args:
        apk_path: APK文件路径
        output_dir: 解压输出目录

    Returns:
        提取的DEX文件路径列表

    Raises:
        FileNotFoundError: APK文件不存在
        zipfile.BadZipFile: 不是有效的APK/ZIP文件
    """
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(
            f"APK文件不存在: {apk_path}\n"
            f"请检查文件路径是否正确，或使用绝对路径。"
        )

    if not zipfile.is_zipfile(apk_path):
        raise ValueError(
            f"不是有效的APK/ZIP文件: {apk_path}\n"
            f"请确认文件扩展名为 .apk 且文件未损坏。"
        )

    extracted_dex = []
    os.makedirs(output_dir, exist_ok=True)

    with zipfile.ZipFile(apk_path, 'r') as zf:
        for info in zf.infolist():
            # 提取 .dex 文件（包括 classes.dex, classes2.dex 等）
            if info.filename.endswith('.dex'):
                # 防止路径遍历攻击
                safe_name = os.path.basename(info.filename)
                if safe_name != info.filename:
                    continue
                target_path = os.path.join(output_dir, safe_name)
                with zf.open(info) as src, open(target_path, 'wb') as dst:
                    shutil.copyfileobj(src, dst)
                extracted_dex.append(target_path)

    return extracted_dex


# ============================================================
# DEX反编译器主类
# ============================================================

class DexDecompiler:
    """
    DEX反编译器 - 将Android DEX字节码反编译为Smali源码，
    并提供字符串和代码检索能力。

    核心能力：
        - APK中DEX文件的自动提取
        - DEX→Smali反编译（基于baksmali）
        - 字符串常量搜索
        - Smali代码模式检索

    输出格式：结构化JSON，可直接被脚本解析。

    示例：
        >>> compiler = DexDecompiler()
        >>> result = compiler.decompile('/path/to/app.apk')
        >>> print(json.dumps(result, indent=2))
    """

    def __init__(self, baksmali_path: Optional[str] = None):
        """
        初始化反编译器。

        Args:
            baksmali_path: baksmali可执行文件路径。为None时自动从PATH查找。

        Raises:
            RuntimeError: 未找到baksmali工具
        """
        if baksmali_path is None:
            baksmali_path = shutil.which('baksmali')
            if baksmali_path is None:
                raise RuntimeError(
                    "未找到 baksmali 工具。\n"
                    "请安装 baksmali：\n"
                    "  方式1: apt-get install baksmali (Debian/Ubuntu)\n"
                    "  方式2: 从 https://github.com/JakeWharton/Baksmali 下载 jar 并配置路径\n"
                    "  或者在实例化时传入 baksmali_path 参数指定完整路径。"
                )

        self.baksmali_path = baksmali_path
        self._java_available = _check_tool_available('java')

        if not self._java_available:
            raise RuntimeError(
                "未找到 Java 运行时环境。\n"
                "baksmali 依赖 Java 运行，请安装 JRE/JDK 后重试。"
            )

    # ------------------------------------------------------------------
    # 公开API
    # ------------------------------------------------------------------

    def decompile(self, apk_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        反编译APK中的DEX文件为Smali源码。

        执行流程：
            1. 从APK中提取所有 .dex 文件
            2. 使用 baksmali 将每个DEX反编译为Smali
            3. 返回结构化结果，包含每个DEX的详细信息

        Args:
            apk_path: APK文件路径
            output_dir: Smali输出目录（默认为临时目录）

        Returns:
            结构化结果字典，格式如下：
            {
                "apk": "/path/to/app.apk",
                "dex_count": 2,
                "dex_files": [
                    {
                        "file": "classes.dex",
                        "smali_dir": "/tmp/xxx/out/smali",
                        "class_count": 150,
                        "classes": ["Lcom/example/Foo;", ...]
                    }
                ],
                "output_root": "/tmp/xxx"
            }

        Raises:
            FileNotFoundError: APK文件不存在
            RuntimeError: 反编译过程失败
        """
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(
                f"APK文件不存在: {apk_path}\n"
                f"请检查文件路径是否正确。"
            )

        # 创建工作目录
        if output_dir is None:
            work_dir = tempfile.mkdtemp(prefix='artoolkit_dex_')
        else:
            work_dir = output_dir
            os.makedirs(work_dir, exist_ok=True)

        dex_dir = os.path.join(work_dir, 'dex')
        smali_out = os.path.join(work_dir, 'smali')
        os.makedirs(dex_dir, exist_ok=True)
        os.makedirs(smali_out, exist_ok=True)

        try:
            # 步骤1: 从APK提取DEX文件
            dex_files = _extract_dex_from_apk(apk_path, dex_dir)

            if not dex_files:
                raise RuntimeError(
                    f"APK中未找到DEX文件: {apk_path}\n"
                    f"请确认该APK已使用标准工具打包，且包含 classes.dex 等文件。"
                )

            # 步骤2: 反编译每个DEX
            dex_results = []
            total_classes = 0

            for dex_path in dex_files:
                dex_name = os.path.basename(dex_path)
                # 为每个DEX创建独立的输出子目录（baksmali不支持多DEX同目录）
                dex_smali_dir = os.path.join(smali_out, dex_name.replace('.dex', ''))
                os.makedirs(dex_smali_dir, exist_ok=True)

                # 调用 baksmali d <dex> -o <output>
                cmd = [
                    'java', '-jar', self.baksmali_path,
                    'd', dex_path,
                    '-o', dex_smali_dir
                ]
                # 如果 baksmali 是直接可执行文件（非jar），则直接调用
                if self.baksmali_path.endswith('.jar'):
                    cmd = ['java', '-jar', self.baksmali_path, 'd', dex_path, '-o', dex_smali_dir]
                else:
                    cmd = [self.baksmali_path, 'd', dex_path, '-o', dex_smali_dir]

                exit_code, stdout, stderr = _run_subprocess(cmd)

                if exit_code != 0:
                    raise RuntimeError(
                        f"baksmali 反编译失败 (exit={exit_code})\n"
                        f"DEX文件: {dex_path}\n"
                        f"错误详情: {stderr.strip()}\n"
                        f"请检查DEX文件是否有效，或尝试更新baksmali版本。"
                    )

                # 统计生成的类
                classes = self._list_smali_classes(dex_smali_dir)
                total_classes += len(classes)

                dex_results.append({
                    "file": dex_name,
                    "smali_dir": dex_smali_dir,
                    "class_count": len(classes),
                    "classes": classes[:50]  # 限制返回数量，避免输出过大
                })

            return {
                "apk": apk_path,
                "dex_count": len(dex_files),
                "dex_files": dex_results,
                "total_classes": total_classes,
                "output_root": work_dir
            }

        except Exception as e:
            # 清理临时目录
            if output_dir is None and os.path.exists(work_dir):
                shutil.rmtree(work_dir, ignore_errors=True)
            raise

    def search_strings(self, apk_path: str, pattern: str) -> Dict[str, Any]:
        """
        在APK的DEX中搜索匹配的字符串常量。

        使用 baksmali 的字符串提取功能，然后进行正则匹配。

        Args:
            apk_path: APK文件路径
            pattern: 正则表达式模式

        Returns:
            结构化结果字典：
            {
                "apk": "...",
                "pattern": "...",
                "matches": [
                    {
                        "value": "匹配的字符串",
                        "dex": "classes.dex",
                        "file": "/path/to/smali/file.smali",
                        "line": 42
                    }
                ],
                "total_matches": N
            }

        Raises:
            FileNotFoundError: APK文件不存在
            re.error: 正则表达式语法错误
        """
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(
                f"APK文件不存在: {apk_path}\n"
                f"请检查文件路径是否正确。"
            )

        # 先反编译获取Smali源码
        decompile_result = self.decompile(apk_path)
        smali_root = decompile_result['output_root']

        try:
            # 编译正则表达式，提前报错
            regex = re.compile(pattern)

            matches = []
            # 遍历所有Smali目录
            for dex_info in decompile_result['dex_files']:
                smali_dir = dex_info['smali_dir']
                dex_name = dex_info['file']

                for root, _, files in os.walk(smali_dir):
                    for f in files:
                        if not f.endswith('.smali'):
                            continue
                        file_path = os.path.join(root, f)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
                                for line_num, line in enumerate(fh, 1):
                                    # 查找字符串常量: .string "..." 或 .string p"..."
                                    string_match = re.search(r'\.string\s+(?:p?\d+\s+)?(".*?"|\'.*?\')', line)
                                    if string_match:
                                        raw_value = string_match.group(1)
                                        # 去掉引号
                                        value = raw_value[1:-1]
                                        if regex.search(value):
                                            matches.append({
                                                "value": value,
                                                "dex": dex_name,
                                                "file": file_path,
                                                "line": line_num
                                            })
                        except Exception:
                            # 跳过无法读取的文件
                            continue

            return {
                "apk": apk_path,
                "pattern": pattern,
                "matches": matches,
                "total_matches": len(matches)
            }
        finally:
            # 清理临时目录（如果是由我们创建的）
            if 'artoolkit_dex_' in smali_root:
                shutil.rmtree(smali_root, ignore_errors=True)

    def search_code(self, apk_path: str, pattern: str) -> Dict[str, Any]:
        """
        在APK的Smali代码中搜索匹配的模式。

        搜索Smali指令、方法调用、类引用等代码模式。

        Args:
            apk_path: APK文件路径
            pattern: 正则表达式模式

        Returns:
            结构化结果字典：
            {
                "apk": "...",
                "pattern": "...",
                "matches": [
                    {
                        "dex": "classes.dex",
                        "file": "/path/to/smali/file.smali",
                        "line": 42,
                        "content": "匹配行的代码片段"
                    }
                ],
                "total_matches": N
            }

        Raises:
            FileNotFoundError: APK文件不存在
            re.error: 正则表达式语法错误
        """
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(
                f"APK文件不存在: {apk_path}\n"
                f"请检查文件路径是否正确。"
            )

        # 先反编译获取Smali源码
        decompile_result = self.decompile(apk_path)
        smali_root = decompile_result['output_root']

        try:
            regex = re.compile(pattern)
            matches = []

            for dex_info in decompile_result['dex_files']:
                smali_dir = dex_info['smali_dir']
                dex_name = dex_info['file']

                for root, _, files in os.walk(smali_dir):
                    for f in files:
                        if not f.endswith('.smali'):
                            continue
                        file_path = os.path.join(root, f)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
                                for line_num, line in enumerate(fh, 1):
                                    if regex.search(line):
                                        matches.append({
                                            "dex": dex_name,
                                            "file": file_path,
                                            "line": line_num,
                                            "content": line.strip()
                                        })
                        except Exception:
                            continue

            return {
                "apk": apk_path,
                "pattern": pattern,
                "matches": matches,
                "total_matches": len(matches)
            }
        finally:
            if 'artoolkit_dex_' in smali_root:
                shutil.rmtree(smali_root, ignore_errors=True)

    # ------------------------------------------------------------------
    # 内部辅助方法
    # ------------------------------------------------------------------

    @staticmethod
    def _list_smali_classes(smali_dir: str) -> List[str]:
        """
        列出Smali目录中的所有类（以 .smali 文件为准）。

        Smali类文件命名格式: ClassName.smali
        类名格式: Lpackage/ClassName;

        Args:
            smali_dir: Smali源码目录

        Returns:
            类名列表
        """
        classes = []
        if not os.path.isdir(smali_dir):
            return classes

        for root, _, files in os.walk(smali_dir):
            for f in files:
                if f.endswith('.smali'):
                    # 将文件名转换为Smali类名格式
                    class_name = f[:-6]  # 去掉 .smali 后缀
                    # 转换为 Lpackage/ClassName; 格式
                    if '/' in class_name:
                        smali_class = 'L' + class_name + ';'
                    else:
                        smali_class = 'L' + class_name + ';'
                    classes.append(smali_class)

        return sorted(classes)


# ============================================================
# CLI入口（当脚本被直接执行时）
# ============================================================

def _print_json(data: Dict[str, Any]) -> None:
    """输出JSON到stdout（无格式化，适合管道）"""
    json.dump(data, sys.stdout, ensure_ascii=False, separators=(',', ':'))
    sys.stdout.write('\n')


def _print_human(data: Dict[str, Any]) -> None:
    """输出人类可读格式到stdout"""
    # 检测是否为TTY
    is_tty = sys.stdout.isatty()

    if not is_tty:
        _print_json(data)
        return

    # 彩色输出
    print("=" * 60)
    print("  DEX 反编译结果")
    print("=" * 60)

    if 'apk' in data:
        print(f"\n APK: {data['apk']}")

    if 'dex_count' in data:
        print(f" DEX文件数: {data['dex_count']}")
        for dex in data.get('dex_files', []):
            print(f"   - {dex['file']}: {dex['class_count']} 个类")

    if 'total_classes' in data:
        print(f" 总类数: {data['total_classes']}")

    if 'output_root' in data:
        print(f" 输出目录: {data['output_root']}")

    if 'pattern' in data:
        print(f"\n 搜索模式: {data['pattern']}")
        print(f" 匹配数: {data.get('total_matches', 0)}")

    if 'matches' in data and data['matches']:
        print("\n 匹配详情:")
        for i, m in enumerate(data['matches'], 1):
            if 'value' in m:
                print(f"   [{i}] {m.get('dex', '?')}: {m['value']}")
            elif 'content' in m:
                print(f"   [{i}] {m.get('dex', '?')}:{m.get('line', '?')}: {m['content']}")

    print("\n" + "=" * 60)


def main() -> int:
    """
    CLI入口函数。

    用法:
        python dex_decompile.py decompile <apk_path> [--json]
        python dex_decompile.py search-strings <apk_path> <pattern> [--json]
        python dex_decompile.py search-code <apk_path> <pattern> [--json]

    全局选项:
        --json          输出机器可读的JSON格式
        --baksmali-path PATH  指定baksmali可执行文件路径
        -h, --help      显示帮助信息

    退出码:
        0: 成功
        1: 参数错误
        2: 文件不存在
        3: 工具缺失
        4: 执行失败
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog='dex_decompile',
        description='DEX反编译模块 - Android逆向工具箱',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 反编译APK
  python dex_decompile.py decompile app.apk

  # 搜索字符串
  python dex_decompile.py search-strings app.apk "api_key.*"

  # 搜索代码
  python dex_decompile.py search-code app.apk "Lcom/example/Network;->sendRequest"

  # 输出JSON（适合管道）
  python dex_decompile.py decompile app.apk --json | jq '.dex_files[0].class_count'
        """
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='输出机器可读的JSON格式（适合管道和脚本）'
    )
    parser.add_argument(
        '--baksmali-path',
        default=None,
        help='指定baksmali可执行文件路径（默认自动查找）'
    )

    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # decompile 子命令
    p_decompile = subparsers.add_parser(
        'decompile',
        help='反编译APK中的DEX文件为Smali源码'
    )
    p_decompile.add_argument('apk_path', help='APK文件路径')

    # search-strings 子命令
    p_strings = subparsers.add_parser(
        'search-strings',
        help='在APK的DEX中搜索字符串常量'
    )
    p_strings.add_argument('apk_path', help='APK文件路径')
    p_strings.add_argument('pattern', help='正则表达式搜索模式')

    # search-code 子命令
    p_code = subparsers.add_parser(
        'search-code',
        help='在Smali代码中搜索匹配模式'
    )
    p_code.add_argument('apk_path', help='APK文件路径')
    p_code.add_argument('pattern', help='正则表达式搜索模式')

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 1

    try:
        compiler = DexDecompiler(baksmali_path=args.baksmali_path)
    except RuntimeError as e:
        print(f"错误: {e}", file=sys.stderr)
        return 3

    try:
        if args.command == 'decompile':
            result = compiler.decompile(args.apk_path)
        elif args.command == 'search-strings':
            result = compiler.search_strings(args.apk_path, args.pattern)
        elif args.command == 'search-code':
            result = compiler.search_code(args.apk_path, args.pattern)
        else:
            print(f"未知命令: {args.command}", file=sys.stderr)
            return 1

        if args.json:
            _print_json(result)
        else:
            _print_human(result)

        return 0

    except FileNotFoundError as e:
        print(f"错误: {e}", file=sys.stderr)
        return 2
    except re.error as e:
        print(f"正则表达式错误: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"执行失败: {e}", file=sys.stderr)
        return 4


if __name__ == '__main__':
    sys.exit(main())