#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
字符串解密模块
==============
功能：XOR、Base64、RC4 等常见字符串加密的检测与解密
"""

import os
import re
import json
import base64
import binascii
import subprocess
from typing import Dict, List, Any, Optional, Tuple


class StringDecryptError(Exception):
    """字符串解密异常"""
    pass


class StringDecryptor:
    """字符串解密器"""

    # 常见密钥模式
    COMMON_KEYS = [
        "key", "secret", "password", "123456", "admin",
        "abcdef", "000000", "111111", "test", "default",
    ]

    def __init__(self):
        pass

    # ==================== XOR ====================
    def xor_decrypt(self, data: str, key: str) -> str:
        """XOR 解密"""
        if key.startswith("0x"):
            try:
                key_byte = int(key, 16)
            except ValueError:
                raise StringDecryptError(f"无效的十六进制密钥: {key}")
        elif len(key) == 1:
            key_byte = ord(key)
        else:
            # 多字节密钥
            result = []
            for i, c in enumerate(data):
                result.append(chr(ord(c) ^ ord(key[i % len(key)])))
            return "".join(result)

        return "".join(chr(ord(c) ^ key_byte) for c in data)

    def xor_detect(self, data: str) -> List[Dict[str, Any]]:
        """检测 XOR 加密并尝试解密"""
        results = []
        # 尝试常见单字节密钥
        for key_byte in range(256):
            if key_byte == 0:
                continue
            try:
                decoded = "".join(chr(ord(c) ^ key_byte) for c in data)
                # 检查是否可打印
                if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in decoded):
                    if any(c.isalpha() for c in decoded):
                        results.append({
                            "type": "xor",
                            "key": f"0x{key_byte:02x}",
                            "decoded": decoded,
                            "confidence": "medium" if len(decoded) > 5 else "low",
                        })
            except:
                pass
        return results[:5]  # 最多返回5个

    # ==================== Base64 ====================
    def base64_decrypt(self, data: str) -> str:
        """Base64 解密"""
        try:
            # 尝试标准 Base64
            decoded = base64.b64decode(data).decode('utf-8', errors='replace')
            return decoded
        except Exception as e:
            raise StringDecryptError(f"Base64 解密失败: {e}")

    def base64_detect(self, data: str) -> List[Dict[str, Any]]:
        """检测 Base64 编码"""
        results = []
        # Base64 模式
        b64_pattern = r'^[A-Za-z0-9+/]+={0,2}$'
        if re.match(b64_pattern, data) and len(data) % 4 == 0:
            try:
                decoded = base64.b64decode(data).decode('utf-8', errors='replace')
                if decoded.isprintable() and len(decoded) > 2:
                    results.append({
                        "type": "base64",
                        "decoded": decoded,
                        "confidence": "high" if len(decoded) > 10 else "medium",
                    })
            except:
                pass
        return results

    # ==================== RC4 ====================
    def rc4_decrypt(self, data: str, key: str) -> str:
        """RC4 解密"""
        if not key:
            raise StringDecryptError("RC4 需要密钥")

        S = list(range(256))
        j = 0
        key_bytes = [ord(c) for c in key]
        for i in range(256):
            j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
            S[i], S[j] = S[j], S[i]

        i = j = 0
        result = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(chr(ord(byte) ^ k))

        return "".join(result)

    def rc4_detect(self, data: str) -> List[Dict[str, Any]]:
        """检测 RC4 加密（使用常见密钥尝试）"""
        results = []
        for key in self.COMMON_KEYS:
            try:
                decoded = self.rc4_decrypt(data, key)
                if decoded.isprintable() and any(c.isalpha() for c in decoded):
                    results.append({
                        "type": "rc4",
                        "key": key,
                        "decoded": decoded,
                        "confidence": "low",
                    })
            except:
                pass
        return results

    # ==================== 自动检测 ====================
    def auto_decrypt(self, data: str) -> List[Dict[str, Any]]:
        """自动检测并尝试所有解密方法"""
        results = []

        # 尝试 Base64
        b64_results = self.base64_detect(data)
        results.extend(b64_results)

        # 尝试 XOR
        xor_results = self.xor_detect(data)
        results.extend(xor_results)

        # 尝试 RC4
        rc4_results = self.rc4_detect(data)
        results.extend(rc4_results)

        # 按置信度排序
        results.sort(key=lambda x: {"high": 3, "medium": 2, "low": 1}.get(x.get("confidence", "low"), 0), reverse=True)
        return results

    # ==================== 文件操作 ====================
    def extract_strings(self, file_path: str, min_length: int = 5) -> List[str]:
        """从文件中提取字符串"""
        if not os.path.exists(file_path):
            raise StringDecryptError(f"文件不存在: {file_path}")

        try:
            result = subprocess.run(
                ["strings", "-n", str(min_length), file_path],
                capture_output=True, text=True, timeout=60
            )
            return result.stdout.splitlines()
        except Exception as e:
            raise StringDecryptError(f"提取字符串失败: {e}")

    def auto_detect_file(self, file_path: str) -> Dict[str, Any]:
        """自动检测文件中的加密字符串"""
        if not os.path.exists(file_path):
            raise StringDecryptError(f"文件不存在: {file_path}")

        strings = self.extract_strings(file_path)
        results = []

        for s in strings:
            if len(s) < 8:
                continue
            decrypted = self.auto_decrypt(s)
            if decrypted:
                results.append({
                    "original": s[:50],
                    "decrypted": decrypted[0].get("decoded", "")[:100],
                    "type": decrypted[0].get("type", "unknown"),
                    "confidence": decrypted[0].get("confidence", "low"),
                })

        return {
            "file": file_path,
            "total_strings": len(strings),
            "detected_count": len(results),
            "results": results[:50],
        }

    # ==================== 批量操作 ====================
    def batch_decrypt(self, strings: List[str]) -> List[Dict[str, Any]]:
        """批量解密字符串列表"""
        results = []
        for s in strings:
            decrypted = self.auto_decrypt(s)
            if decrypted:
                results.append({
                    "original": s,
                    "decrypted": decrypted[0].get("decoded", ""),
                    "type": decrypted[0].get("type", "unknown"),
                })
        return results


def main() -> int:
    """命令行入口"""
    import argparse
    parser = argparse.ArgumentParser(description="字符串解密工具")
    sub = parser.add_subparsers(dest="command")

    # xor
    p = sub.add_parser("xor", help="XOR 解密")
    p.add_argument("--data", required=True, help="要解密的数据")
    p.add_argument("--key", required=True, help="密钥")

    # base64
    p = sub.add_parser("base64", help="Base64 解密")
    p.add_argument("--data", required=True, help="要解密的数据")

    # rc4
    p = sub.add_parser("rc4", help="RC4 解密")
    p.add_argument("--data", required=True, help="要解密的数据")
    p.add_argument("--key", required=True, help="密钥")

    # auto
    p = sub.add_parser("auto", help="自动检测")
    p.add_argument("--data", default=None, help="要检测的字符串")
    p.add_argument("--file", default=None, help="要检测的文件")
    p.add_argument("--json", action="store_true", help="JSON 输出")

    args = parser.parse_args()

    decryptor = StringDecryptor()

    if args.command == "xor":
        result = decryptor.xor_decrypt(args.data, args.key)
        print(f"🔓 XOR 解密: {result}")
    elif args.command == "base64":
        result = decryptor.base64_decrypt(args.data)
        print(f"🔓 Base64 解密: {result}")
    elif args.command == "rc4":
        result = decryptor.rc4_decrypt(args.data, args.key)
        print(f"🔓 RC4 解密: {result}")
    elif args.command == "auto":
        if args.data:
            results = decryptor.auto_decrypt(args.data)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                for r in results:
                    print(f"  [{r['type']}] {r['decoded'][:50]}...")
        elif args.file:
            result = decryptor.auto_detect_file(args.file)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"🔍 文件检测: {result['file']}")
                print(f"  总字符串: {result['total_strings']}")
                print(f"  检测到加密: {result['detected_count']}")
                for r in result['results'][:10]:
                    print(f"  [{r['type']}] {r['original'][:30]}... -> {r['decrypted'][:30]}...")
        else:
            print("[-] 请提供 --data 或 --file 参数")
            return 1
    else:
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())