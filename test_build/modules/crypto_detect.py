#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
加密识别与密钥提取模块
======================
功能：对 Android APK 及 SO 文件进行加密算法特征识别、硬编码密钥提取、
      加密库检测。支持 AES/DES/3DES/RSA/MD5/SHA 等常见算法。

依赖：Python 3.6+ 标准库 + 系统工具 (strings, grep)

使用示例：
    from crypto_detect import CryptoDetector

    detector = CryptoDetector()
    result = detector.detect_algorithms("/path/to/app.apk")
    print(json.dumps(result, indent=2))

    keys = detector.extract_keys("/path/to/app.apk")
    libs = detector.detect_crypto_libraries("/path/to/libnative.so")
"""

import os
import re
import json
import subprocess
import zipfile
import tempfile
import shutil
from typing import Dict, List, Optional, Any, Tuple, Set


# ============================================================================
# 异常类定义
# ============================================================================

class CryptoDetectorError(Exception):
    """加密检测异常基类"""
    pass


class CryptoFileNotFoundError(CryptoDetectorError):
    """文件不存在"""
    pass


class CryptoToolNotFoundError(CryptoDetectorError):
    """必需的系统工具未找到"""
    pass


class CryptoAnalysisError(CryptoDetectorError):
    """分析过程中的通用错误"""
    pass

# ============================================================================
# 加密算法特征库
# ============================================================================

# 已知加密算法特征模式
# 格式: 算法名 -> (正则模式列表, 算法类别, 风险等级)
ALGORITHM_SIGNATURES: Dict[str, Tuple[List[str], str, str]] = {
    # === 对称加密 ===
    "AES": (
        [
            r'AES_(?:128|192|256)_(?:ECB|CBC|CTR|GCM|CFB|OFB)',
            r'aes_(?:128|192|256)_(?:ecb|cbc|ctr|gcm|cfb|ofb)',
            r'AES_KEY',
            r'AES_IV',
            r'AES Encrypt',
            r'AES Decrypt',
            r'AES/CBC/PKCS5',
            r'AES/GCM/NoPadding',
            r'javax\.crypto\.Cipher',
            r'javax\.crypto\.spec\.SecretKeySpec',
            r'javax\.crypto\.spec\.IvParameterSpec',
            r'android\.security\.keystore',
        ],
        "symmetric",
        "high"
    ),
    "DES": (
        [
            r'DES_(?:ECB|CBC|CTR)',
            r'des_(?:ecb|cbc|ctr)',
            r'DES_KEY',
            r'DES Encrypt',
            r'DES Decrypt',
            r'DES/ECB/',
            r'DES/CBC/',
        ],
        "symmetric",
        "medium"
    ),
    "3DES": (
        [
            r'3DES',
            r'TripleDES',
            r'TDES',
            r'desede',
            r'DES_EDE',
            r'DES_EDE3',
        ],
        "symmetric",
        "medium"
    ),
    "Blowfish": (
        [
            r'Blowfish',
            r'blowfish',
            r'BF_(?:ECB|CBC)',
        ],
        "symmetric",
        "medium"
    ),
    "RC4": (
        [
            r'RC4',
            r'rc4',
            r'ARC4',
            r'arc4',
        ],
        "symmetric",
        "high"
    ),
    "ChaCha20": (
        [
            r'ChaCha20',
            r'chacha20',
            r'ChaCha',
            r'chacha',
        ],
        "symmetric",
        "medium"
    ),

    # === 非对称加密 ===
    "RSA": (
        [
            r'RSA_(?:1024|2048|4096)',
            r'rsa_(?:1024|2048|4096)',
            r'RSA_KEY',
            r'RSA Encrypt',
            r'RSA Decrypt',
            r'java\.security\.KeyPairGenerator',
            r'java\.security\.KeyFactory',
            r'java\.security\.PrivateKey',
            r'java\.security\.PublicKey',
            r'android\.security\.keystore\.KeyPairGenerator',
        ],
        "asymmetric",
        "high"
    ),
    "ECC": (
        [
            r'EC_(?:P_256|P_384|P_521|secp256r1|secp384r1)',
            r'ec_(?:p_256|p_384|p_521)',
            r'ECDH',
            r'ECDSA',
            r'ecdh',
            r'ecdsa',
            r'EllipticCurve',
        ],
        "asymmetric",
        "medium"
    ),
    "DSA": (
        [
            r'DSA',
            r'dsa',
            r'DigitalSignatureAlgorithm',
        ],
        "asymmetric",
        "low"
    ),

    # === 哈希算法 ===
    "MD5": (
        [
            r'MD5',
            r'md5',
            r'MessageDigest.*MD5',
            r'MD5Digest',
            r'md5_',
        ],
        "hash",
        "low"
    ),
    "SHA-1": (
        [
            r'SHA-1',
            r'SHA1',
            r'sha1',
            r'SHA_1',
            r'SHA1Digest',
            r'MessageDigest.*SHA.*1',
            r'SHA-1 Digest',
        ],
        "hash",
        "low"
    ),
    "SHA-256": (
        [
            r'SHA-256',
            r'SHA256',
            r'sha256',
            r'SHA_256',
            r'SHA256Digest',
            r'MessageDigest.*SHA.*256',
            r'SHA-256 Digest',
        ],
        "hash",
        "low"
    ),
    "SHA-384": (
        [
            r'SHA-384',
            r'SHA384',
            r'sha384',
            r'SHA_384',
            r'MessageDigest.*SHA.*384',
        ],
        "hash",
        "low"
    ),
    "SHA-512": (
        [
            r'SHA-512',
            r'SHA512',
            r'sha512',
            r'SHA_512',
            r'SHA512Digest',
            r'MessageDigest.*SHA.*512',
        ],
        "hash",
        "low"
    ),

    # === HMAC ===
    "HMAC": (
        [
            r'HMAC',
            r'hmac',
            r'HmacSHA',
            r'HmacSHA1',
            r'HmacSHA256',
            r'HmacSHA384',
            r'HmacSHA512',
            r'javax\.crypto\.Mac',
        ],
        "hmac",
        "medium"
    ),

    # === 密钥派生 ===
    "PBKDF2": (
        [
            r'PBKDF2',
            r'pbkdf2',
            r'PBKDF2WithHMAC',
            r'SecretKeyFactory.*PBKDF2',
        ],
        "kdf",
        "medium"
    ),
    "bcrypt": (
        [
            r'bcrypt',
            r'BCrypt',
            r'org\.mindspring\.bcrypt',
            r'springframework\.security\.crypto\.bcrypt',
        ],
        "kdf",
        "medium"
    ),
    "scrypt": (
        [
            r'scrypt',
            r'Scrypt',
            r'org\.bouncycastle\.crypto\.generators\.scrypt',
        ],
        "kdf",
        "medium"
    ),
}

# 加密库特征 (用于检测 .so 文件中的第三方加密库)
CRYPTO_LIBRARY_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "OpenSSL": {
        "patterns": [
            r'openssl_',
            r'OpenSSL',
            r'SSL_',
            r'TLS_',
            r'EVP_[A-Za-z0-9_]+',
            r'BIO_[A-Za-z0-9_]+',
            r'RSA_[A-Za-z0-9_]+',
            r'EC_[A-Za-z0-9_]+',
            r'BN_[A-Za-z0-9_]+',
            r'SHA_[A-Za-z0-9_]+',
            r'MD_[A-Za-z0-9_]+',
            r'AES_[A-Za-z0-9_]+',
            r'DES_[A-Za-z0-9_]+',
            r'X509_[A-Za-z0-9_]+',
            r'PEM_[A-Za-z0-9_]+',
            r'PKCS[0-9_]+',
            r'CRYPTO_[A-Za-z0-9_]+',
        ],
        "description": "OpenSSL - 业界标准的加密库"
    },
    "BouncyCastle": {
        "patterns": [
            r'org\.bouncycastle',
            r'bouncycastle',
            r'BCLightCastle',
            r'Castle',
            r'PBE',
            r'PGP',
            r'OpenPGP',
            r'SMC',
            r'ASN1',
            r'X509ObjectIdentifiers',
        ],
        "description": "BouncyCastle - Java 加密扩展库"
    },
    "Conscrypt": {
        "patterns": [
            r'conscript',
            r'Conscrypt',
            r'org\.conscrypt',
            r'OpenSSL',
        ],
        "description": "Conscrypt - Google 的 OpenSSL/JVM 桥接"
    },
    "Tink": {
        "patterns": [
            r'google\.tink',
            r'com\.google\.tink',
            r'Tink',
            r'Aead',
            r'HybridDecrypt',
            r'HybridEncrypt',
            r'Signature',
            r'Mac',
            r'KeysetHandle',
            r'CleartextKeysetHandle',
            r'BinaryKeysetReader',
        ],
        "description": "Tink - Google 的多语言加密库"
    },
    "Crypto++": {
        "patterns": [
            r'CryptoPP',
            r'crypto\+\+',
            r'cryptopp',
            r'CryptoPP::',
            r'Vector2BLM',
            r'AutoSeededRandomPool',
        ],
        "description": "Crypto++ - C++ 加密库"
    },
    "LibTomCrypt": {
        "patterns": [
            r'ltc_',
            r'LibTomCrypt',
            r'prng_',
            r'hash_',
            r'cipher_',
            r'pk_',
            r'ecc_',
            r'sprng_',
        ],
        "description": "LibTomCrypt - 轻量级 C 加密库"
    },
    "MbedTLS": {
        "patterns": [
            r'mbedtls_',
            r'MbedTLS',
            r'md_',
            r'aes_',
            r'rsa_',
            r'ecdsa_',
            r'ecp_',
            r'bl_',
            r'hm_',
            r'pk_',
        ],
        "description": "MbedTLS - 嵌入式 TLS/加密库"
    },
    "WolfSSL": {
        "patterns": [
            r'wolfssl',
            r'WolfSSL',
            r'wc_',
            r'InitCiphers',
            r'wolfSSL_',
        ],
        "description": "WolfSSL - 嵌入式 TLS/DTLS 库"
    },
    "Botan": {
        "patterns": [
            r'Botan',
            r'botan_',
            r'Botan::',
            r'AutoSeeded_RNG',
            r'PKCS8',
            r'X509_Certificate',
        ],
        "description": "Botan - C++ 加密库"
    },
    "Libgcrypt": {
        "patterns": [
            r'libgcrypt',
            r'gcry_',
            r'Gcry',
            r'GPG',
        ],
        "description": "Libgcrypt - GNU 加密库"
    },
    "NaCl": {
        "patterns": [
            r'crypto_',
            r'sodium',
            r'NaCl',
            r'crypto_box',
            r'crypto_secretbox',
            r'crypto_sign',
        ],
        "description": "NaCl - 现代加密库"
    },
    "libsodium": {
        "patterns": [
            r'sodium',
            r'crypto_',
            r'crypto_box_',
            r'crypto_secretbox_',
            r'crypto_sign_',
            r'crypto_stream_',
        ],
        "description": "libsodium - NaCl 的可移植分支"
    },
}

# 硬编码密钥特征模式
# 格式: 密钥类型 -> (正则模式列表, 期望长度范围, 说明)
HARDCODED_KEY_PATTERNS: Dict[str, Tuple[List[str], Tuple[int, int], str]] = {
    "AES_KEY": (
        [
            r'(?i)(?:aes[_-]?key|secret[_-]?key|private[_-]?key)\s*[=:]\s*["\']([0-9a-fA-F]{32,64})["\']',
            r'(?i)(?:aes[_-]?key|secret[_-]?key)\s*[=:]\s*["\']([0-9a-fA-F]{32})["\']',
            r'(?i)(?:aes[_-]?key|secret[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9+/]{20,44}=?)["\']',
            r'(?i)(?:aes[_-]?key|secret[_-]?key)\s*[=:]\s*([0-9a-fA-F]{32,64})',
        ],
        (32, 64),
        "AES 密钥 (128/192/256位)"
    ),
    "DES_KEY": (
        [
            r'(?i)(?:des[_-]?key|des[_-]?secret)\s*[=:]\s*["\']([0-9a-fA-F]{8,16})["\']',
            r'(?i)(?:des[_-]?key|des[_-]?secret)\s*[=:]\s*["\']([A-Za-z0-9+/]{8,16}=?)["\']',
        ],
        (8, 16),
        "DES 密钥 (56/112/168位)"
    ),
    "RSA_PRIVATE_KEY": (
        [
            r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
            r'-----BEGIN (?:RSA )?ENCRYPTED PRIVATE KEY-----',
            r'-----BEGIN EC PRIVATE KEY-----',
            r'-----BEGIN OPENSSH PRIVATE KEY-----',
            r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        ],
        (100, 10000),
        "RSA/EC 私钥 (PEM 格式)"
    ),
    "RSA_PUBLIC_KEY": (
        [
            r'-----BEGIN (?:RSA )?PUBLIC KEY-----',
            r'-----BEGIN PUBLIC KEY-----',
            r'-----BEGIN EC PUBLIC KEY-----',
        ],
        (100, 5000),
        "RSA/EC 公钥 (PEM 格式)"
    ),
    "API_KEY": (
        [
            r'(?i)(?:api[_-]?key|api[_-]?secret|app[_-]?secret|access[_-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,128})["\']',
            r'(?i)(?:api[_-]?key|api[_-]?secret|app[_-]?secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,128})["\']',
        ],
        (16, 128),
        "API 密钥/令牌"
    ),
    "PASSWORD": (
        [
            r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,64})["\']',
            r'(?i)(?:password|passwd|pwd)\s*[=:]\s*([^\s"\']{6,64})',
        ],
        (6, 64),
        "硬编码密码"
    ),
    "SALT_IV": (
        [
            r'(?i)(?:salt|iv|nonce|initialization[_-]?vector)\s*[=:]\s*["\']([0-9a-fA-F]{8,64})["\']',
            r'(?i)(?:salt|iv|nonce)\s*[=:]\s*["\']([A-Za-z0-9+/]{8,44}=?)["\']',
        ],
        (8, 64),
        "盐值/初始化向量"
    ),
    "HMAC_KEY": (
        [
            r'(?i)(?:hmac[_-]?key|hmac[_-]?secret)\s*[=:]\s*["\']([0-9a-fA-F]{32,64})["\']',
            r'(?i)(?:hmac[_-]?key|hmac[_-]?secret)\s*[=:]\s*["\']([A-Za-z0-9+/]{20,44}=?)["\']',
        ],
        (32, 64),
        "HMAC 密钥"
    ),
    "JWT_SECRET": (
        [
            r'(?i)(?:jwt[_-]?secret|jwt[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,256})["\']',
        ],
        (16, 256),
        "JWT 签名密钥"
    ),
    "AWS_CREDENTIALS": (
        [
            r'(?i)aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9/+=]{16,64})["\']',
        ],
        (16, 64),
        "AWS 凭证"
    ),
}

# ============================================================================
# 主类定义
# ============================================================================

class CryptoDetector:
    """
    APK/SO 加密特征检测器

    提供对 Android 应用中加密算法使用情况的全面检测能力，包括：
    - 加密算法特征识别 (AES/DES/RSA/MD5/SHA 等)
    - 硬编码密钥提取 (AES 密钥、私钥、API 密钥等)
    - 加密库检测 (OpenSSL、BouncyCastle、Tink 等)
    - 风险评估

    所有方法返回结构化 dict，可直接序列化为 JSON。
    支持 APK 文件直接分析 (自动解包) 和 .so 文件分析。
    """

    # 字符串提取工具候选
    TOOL_CANDIDATES = {
        "strings": ["/usr/bin/strings", "/bin/strings", "strings"],
    }

    def __init__(self):
        """初始化检测器，检测系统工具可用性"""
        self._tool_paths: Dict[str, str] = {}
        self._detect_tools()

    def _detect_tools(self) -> None:
        """检测必需的系统工具路径"""
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
                    if os.path.isfile(candidate):
                        self._tool_paths[tool_name] = candidate
                        break

    def _get_tool(self, tool_name: str) -> str:
        """获取工具路径，如果未找到则抛出异常"""
        path = self._tool_paths.get(tool_name)
        if path is None:
            raise CryptoToolNotFoundError(
                f"必需的系统工具 '{tool_name}' 未找到。"
                f"请安装对应工具或检查 PATH 设置。"
            )
        return path

    # ========================================================================
    # 公共 API 方法
    # ========================================================================

    def detect_algorithms(self, apk_path: str) -> Dict[str, Any]:
        """
        检测 APK 中使用的加密算法

        扫描 APK 文件中的字符串，匹配已知加密算法特征模式，
        返回检测到的算法列表及其详细信息。

        参数：
            apk_path: APK 文件路径

        返回：
            dict: {
                "apk_path": str,
                "algorithms_detected": [...],
                "summary": {...},
                "risk_level": str,
                "error": str | None
            }

        异常：
            CryptoFileNotFoundError: 文件不存在
            CryptoAnalysisError: 分析失败
        """
        if not os.path.isfile(apk_path):
            raise CryptoFileNotFoundError(
                f"APK 文件不存在: {apk_path}"
            )

        result: Dict[str, Any] = {
            "apk_path": apk_path,
            "algorithms_detected": [],
            "summary": {},
            "risk_level": "unknown",
            "error": None,
        }

        try:
            strings_data = self._extract_apk_strings(apk_path)

            detected: List[Dict[str, Any]] = []
            algorithm_counts: Dict[str, int] = {}
            category_counts: Dict[str, int] = {}

            for algo_name, (patterns, category, risk) in ALGORITHM_SIGNATURES.items():
                matches = []
                for pattern in patterns:
                    try:
                        found = re.findall(pattern, strings_data, re.IGNORECASE)
                        if found:
                            matches.extend(found)
                    except re.error:
                        continue

                if matches:
                    unique_matches = list(set(matches))[:20]
                    detected.append({
                        "algorithm": algo_name,
                        "category": category,
                        "risk_level": risk,
                        "match_count": len(matches),
                        "sample_matches": unique_matches[:10],
                    })
                    algorithm_counts[algo_name] = len(matches)
                    category_counts[category] = category_counts.get(category, 0) + 1

            result["algorithms_detected"] = detected
            result["summary"] = {
                "total_algorithms": len(detected),
                "by_category": category_counts,
                "by_risk": self._summarize_risk(detected),
            }
            result["risk_level"] = self._calculate_risk_level(detected)

        except CryptoDetectorError:
            raise
        except Exception as e:
            result["error"] = f"算法检测失败: {str(e)}"
            raise CryptoAnalysisError(result["error"]) from e

        return result

    def extract_keys(self, apk_path: str) -> Dict[str, Any]:
        """
        提取 APK 中的硬编码密钥

        扫描 APK 文件中的字符串，匹配硬编码密钥特征模式，
        返回发现的密钥列表。

        参数：
            apk_path: APK 文件路径

        返回：
            dict: {
                "apk_path": str,
                "keys_found": [...],
                "summary": {...},
                "error": str | None
            }

        异常：
            CryptoFileNotFoundError: 文件不存在
            CryptoAnalysisError: 提取失败
        """
        if not os.path.isfile(apk_path):
            raise CryptoFileNotFoundError(
                f"APK 文件不存在: {apk_path}"
            )

        result: Dict[str, Any] = {
            "apk_path": apk_path,
            "keys_found": [],
            "summary": {},
            "error": None,
        }

        try:
            strings_data = self._extract_apk_strings(apk_path)

            keys_found: List[Dict[str, Any]] = []
            key_type_counts: Dict[str, int] = {}

            for key_type, (patterns, expected_range, description) in HARDCODED_KEY_PATTERNS.items():
                matches = []
                for pattern in patterns:
                    try:
                        found = re.findall(pattern, strings_data, re.IGNORECASE | re.MULTILINE)
                        if found:
                            matches.extend(found)
                    except re.error:
                        continue

                if matches:
                    unique_matches = list(set(matches))
                    filtered = []
                    for m in unique_matches:
                        if isinstance(m, tuple):
                            value = next((g for g in reversed(m) if g), '')
                        else:
                            value = m
                        min_len, max_len = expected_range
                        if min_len <= len(value) <= max_len:
                            filtered.append(value)

                    if filtered:
                        keys_found.append({
                            "key_type": key_type,
                            "description": description,
                            "match_count": len(filtered),
                            "samples": filtered[:5],
                        })
                        key_type_counts[key_type] = len(filtered)

            result["keys_found"] = keys_found
            result["summary"] = {
                "total_key_types": len(keys_found),
                "total_keys_found": sum(key_type_counts.values()),
                "by_type": key_type_counts,
            }
            high_risk_types = {"AES_KEY", "RSA_PRIVATE_KEY", "API_KEY", "AWS_CREDENTIALS"}
            if any(k["key_type"] in high_risk_types for k in keys_found):
                result["risk_level"] = "critical"
            elif keys_found:
                result["risk_level"] = "high"
            else:
                result["risk_level"] = "low"

        except CryptoDetectorError:
            raise
        except Exception as e:
            result["error"] = f"密钥提取失败: {str(e)}"
            raise CryptoAnalysisError(result["error"]) from e

        return result

    def detect_crypto_libraries(self, so_path: str) -> Dict[str, Any]:
        """
        检测 .so 文件中使用的加密库

        扫描 Android 原生库 (.so) 中的导出符号和字符串，
        匹配已知加密库特征。

        参数：
            so_path: .so 文件路径

        返回：
            dict: {
                "so_path": str,
                "libraries_detected": [...],
                "summary": {...},
                "error": str | None
            }

        异常：
            CryptoFileNotFoundError: 文件不存在
            CryptoAnalysisError: 检测失败
        """
        if not os.path.isfile(so_path):
            raise CryptoFileNotFoundError(
                f"SO 文件不存在: {so_path}"
            )

        result: Dict[str, Any] = {
            "so_path": so_path,
            "libraries_detected": [],
            "summary": {},
            "error": None,
        }

        try:
            strings_data = self._extract_so_strings(so_path)

            detected: List[Dict[str, Any]] = []
            lib_counts: Dict[str, int] = {}

            for lib_name, lib_info in CRYPTO_LIBRARY_SIGNATURES.items():
                patterns = lib_info["patterns"]
                description = lib_info["description"]
                matches = []

                for pattern in patterns:
                    try:
                        found = re.findall(pattern, strings_data, re.IGNORECASE)
                        if found:
                            matches.extend(found)
                    except re.error:
                        continue

                if matches:
                    unique_matches = list(set(matches))[:20]
                    detected.append({
                        "library": lib_name,
                        "description": description,
                        "match_count": len(matches),
                        "sample_matches": unique_matches[:10],
                    })
                    lib_counts[lib_name] = len(matches)

            result["libraries_detected"] = detected
            result["summary"] = {
                "total_libraries": len(detected),
                "by_library": lib_counts,
            }

        except CryptoDetectorError:
            raise
        except Exception as e:
            result["error"] = f"加密库检测失败: {str(e)}"
            raise CryptoAnalysisError(result["error"]) from e

        return result

    def analyze(self, apk_path: str) -> Dict[str, Any]:
        """
        综合分析：算法检测 + 密钥提取 + SO 库检测

        对 APK 进行完整的加密分析，包括：
        1. 检测 APK 中使用的加密算法
        2. 提取硬编码密钥
        3. 扫描 APK 中的 .so 文件并检测加密库

        参数：
            apk_path: APK 文件路径

        返回：
            dict: 完整的加密分析结果
        """
        if not os.path.isfile(apk_path):
            raise CryptoFileNotFoundError(
                f"APK 文件不存在: {apk_path}"
            )

        result: Dict[str, Any] = {
            "apk_path": apk_path,
            "algorithm_detection": {},
            "key_extraction": {},
            "library_detection": [],
            "overall_risk": "unknown",
            "error": None,
        }

        try:
            result["algorithm_detection"] = self.detect_algorithms(apk_path)
            result["key_extraction"] = self.extract_keys(apk_path)

            so_files = self._extract_so_files(apk_path)
            for so_path in so_files:
                try:
                    lib_result = self.detect_crypto_libraries(so_path)
                    result["library_detection"].append(lib_result)
                except CryptoDetectorError as e:
                    result["library_detection"].append({
                        "so_path": so_path,
                        "error": str(e),
                    })

            result["overall_risk"] = self._calculate_overall_risk(result)

        except CryptoDetectorError:
            raise
        except Exception as e:
            result["error"] = f"综合分析失败: {str(e)}"
            raise CryptoAnalysisError(result["error"]) from e

        return result

    # ========================================================================
    # 内部辅助方法
    # ========================================================================

    def _extract_apk_strings(self, apk_path: str) -> str:
        """
        从 APK 文件中提取字符串

        支持直接读取 APK 中的 classes.dex 文件，或回退到 strings 命令。
        """
        strings_output = ""

        # 方法1: 尝试从 APK 中解包 DEX 并提取字符串
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.dex'):
                        try:
                            dex_data = zf.read(name)
                            dex_strings = self._extract_dex_strings(dex_data)
                            strings_output += dex_strings + "\n"
                        except Exception:
                            continue
        except (zipfile.BadZipFile, OSError):
            pass

        # 方法2: 使用 strings 命令作为补充
        try:
            strings_tool = self._get_tool("strings")
            result = subprocess.run(
                [strings_tool, "-n", "6", apk_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                strings_output += result.stdout + "\n"
        except (CryptoToolNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        return strings_output

    def _extract_so_strings(self, so_path: str) -> str:
        """从 .so 文件中提取字符串"""
        try:
            strings_tool = self._get_tool("strings")
            result = subprocess.run(
                [strings_tool, "-n", "5", so_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout
        except (CryptoToolNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        # 回退: 直接读取二进制文件中的 ASCII 字符串
        return self._extract_ascii_strings(so_path)

    def _extract_dex_strings(self, dex_data: bytes) -> str:
        """从 DEX 字节数据中提取字符串"""
        strings = []
        current = []
        for byte in dex_data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= 6:
                    strings.append(''.join(current))
                current = []
        if len(current) >= 6:
            strings.append(''.join(current))
        return '\n'.join(strings)

    def _extract_ascii_strings(self, file_path: str) -> str:
        """从二进制文件中提取 ASCII 字符串"""
        strings = []
        try:
            with open(file_path, 'rb') as f:
                current = []
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    for byte in chunk:
                        if 32 <= byte < 127:
                            current.append(chr(byte))
                        else:
                            if len(current) >= 5:
                                strings.append(''.join(current))
                            current = []
                if len(current) >= 5:
                    strings.append(''.join(current))
        except OSError:
            pass
        return '\n'.join(strings)

    def _extract_so_files(self, apk_path: str) -> List[str]:
        """从 APK 中提取 .so 文件路径列表"""
        so_files = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.so'):
                        temp_dir = tempfile.mkdtemp(prefix='artoolkit_so_')
                        try:
                            zf.extract(name, temp_dir)
                            so_path = os.path.join(temp_dir, name)
                            if os.path.isfile(so_path):
                                so_files.append(so_path)
                        except Exception:
                            shutil.rmtree(temp_dir, ignore_errors=True)
        except (zipfile.BadZipFile, OSError):
            pass
        return so_files

    def _summarize_risk(self, detected: List[Dict[str, Any]]) -> Dict[str, int]:
        """汇总风险等级统计"""
        risk_counts = {"high": 0, "medium": 0, "low": 0}
        for item in detected:
            risk = item.get("risk_level", "low")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        return risk_counts

    def _calculate_risk_level(self, detected: List[Dict[str, Any]]) -> str:
        """根据检测到的算法计算风险等级"""
        if not detected:
            return "low"

        high_risk_algos = {"AES", "RSA", "RC4", "ChaCha20", "ECC"}
        has_high_risk = any(
            item["algorithm"] in high_risk_algos for item in detected
        )

        if has_high_risk:
            return "high"
        elif len(detected) >= 3:
            return "medium"
        else:
            return "low"

    def _calculate_overall_risk(self, result: Dict[str, Any]) -> str:
        """计算综合风险等级"""
        algo_risk = result.get("algorithm_detection", {}).get("risk_level", "low")
        key_risk = result.get("key_extraction", {}).get("risk_level", "low")

        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        max_risk = max(
            risk_order.get(algo_risk, 0),
            risk_order.get(key_risk, 0),
        )

        if max_risk >= 3:
            return "critical"
        elif max_risk >= 2:
            return "high"
        elif max_risk >= 1:
            return "medium"
        else:
            return "low"

# ============================================================================
# 命令行接口 (CLI)
# ============================================================================

def main() -> int:
    """
    命令行入口

    用法:
        crypto_detect.py <apk_path> [选项]

    选项:
        --json          输出 JSON 格式
        --verbose       输出详细信息
        --quiet         仅输出错误
        --help          显示帮助信息
    """
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        prog="crypto_detect",
        description="APK 加密特征检测与密钥提取工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  %(prog)s app.apk
  %(prog)s app.apk --json
  %(prog)s app.apk --verbose
  %(prog)s app.apk --quiet --json
        """
    )
    parser.add_argument(
        "apk_path",
        help="APK 文件路径"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="以 JSON 格式输出结果 (适合管道/脚本)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="输出详细信息 (包括样本密钥等)"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="仅输出错误信息"
    )

    args = parser.parse_args()

    try:
        detector = CryptoDetector()
        result = detector.analyze(args.apk_path)

        if args.quiet:
            if result.get("error"):
                print(f"Error: {result['error']}", file=sys.stderr)
                return 1
            return 0

        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            # 人类可读输出
            print("\n" + "=" * 60)
            print("  APK 加密分析报告")
            print("=" * 60)
            print(f"  文件: {result.get('apk_path', 'N/A')}")
            print(f"  综合风险: {result.get('overall_risk', 'unknown').upper()}")
            print()

            algo = result.get("algorithm_detection", {})
            if algo:
                print("-" * 60)
                print("  检测到的加密算法")
                print("-" * 60)
                algos = algo.get("algorithms_detected", [])
                if algos:
                    for a in algos:
                        print(f"  • {a['algorithm']} ({a['category']}) - 风险: {a['risk_level']} - 匹配数: {a['match_count']}")
                else:
                    print("  (未检测到加密算法)")
                print()

            keys = result.get("key_extraction", {})
            if keys:
                print("-" * 60)
                print("  硬编码密钥")
                print("-" * 60)
                keys_found = keys.get("keys_found", [])
                if keys_found:
                    for k in keys_found:
                        print(f"  • {k['key_type']}: {k['description']} (发现 {k['match_count']} 个)")
                        if args.verbose:
                            for sample in k.get("samples", []):
                                masked = sample[:8] + "..." + sample[-4:] if len(sample) > 12 else "***"
                                print(f"    - {masked}")
                else:
                    print("  (未发现硬编码密钥)")
                print()

            libs = result.get("library_detection", [])
            if libs:
                print("-" * 60)
                print("  原生加密库")
                print("-" * 60)
                for lib_result in libs:
                    so_path = lib_result.get("so_path", "N/A")
                    detected = lib_result.get("libraries_detected", [])
                    print(f"  SO: {os.path.basename(so_path)}")
                    if detected:
                        for d in detected:
                            print(f"    • {d['library']}: {d['description']} (匹配数: {d['match_count']})")
                    else:
                        print("    (未检测到加密库)")
                    print()

            print("=" * 60)

        return 0 if not result.get("error") else 1

    except CryptoFileNotFoundError as e:
        if not args.quiet:
            print(f"✗ {e}", file=sys.stderr)
        return 2
    except CryptoToolNotFoundError as e:
        if not args.quiet:
            print(f"✗ {e}", file=sys.stderr)
        return 3
    except CryptoAnalysisError as e:
        if not args.quiet:
            print(f"✗ 分析失败: {e}", file=sys.stderr)
        return 4
    except Exception as e:
        if not args.quiet:
            print(f"✗ 未预期的错误: {e}", file=sys.stderr)
        return 5


if __name__ == "__main__":
    import sys
    sys.exit(main())
