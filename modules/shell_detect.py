#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shell Detection and DEX Integrity Module for Android Reverse Engineering

This module provides:
- Detection of common Android shell providers (360, Tencent, Baidu, Alibaba, NetEase, AiJiaMi, etc.)
- DEX file integrity checking (count, magic numbers, size anomalies)
- Unpacking strategy recommendations based on shell type
- Frida memory dump script generation for runtime DEX extraction

Dependencies: Pure Python standard library only.
Output format: Structured JSON.
"""

import os
import json
import struct
import zipfile
import hashlib
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any


class ShellType(Enum):
    """Enumeration of known shell/protect providers."""
    UNKNOWN = "unknown"
    _360 = "360"
    TENCENT = "tencent"
    BAIDU = "baidu"
    ALIBABA = "alibaba"
    NETEASE = "netease"
    AIJIA_MI = "aijiami"
    QIHOO = "qihoo"
    SONIC = "sonic"
    AMATRI_X = "amatriX"
    DAQIN = "daqin"
    MERCURY = "mercury"
    ARS_PROTECT = "ars_protect"
    VIPRO = "vipro"
    YOUPIN = "youpin"
    CLOVER = "clover"
    IJIA = "ijia"
    BANG = "bang"
    THIKA = "thika"


class DEXMagicError(Exception):
    """Raised when DEX magic number is invalid."""
    pass


class DEXIntegrityIssue(Enum):
    """Types of DEX integrity issues."""
    MISSING = "missing"
    CORRUPTED = "corrupted"
    SIZE_ANOMALY = "size_anomaly"
    DUPLICATE = "duplicate"
    OBFUSCATED = "obfuscated"


# Known shell provider signatures
SHELL_SIGNATURES: Dict[str, Dict[str, Any]] = {
    ShellType._360.value: {
        "name": "360加固",
        "package_patterns": [
            "com.qihoo",
            "com.360",
            "com.qihoo.security",
            "com.360.security",
        ],
        "native_lib_patterns": [
            "lib360",
            "libqihoo",
            "libsecurity",
            "libprotect",
        ],
        "string_signatures": [
            "360",
            "qihoo",
            "com.qihoo",
            "lib360",
            "360safe",
        ],
        "asset_patterns": [
            "360",
            "qihoo",
        ],
        "description": "360加固（奇虎360）- 国内主流加固方案之一"
    },
    ShellType.TENCENT.value: {
        "name": "腾讯加固",
        "package_patterns": [
            "com.tencent",
            "com.android Tencent",
        ],
        "native_lib_patterns": [
            "libtencent",
            "libmtg",
            "libtp",
            "libTencent",
        ],
        "string_signatures": [
            "tencent",
            "mtg",
            "tp",
            "libtencent",
        ],
        "asset_patterns": [
            "tencent",
        ],
        "description": "腾讯加固 - 腾讯系应用常用加固方案"
    },
    ShellType.BAIDU.value: {
        "name": "百度加固",
        "package_patterns": [
            "com.baidu",
        ],
        "native_lib_patterns": [
            "libbaidu",
            "libmochi",
            "libbaiduprotect",
        ],
        "string_signatures": [
            "baidu",
            "mochi",
            "libbaidu",
        ],
        "asset_patterns": [
            "baidu",
        ],
        "description": "百度加固 - 百度系应用加固方案"
    },
    ShellType.ALIBABA.value: {
        "name": "阿里加固",
        "package_patterns": [
            "com.alibaba",
            "com.ali",
            "taobao",
        ],
        "native_lib_patterns": [
            "libalibaba",
            "libali",
            "libtaobao",
        ],
        "string_signatures": [
            "alibaba",
            "ali",
            "taobao",
        ],
        "asset_patterns": [
            "alibaba",
        ],
        "description": "阿里加固 - 阿里巴巴系应用加固方案"
    },
    ShellType.NETEASE.value: {
        "name": "网易加固",
        "package_patterns": [
            "com.netease",
        ],
        "native_lib_patterns": [
            "libnetease",
            "libease",
        ],
        "string_signatures": [
            "netease",
            "libnetease",
        ],
        "asset_patterns": [
            "netease",
        ],
        "description": "网易加固 - 网易系游戏/应用加固方案"
    },
    ShellType.AIJIA_MI.value: {
        "name": "爱加密",
        "package_patterns": [
            "com.ijiami",
            "com.aijiami",
        ],
        "native_lib_patterns": [
            "libijiami",
            "libprotect",
        ],
        "string_signatures": [
            "ijiami",
            "aijiami",
            "爱加密",
        ],
        "asset_patterns": [
            "ijiami",
        ],
        "description": "爱加密 - 专业移动安全加固方案"
    },
    ShellType.QIHOO.value: {
        "name": "奇虎加固",
        "package_patterns": [
            "com.qihoo",
        ],
        "native_lib_patterns": [
            "libqihoo",
            "lib360",
        ],
        "string_signatures": [
            "qihoo",
            "奇虎",
        ],
        "asset_patterns": [
            "qihoo",
        ],
        "description": "奇虎加固 - 与360加固同源"
    },
    ShellType.SONIC.value: {
        "name": "Sonic加固",
        "package_patterns": [
            "com.sonic",
            "org.sonic",
        ],
        "native_lib_patterns": [
            "libsonic",
        ],
        "string_signatures": [
            "sonic",
        ],
        "asset_patterns": [],
        "description": "Sonic加固 - 腾讯开源热更新方案加固"
    },
    ShellType.AMATRI_X.value: {
        "name": "AmatriX加固",
        "package_patterns": [
            "com.amatrix",
        ],
        "native_lib_patterns": [
            "libamatrix",
            "libamatriX",
        ],
        "string_signatures": [
            "amatrix",
            "amatriX",
        ],
        "asset_patterns": [],
        "description": "AmatriX加固 - 移动应用保护方案"
    },
    ShellType.DAQIN.value: {
        "name": "大秦加固",
        "package_patterns": [
            "com.daqin",
        ],
        "native_lib_patterns": [
            "libdaqin",
        ],
        "string_signatures": [
            "daqin",
            "大秦",
        ],
        "asset_patterns": [],
        "description": "大秦加固 - 移动安全加固方案"
    },
    ShellType.MERCURY.value: {
        "name": "水星加固",
        "package_patterns": [
            "com.mercury",
        ],
        "native_lib_patterns": [
            "libmercury",
        ],
        "string_signatures": [
            "mercury",
            "水星",
        ],
        "asset_patterns": [],
        "description": "水星加固 - 移动应用保护"
    },
    ShellType.ARS_PROTECT.value: {
        "name": "ARS Protect加固",
        "package_patterns": [
            "com.ars",
        ],
        "native_lib_patterns": [
            "libars",
        ],
        "string_signatures": [
            "ars",
            "arsprotect",
        ],
        "asset_patterns": [],
        "description": "ARS Protect - 企业级应用加固"
    },
    ShellType.VIPRO.value: {
        "name": "Vipro加固",
        "package_patterns": [
            "com.vipro",
        ],
        "native_lib_patterns": [
            "libvipro",
        ],
        "string_signatures": [
            "vipro",
        ],
        "asset_patterns": [],
        "description": "Vipro加固 - 移动应用安全保护"
    },
    ShellType.YOUPIN.value: {
        "name": "友品加固",
        "package_patterns": [
            "com.youpin",
        ],
        "native_lib_patterns": [
            "libyoupin",
        ],
        "string_signatures": [
            "youpin",
            "友品",
        ],
        "asset_patterns": [],
        "description": "友品加固 - 移动安全方案"
    },
    ShellType.CLOVER.value: {
        "name": "Clover加固",
        "package_patterns": [
            "com.clover",
        ],
        "native_lib_patterns": [
            "libclover",
        ],
        "string_signatures": [
            "clover",
        ],
        "asset_patterns": [],
        "description": "Clover加固 - 应用保护方案"
    },
    ShellType.IJIA.value: {
        "name": "IJIA加固",
        "package_patterns": [
            "com.ijia",
        ],
        "native_lib_patterns": [
            "libijia",
        ],
        "string_signatures": [
            "ijia",
        ],
        "asset_patterns": [],
        "description": "IJIA加固 - 移动安全加固"
    },
    ShellType.BANG.value: {
        "name": "Bang加固",
        "package_patterns": [
            "com.bang",
        ],
        "native_lib_patterns": [
            "libbang",
        ],
        "string_signatures": [
            "bang",
        ],
        "asset_patterns": [],
        "description": "Bang加固 - 应用保护方案"
    },
    ShellType.THIKA.value: {
        "name": "Thika加固",
        "package_patterns": [
            "com.thika",
        ],
        "native_lib_patterns": [
            "libthika",
        ],
        "string_signatures": [
            "thika",
        ],
        "asset_patterns": [],
        "description": "Thika加固 - 移动应用安全"
    },
}


class DEXHeader:
    """DEX file header constants."""
    MAGIC = b"dex\n035\x00"
    MAGIC_OLD = b"dex\n035"
    MAGIC_V = b"dex\n037\x00"
    MAGIC_V_OLD = b"dex\n037"
    HEADER_SIZE = 0x70
    ENDIAN_TAG = 0x12345678


class ShellDetector:
    """
    Android APK shell detection and DEX integrity checking module.

    Detects common shell providers through:
    - Package name patterns
    - Native library patterns
    - Characteristic string signatures
    - Asset file patterns

    Provides:
    - DEX integrity checking
    - Unpacking strategy recommendations
    - Frida memory dump script generation
    """

    def __init__(self):
        """Initialize the ShellDetector."""
        self.detection_result: Dict[str, Any] = {}
        self.dex_issues: List[Dict[str, Any]] = []
        self.frida_script: str = ""

    def _check_apk_exists(self, apk_path: str) -> None:
        """Validate that the APK file exists and is readable."""
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        if not os.path.isfile(apk_path):
            raise ValueError(f"Path is not a file: {apk_path}")
        if not os.access(apk_path, os.R_OK):
            raise PermissionError(f"APK file is not readable: {apk_path}")

    def _open_apk(self, apk_path: str) -> zipfile.ZipFile:
        """Open APK as ZIP file with error handling."""
        try:
            return zipfile.ZipFile(apk_path, 'r')
        except zipfile.BadZipFile as e:
            raise ValueError(f"Invalid APK (not a valid ZIP): {apk_path}") from e
        except Exception as e:
            raise RuntimeError(f"Failed to open APK: {apk_path}") from e

    def _get_apk_entries(self, zf: zipfile.ZipFile) -> List[str]:
        """Get all file entries from the APK."""
        return [info.filename for info in zf.infolist()]

    def _read_file_from_zip(self, zf: zipfile.ZipFile, filename: str, max_size: int = 1024 * 1024) -> Optional[bytes]:
        """Read a file from the APK ZIP, with size limit."""
        try:
            with zf.open(filename) as f:
                data = f.read(max_size)
                return data
        except KeyError:
            return None
        except Exception:
            return None

    def _check_dex_magic(self, data: bytes) -> bool:
        """Check if data starts with a valid DEX magic number."""
        if not data or len(data) < 8:
            return False
        magic = data[:8]
        return (magic == DEXHeader.MAGIC or magic == DEXHeader.MAGIC_OLD or
                magic == DEXHeader.MAGIC_V or magic == DEXHeader.MAGIC_V_OLD)

    def _check_dex_header(self, data: bytes) -> Tuple[bool, Optional[str]]:
        """Validate DEX header fields."""
        if len(data) < DEXHeader.HEADER_SIZE:
            return False, "Header too short"

        magic = data[:8]
        if not (magic == DEXHeader.MAGIC or magic == DEXHeader.MAGIC_OLD or
                magic == DEXHeader.MAGIC_V or magic == DEXHeader.MAGIC_V_OLD):
            return False, f"Invalid magic: {magic.hex()}"

        file_size = struct.unpack('<I', data[32:36])[0]
        if file_size != len(data):
            return False, f"Size mismatch: header={file_size}, actual={len(data)}"

        endian_tag = struct.unpack('<I', data[40:44])[0]
        if endian_tag != DEXHeader.ENDIAN_TAG:
            return False, f"Invalid endian tag: 0x{endian_tag:08x}"

        return True, None

    def detect_shell(self, apk_path: str) -> Dict[str, Any]:
        """
        Detect shell/protect provider in an APK file.

        Args:
            apk_path: Path to the APK file.

        Returns:
            Dictionary containing detection results with:
            - detected: bool - whether a shell was detected
            - shell_type: str - detected shell type
            - shell_name: str - human-readable shell name
            - confidence: float - detection confidence (0.0-1.0)
            - indicators: list - specific indicators that matched
            - description: str - shell description

        Raises:
            FileNotFoundError: If APK doesn't exist.
            ValueError: If APK is invalid.
        """
        self._check_apk_exists(apk_path)

        result: Dict[str, Any] = {
            "detected": False,
            "shell_type": ShellType.UNKNOWN.value,
            "shell_name": "Unknown",
            "confidence": 0.0,
            "indicators": [],
            "description": "No shell detected - APK appears to be unprotected",
            "all_detections": []
        }

        try:
            with self._open_apk(apk_path) as zf:
                entries = self._get_apk_entries(zf)

                for shell_key, shell_info in SHELL_SIGNATURES.items():
                    indicators: List[Dict[str, str]] = []
                    score = 0.0

                    manifest_data = self._read_file_from_zip(zf, "AndroidManifest.xml", max_size=512 * 1024)
                    if manifest_data:
                        manifest_str = manifest_data.decode('utf-8', errors='ignore')
                        for pattern in shell_info.get("package_patterns", []):
                            if pattern.lower() in manifest_str.lower():
                                indicators.append({
                                    "type": "package",
                                    "pattern": pattern,
                                    "location": "AndroidManifest.xml"
                                })
                                score += 0.3

                    for lib_pattern in shell_info.get("native_lib_patterns", []):
                        for entry in entries:
                            if f"lib/{lib_pattern}" in entry.lower() or f"lib/{lib_pattern.lower()}" in entry.lower():
                                indicators.append({
                                    "type": "native_lib",
                                    "pattern": lib_pattern,
                                    "location": entry
                                })
                                score += 0.25
                                break

                    for entry in entries:
                        if entry.startswith("classes") and entry.endswith(".dex"):
                            dex_data = self._read_file_from_zip(zf, entry, max_size=256 * 1024)
                            if dex_data:
                                dex_str = dex_data.decode('utf-8', errors='ignore')
                                for sig in shell_info.get("string_signatures", []):
                                    if sig.lower() in dex_str.lower():
                                        indicators.append({
                                            "type": "string_signature",
                                            "pattern": sig,
                                            "location": entry
                                        })
                                        score += 0.15
                                        break

                    for asset_pattern in shell_info.get("asset_patterns", []):
                        for entry in entries:
                            if entry.startswith("assets/") and asset_pattern.lower() in entry.lower():
                                indicators.append({
                                    "type": "asset",
                                    "pattern": asset_pattern,
                                    "location": entry
                                })
                                score += 0.1
                                break

                    if indicators:
                        result["all_detections"].append({
                            "shell_type": shell_key,
                            "shell_name": shell_info["name"],
                            "confidence": min(score, 1.0),
                            "indicators": indicators,
                            "description": shell_info["description"]
                        })

                if result["all_detections"]:
                    best = max(result["all_detections"], key=lambda x: x["confidence"])
                    result["detected"] = True
                    result["shell_type"] = best["shell_type"]
                    result["shell_name"] = best["shell_name"]
                    result["confidence"] = best["confidence"]
                    result["indicators"] = best["indicators"]
                    result["description"] = best["description"]

        except Exception as e:
            result["error"] = str(e)

        self.detection_result = result
        return result

    def check_dex_integrity(self, apk_path: str) -> Dict[str, Any]:
        """
        Check DEX file integrity in the APK.

        Checks:
        - Number of classes.dex files
        - DEX magic numbers
        - DEX header validity
        - DEX file size anomalies

        Args:
            apk_path: Path to the APK file.

        Returns:
            Dictionary containing DEX integrity analysis results.

        Raises:
            FileNotFoundError: If APK doesn't exist.
            ValueError: If APK is invalid.
        """
        self._check_apk_exists(apk_path)

        result: Dict[str, Any] = {
            "dex_files": [],
            "total_dex_count": 0,
            "valid_dex_count": 0,
            "corrupted_dex_count": 0,
            "missing_dex": False,
            "size_anomalies": [],
            "integrity_issues": [],
            "overall_status": "unknown"
        }

        try:
            with self._open_apk(apk_path) as zf:
                entries = self._get_apk_entries(zf)

                dex_entries = [e for e in entries if e.endswith(".dex")]
                result["total_dex_count"] = len(dex_entries)

                if not dex_entries:
                    result["missing_dex"] = True
                    result["integrity_issues"].append({
                        "type": DEXIntegrityIssue.MISSING.value,
                        "description": "No DEX files found in APK",
                        "severity": "critical"
                    })
                    result["overall_status"] = "corrupted"
                    self.dex_issues = result["integrity_issues"]
                    return result

                dex_sizes = []
                for entry in sorted(dex_entries):
                    dex_info = zf.getinfo(entry)
                    dex_size = dex_info.file_size
                    dex_sizes.append(dex_size)

                    dex_data = self._read_file_from_zip(zf, entry, max_size=dex_size + 1024)
                    dex_file_info: Dict[str, Any] = {
                        "filename": entry,
                        "size": dex_size,
                        "compressed_size": dex_info.compress_size,
                        "valid": False,
                        "issues": []
                    }

                    if dex_data is None:
                        dex_file_info["issues"].append({
                            "type": DEXIntegrityIssue.MISSING.value,
                            "description": f"Failed to read {entry}",
                            "severity": "critical"
                        })
                        result["corrupted_dex_count"] += 1
                        result["integrity_issues"].append({
                            "type": DEXIntegrityIssue.MISSING.value,
                            "file": entry,
                            "description": f"Failed to read {entry}",
                            "severity": "critical"
                        })
                    else:
                        if not self._check_dex_magic(dex_data):
                            dex_file_info["issues"].append({
                                "type": DEXIntegrityIssue.CORRUPTED.value,
                                "description": f"Invalid DEX magic number: {dex_data[:8].hex()}",
                                "severity": "critical"
                            })
                            result["corrupted_dex_count"] += 1
                            result["integrity_issues"].append({
                                "type": DEXIntegrityIssue.CORRUPTED.value,
                                "file": entry,
                                "description": f"Invalid DEX magic number",
                                "severity": "critical"
                            })
                        else:
                            header_valid, header_error = self._check_dex_header(dex_data)
                            if not header_valid:
                                dex_file_info["issues"].append({
                                    "type": DEXIntegrityIssue.CORRUPTED.value,
                                    "description": f"Invalid DEX header: {header_error}",
                                    "severity": "high"
                                })
                                result["corrupted_dex_count"] += 1
                                result["integrity_issues"].append({
                                    "type": DEXIntegrityIssue.CORRUPTED.value,
                                    "file": entry,
                                    "description": header_error or "Invalid header",
                                    "severity": "high"
                                })
                            else:
                                dex_file_info["valid"] = True
                                result["valid_dex_count"] += 1

                    result["dex_files"].append(dex_file_info)

                if len(dex_sizes) > 1:
                    avg_size = sum(dex_sizes) / len(dex_sizes)
                    for entry, size in zip(sorted(dex_entries), dex_sizes):
                        if size > avg_size * 3 and size > 10 * 1024 * 1024:
                            result["size_anomalies"].append({
                                "file": entry,
                                "size": size,
                                "average_size": avg_size,
                                "ratio": round(size / avg_size, 2),
                                "description": f"DEX file is {size / avg_size:.1f}x larger than average"
                            })
                            result["integrity_issues"].append({
                                "type": DEXIntegrityIssue.SIZE_ANOMALY.value,
                                "file": entry,
                                "description": f"Unusually large DEX file ({size / (1024*1024):.1f}MB)",
                                "severity": "medium"
                            })

                if len(dex_sizes) > 1:
                    seen_hashes = {}
                    for entry in sorted(dex_entries):
                        dex_data = self._read_file_from_zip(zf, entry, max_size=10 * 1024 * 1024)
                        if dex_data:
                            dex_hash = hashlib.sha256(dex_data).hexdigest()
                            if dex_hash in seen_hashes:
                                result["integrity_issues"].append({
                                    "type": DEXIntegrityIssue.DUPLICATE.value,
                                    "file": entry,
                                    "duplicate_of": seen_hashes[dex_hash],
                                    "description": f"Duplicate of {seen_hashes[dex_hash]}",
                                    "severity": "low"
                                })
                                for dex_file in result["dex_files"]:
                                    if dex_file["filename"] == entry:
                                        dex_file["issues"].append({
                                            "type": DEXIntegrityIssue.DUPLICATE.value,
                                            "description": f"Duplicate DEX file",
                                            "severity": "low"
                                        })
                            else:
                                seen_hashes[dex_hash] = entry

                if result["corrupted_dex_count"] > 0:
                    result["overall_status"] = "corrupted"
                elif result["missing_dex"]:
                    result["overall_status"] = "missing"
                elif result["size_anomalies"]:
                    result["overall_status"] = "warning"
                else:
                    result["overall_status"] = "healthy"

        except Exception as e:
            result["error"] = str(e)
            result["overall_status"] = "error"

        self.dex_issues = result["integrity_issues"]
        return result

    def get_unpack_advice(self, apk_path: str) -> Dict[str, Any]:
        """
        Generate unpacking strategy recommendations based on shell detection.

        Args:
            apk_path: Path to the APK file.

        Returns:
            Dictionary containing unpacking advice with:
            - shell_detected: bool
            - recommended_methods: list of recommended unpacking methods
            - frida_script_available: bool
            - manual_steps: list of manual steps if needed
            - difficulty: str - estimated difficulty level
            - estimated_time: str - estimated time to unpack
        """
        shell_result = self.detect_shell(apk_path)
        dex_result = self.check_dex_integrity(apk_path)

        advice: Dict[str, Any] = {
            "shell_detected": shell_result["detected"],
            "shell_type": shell_result["shell_type"],
            "shell_name": shell_result["shell_name"],
            "confidence": shell_result["confidence"],
            "recommended_methods": [],
            "frida_script_available": False,
            "manual_steps": [],
            "difficulty": "easy",
            "estimated_time": "5 minutes",
            "notes": []
        }

        shell_type = shell_result["shell_type"]

        if not shell_result["detected"]:
            advice["recommended_methods"].append({
                "method": "Direct DEX extraction",
                "description": "Extract classes.dex directly from APK",
                "commands": [
                    "unzip -o app.apk classes.dex -d output/",
                    "apktool d app.apk -o output/"
                ],
                "difficulty": "easy"
            })
            advice["difficulty"] = "easy"
            advice["estimated_time"] = "2 minutes"
        elif shell_type == ShellType._360.value or shell_type == ShellType.QIHOO.value:
            advice["recommended_methods"].extend([
                {
                    "method": "Frida memory dump",
                    "description": "Use Frida to hook and dump DEX from memory at runtime",
                    "difficulty": "medium"
                },
                {
                    "method": "Custom linker extraction",
                    "description": "Extract and analyze the custom linker/library to find DEX loading logic",
                    "difficulty": "hard"
                }
            ])
            advice["difficulty"] = "hard"
            advice["estimated_time"] = "30-60 minutes"
            advice["manual_steps"] = [
                "1. Install app on rooted device/emulator",
                "2. Use Frida to attach to the app process",
                "3. Run the generated dump script",
                "4. Collect DEX files from the dump directory"
            ]
        elif shell_type == ShellType.TENCENT.value:
            advice["recommended_methods"].extend([
                {
                    "method": "Frida memory dump",
                    "description": "Use Frida to hook Open/load functions and dump DEX from memory",
                    "difficulty": "medium"
                },
                {
                    "method": "Sonic dump",
                    "description": "If using Sonic, extract the patch and base DEX",
                    "difficulty": "easy"
                }
            ])
            advice["difficulty"] = "medium"
            advice["estimated_time"] = "15-30 minutes"
        elif shell_type == ShellType.BAIDU.value:
            advice["recommended_methods"].extend([
                {
                    "method": "Frida memory dump",
                    "description": "Hook native functions to dump DEX",
                    "difficulty": "medium"
                },
                {
                    "method": "Dynamic analysis",
                    "description": "Use Xposed/EdXposed to hook and dump DEX",
                    "difficulty": "medium"
                }
            ])
            advice["difficulty"] = "medium"
            advice["estimated_time"] = "20-40 minutes"
        elif shell_type == ShellType.ALIBABA.value:
            advice["recommended_methods"].extend([
                {
                    "method": "Frida memory dump",
                    "description": "Hook DEX loading functions and dump from memory",
                    "difficulty": "medium"
                },
                {
                    "method": "TAobao/Alibaba specific extraction",
                    "description": "Extract specific libraries and analyze loading mechanism",
                    "difficulty": "hard"
                }
            ])
            advice["difficulty"] = "medium"
            advice["estimated_time"] = "20-40 minutes"
        elif shell_type == ShellType.NETEASE.value:
            advice["recommended_methods"].extend([
                {
                    "method": "Frida memory dump",
                    "description": "Hook DEX loading and dump from memory",
                    "difficulty": "medium"
                }
            ])
            advice["difficulty"] = "medium"
            advice["estimated_time"] = "15-30 minutes"
        elif shell_type == ShellType.AIJIA_MI.value:
            advice["recommended_methods"].extend([
                {
                    "method": "Frida memory dump",
                    "description": "Use Frida to hook and dump DEX from memory",
                    "difficulty": "medium"
                },
                {
                    "method": "Static analysis of native libs",
                    "description": "Analyze the native library to understand DEX loading",
                    "difficulty": "hard"
                }
            ])
            advice["difficulty"] = "hard"
            advice["estimated_time"] = "30-60 minutes"
        else:
            advice["recommended_methods"].extend([
                {
                    "method": "Frida memory dump",
                    "description": "Generic Frida script to dump DEX from memory",
                    "difficulty": "medium"
                },
                {
                    "method": "Dynamic analysis",
                    "description": "Use dynamic analysis tools to extract DEX at runtime",
                    "difficulty": "hard"
                }
            ])
            advice["difficulty"] = "medium"
            advice["estimated_time"] = "20-40 minutes"

        if dex_result.get("integrity_issues"):
            advice["notes"].append(f"Found {len(dex_result['integrity_issues'])} DEX integrity issues")
            for issue in dex_result["integrity_issues"]:
                if issue.get("severity") in ("critical", "high"):
                    advice["notes"].append(f"  - {issue.get('description', '')}")

        advice["frida_script_available"] = True
        advice["frida_script"] = self.generate_dump_script(apk_path)

        return advice

    def generate_dump_script(self, apk_path: str) -> str:
        """
        Generate a Frida script for dumping DEX files from a running app.

        The script hooks common DEX loading functions and dumps DEX files
        from memory when they are loaded.

        Args:
            apk_path: Path to the APK file (used for package name extraction).

        Returns:
            Frida JavaScript script as a string.
        """
        apk_name = os.path.basename(apk_path)

        script = f'''/**
 * Frida DEX Dump Script
 * Generated for: {apk_name}
 * 
 * Usage:
 *   frida -U -f <package_name> --no-pause -l dump_dex.js
 *   or
 *   frida -U --pid <pid> -l dump_dex.js
 * 
 * This script hooks common DEX loading functions and dumps DEX files
 * from memory when they are loaded by the Android runtime.
 */

// Configuration
const CONFIG = {{
    outputDir: '/data/local/tmp/dex_dump',
    dumpOnLoad: true,
    dumpExisting: true,
    verbose: true,
    minDexSize: 1024,  // Minimum DEX size to dump (bytes)
}};

// Utility: log with timestamp
function log(msg) {{
    if (CONFIG.verbose) {{
        console.log("[DEX-DUMP] " + new Date().toISOString() + " " + msg);
    }}
}}

// Utility: hex dump
function hexDump(data, maxLen) {{
    maxLen = maxLen || 64;
    let result = "";
    for (let i = 0; i < Math.min(data.length, maxLen); i++) {{
        result += data.charAt(i).toString(16).padStart(2, '0') + " ";
    }}
    if (data.length > maxLen) result += "...";
    return result;
}}

// Utility: save DEX file
function saveDex(dexData, filename) {{
    if (!dexData || dexData.length < CONFIG.minDexSize) {{
        log("Skipping " + filename + " (too small: " + (dexData ? dexData.length : 0) + " bytes)");
        return false;
    }}
    
    log("Saving DEX: " + filename + " (" + dexData.length + " bytes)");
    
    // Write file using Java's FileOutputStream
    try {{
        const File = Java.use("java.io.File");
        const FileOutputStream = Java.use("java.io.FileOutputStream");
        
        let dir = new File(CONFIG.outputDir);
        if (!dir.exists()) {{
            dir.mkdirs();
        }}
        
        let file = new File(CONFIG.outputDir, filename);
        let fos = new FileOutputStream(file);
        fos.write(dexData);
        fos.close();
        
        log("Successfully saved: " + file.getAbsolutePath());
        return true;
    }} catch (e) {{
        log("Error saving " + filename + ": " + e.message);
        return false;
    }}
}}

// Utility: check DEX magic
function isDex(data) {{
    if (!data || data.length < 8) return false;
    const magic = data.substring(0, 8);
    return magic === "dex\\\\n035\\\\x00" || 
           magic === "dex\\\\n035" ||
           magic === "dex\\\\n037\\\\x00" ||
           magic === "dex\\\\n037";
}}

// Hook android.content.pm.BasePackageInfo (for Android 8+)
function hookPackageInfo() {{
    try {{
        const BasePackageInfo = Java.use("android.content.pm.BasePackageInfo");
        BasePackageInfo.toString.implementation = function() {{
            let result = this.super.toString.call(this);
            log("PackageInfo.toString: " + result);
            return result;
        }};
    }} catch (e) {{
        log("hookPackageInfo: " + e.message);
    }}
}}

// Hook DexClassLoader (common DEX loading)
function hookDexClassLoader() {{
    try {{
        const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        
        // Hook constructor to capture DEX path
        DexClassLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader").implementation = function(
            dexPath, optimizedDirectory, libraryPath, parent
        ) {{
            log("DexClassLoader created: " + dexPath);
            this.$init.call(this, dexPath, optimizedDirectory, libraryPath, parent);
            
            // Try to read and dump the DEX file
            setTimeout(function() {{
                try {{
                    const File = Java.use("java.io.File");
                    const FileInputStream = Java.use("java.io.FileInputStream");
                    const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                    
                    let file = new File(dexPath);
                    if (file.exists() && file.isFile()) {{
                        let fis = new FileInputStream(file);
                        let baos = new ByteArrayOutputStream();
                        let buffer = Java.array Allocate(byte, 4096);
                        let bytesRead;
                        
                        while ((bytesRead = fis.read(buffer)) !== -1) {{
                            baos.write(buffer, 0, bytesRead);
                        }}
                        
                        fis.close();
                        let dexData = baos.toByteArray();
                        
                        if (isDex(dexData)) {{
                            let filename = "classes_" + Date.now() + ".dex";
                            saveDex(dexData, filename);
                        }}
                        
                        baos.close();
                    }}
                }} catch (e) {{
                    log("DexClassLoader dump error: " + e.message);
                }}
            }}, 100);
        }};
    }} catch (e) {{
        log("hookDexClassLoader: " + e.message);
    }}
}}

// Hook PathClassLoader
function hookPathClassLoader() {{
    try {{
        const PathClassLoader = Java.use("dalvik.system.PathClassLoader");
        
        PathClassLoader.$init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function(
            dexPath, parent
        ) {{
            log("PathClassLoader created: " + dexPath);
            this.$init.call(this, dexPath, parent);
            
            setTimeout(function() {{
                try {{
                    const File = Java.use("java.io.File");
                    const FileInputStream = Java.use("java.io.FileInputStream");
                    const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                    
                    let file = new File(dexPath);
                    if (file.exists() && file.isFile()) {{
                        let fis = new FileInputStream(file);
                        let baos = new ByteArrayOutputStream();
                        let buffer = Java.array Allocate(byte, 4096);
                        let bytesRead;
                        
                        while ((bytesRead = fis.read(buffer)) !== -1) {{
                            baos.write(buffer, 0, bytesRead);
                        }}
                        
                        fis.close();
                        let dexData = baos.toByteArray();
                        
                        if (isDex(dexData)) {{
                            let filename = "classes_" + Date.now() + ".dex";
                            saveDex(dexData, filename);
                        }}
                        
                        baos.close();
                    }}
                }} catch (e) {{
                    log("PathClassLoader dump error: " + e.message);
                }}
            }}, 100);
        }};
    }} catch (e) {{
        log("hookPathClassLoader: " + e.message);
    }}
}}

// Hook InMemoryDex (Android 8+ in-memory DEX)
function hookInMemoryDex() {{
    try {{
        const InMemoryDex = Java.use("dalvik.system.InMemoryDex");
        
        InMemoryDex.$init.overload("java.nio.ByteBuffer").implementation = function(buffer) {{
            log("InMemoryDex created from ByteBuffer");
            this.$init.call(this, buffer);
            
            try {{
                let dexData = buffer.array();
                if (isDex(dexData)) {{
                    let filename = "inmemory_" + Date.now() + ".dex";
                    saveDex(dexData, filename);
                }}
            }} catch (e) {{
                log("InMemoryDex dump error: " + e.message);
            }}
        }};
        
        InMemoryDex.$init.overload("[B").implementation = function(data) {{
            log("InMemoryDex created from byte[]");
            this.$init.call(this, data);
            
            try {{
                if (isDex(data)) {{
                    let filename = "inmemory_" + Date.now() + ".dex";
                    saveDex(dexData, filename);
                }}
            }} catch (e) {{
                log("InMemoryDex dump error: " + e.message);
            }}
        }};
    }} catch (e) {{
        log("hookInMemoryDex: " + e.message);
    }}
}}

// Hook DexFile (low-level DEX loading)
function hookDexFile() {{
    try {{
        const DexFile = Java.use("dalvik.system.DexFile");
        
        DexFile.loadDex.implementation = function(sourceFileName, outputPath, loadCallback) {{
            log("DexFile.loadDex: " + sourceFileName + " -> " + outputPath);
            let result = this.loadDex.call(this, sourceFileName, outputPath, loadCallback);
            
            if (outputPath) {{
                setTimeout(function() {{
                    try {{
                        const File = Java.use("java.io.File");
                        const FileInputStream = Java.use("java.io.FileInputStream");
                        const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                        
                        let file = new File(outputPath);
                        if (file.exists() && file.isFile()) {{
                            let fis = new FileInputStream(file);
                            let baos = new ByteArrayOutputStream();
                            let buffer = Java.array Allocate(byte, 4096);
                            let bytesRead;
                            
                            while ((bytesRead = fis.read(buffer)) !== -1) {{
                                baos.write(buffer, 0, bytesRead);
                            }}
                            
                            fis.close();
                            let dexData = baos.toByteArray();
                            
                            if (isDex(dexData)) {{
                                let filename = "dexfile_" + Date.now() + ".dex";
                                saveDex(dexData, filename);
                            }}
                            
                            baos.close();
                        }}
                    }} catch (e) {{
                        log("DexFile dump error: " + e.message);
                    }}
                }}, 100);
            }}
            
            return result;
        }};
    }} catch (e) {{
        log("hookDexFile: " + e.message);
    }}
}}

// Hook native DEX loading (for shell apps)
function hookNativeDexLoad() {{
    try {{
        // Hook common native functions that load DEX
        const nativeLibs = ["libdvm.so", "libart.so", "libdexfile.so"];
        
        for (let i = 0; i < nativeLibs.length; i++) {{
            try {{
                const lib = Module.findExportByName(nativeLibs[i], null);
                if (lib) {{
                    log("Hooking native lib: " + nativeLibs[i]);
                    
                    // Hook open/openat for DEX files
                    Interceptor.attach(lib, {{
                        onEnter: function(args) {{
                            // This is a simplified hook - real implementation would need
                            // to parse the path argument to detect DEX files
                        }},
                        onLeave: function(retval) {{
                            // Could dump DEX from file descriptor here
                        }}
                    }};
                }}
            }} catch (e) {{
                // Library not found, continue
            }}
        }}
    }} catch (e) {{
        log("hookNativeDexLoad: " + e.message);
    }}
}}

// Hook Zygote (for pre-loaded DEX)
function hookZygote() {{
    try {{
        // Hook ActivityThread (for loaded DEX)
        const ActivityThread = Java.use("android.app.ActivityThread");
        ActivityThread.getLoadedAPK.implementation = function() {{
            let apk = this.getLoadedAPK.call(this);
            if (apk) {{
                log("Loaded APK: " + apk.getSourceDir());
            }}
            return apk;
        }};
    }} catch (e) {{
        log("hookZygote: " + e.message);
    }}
}}

// Main initialization
function init() {{
    log("Initializing DEX dump script...");
    log("Output directory: " + CONFIG.outputDir);
    
    // Create output directory
    try {{
        const File = Java.use("java.io.File");
        let dir = new File(CONFIG.outputDir);
        if (!dir.exists()) {{
            dir.mkdirs();
            log("Created output directory");
        }}
    }} catch (e) {{
        log("Error creating output directory: " + e.message);
    }}
    
    // Hook all DEX loading mechanisms
    hookDexClassLoader();
    hookPathClassLoader();
    hookInMemoryDex();
    hookDexFile();
    hookNativeDexLoad();
    hookZygote();
    
    log("DEX dump script initialized successfully");
    log("Waiting for DEX files to be loaded...");
}}

// Auto-initialize when script is loaded
setImmediate(init);

// Export for manual triggering
module.exports = {{
    saveDex: saveDex,
    isDex: isDex,
    init: init,
    config: CONFIG
}};
'''
        self.frida_script = script
        return script

    def to_json(self, indent: int = 2) -> str:
        """
        Convert all analysis results to a JSON string.

        Args:
            indent: JSON indentation level.

        Returns:
            JSON string containing all analysis results.
        """
        result = {
            "detection": self.detection_result,
            "dex_integrity": self.dex_issues,
            "frida_script_length": len(self.frida_script) if self.frida_script else 0
        }
        return json.dumps(result, indent=indent, ensure_ascii=False)

    def analyze_all(self, apk_path: str) -> Dict[str, Any]:
        """
        Perform complete analysis: shell detection, DEX integrity, and unpacking advice.

        Args:
            apk_path: Path to the APK file.

        Returns:
            Dictionary containing all analysis results.
        """
        self._check_apk_exists(apk_path)

        # Detect shell
        shell_result = self.detect_shell(apk_path)

        # Check DEX integrity
        dex_result = self.check_dex_integrity(apk_path)

        # Get unpacking advice
        advice_result = self.get_unpack_advice(apk_path)

        # Combine results
        full_result = {
            "apk_path": apk_path,
            "apk_name": os.path.basename(apk_path),
            "apk_size": os.path.getsize(apk_path),
            "shell_detection": shell_result,
            "dex_integrity": dex_result,
            "unpack_advice": advice_result,
            "frida_script": self.frida_script
        }

        return full_result


# Command-line interface for testing
def main():
    """CLI entry point for testing the module."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Android APK Shell Detection and DEX Integrity Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python shell_detect.py app.apk
  python shell_detect.py app.apk --json
  python shell_detect.py app.apk --dump-script output.js
        """
    )
    parser.add_argument("apk_path", help="Path to the APK file")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--dump-script", metavar="FILE", help="Save Frida dump script to file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    detector = ShellDetector()

    try:
        result = detector.analyze_all(args.apk_path)

        if args.dump_script:
            with open(args.dump_script, 'w', encoding='utf-8') as f:
                f.write(detector.frida_script)
            print(f"Frida script saved to: {args.dump_script}")

        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            # Human-readable output
            print("=" * 60)
            print("Android APK Shell Detection Report")
            print("=" * 60)
            print(f"APK: {result['apk_name']}")
            print(f"Size: {result['apk_size']:,} bytes")
            print()

            # Shell detection
            shell = result["shell_detection"]
            print("--- Shell Detection ---")
            print(f"  Detected: {shell['detected']}")
            print(f"  Shell: {shell['shell_name']}")
            print(f"  Confidence: {shell['confidence']:.0%}")
            print(f"  Description: {shell['description']}")
            if shell.get("indicators"):
                print("  Indicators:")
                for ind in shell["indicators"]:
                    print(f"    - {ind['type']}: {ind['pattern']} ({ind['location']})")
            print()

            # DEX integrity
            dex = result["dex_integrity"]
            print("--- DEX Integrity ---")
            print(f"  Total DEX files: {dex['total_dex_count']}")
            print(f"  Valid: {dex['valid_dex_count']}")
            print(f"  Corrupted: {dex['corrupted_dex_count']}")
            print(f"  Status: {dex['overall_status']}")
            if dex.get("integrity_issues"):
                print("  Issues:")
                for issue in dex["integrity_issues"]:
                    print(f"    - [{issue['severity']}] {issue.get('description', '')}")
            print()

            # Unpacking advice
            advice = result["unpack_advice"]
            print("--- Unpacking Advice ---")
            print(f"  Difficulty: {advice['difficulty']}")
            print(f"  Estimated time: {advice['estimated_time']}")
            print("  Recommended methods:")
            for method in advice["recommended_methods"]:
                print(f"    - {method['method']} ({method['difficulty']})")
            if advice.get("manual_steps"):
                print("  Manual steps:")
                for step in advice["manual_steps"]:
                    print(f"    {step}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()