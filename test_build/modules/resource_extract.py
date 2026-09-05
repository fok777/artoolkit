#!/usr/bin/env python3
"""
资源提取模块 - 安卓逆向工具箱
功能：从APK中提取各类资源文件（图片、布局、字符串、原生库等）
"""

import os
import json
import zipfile
import hashlib
import shutil
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import subprocess
import tempfile


class ResourceType(Enum):
    IMAGE = "image"
    LAYOUT = "layout"
    STRING = "string"
    NATIVE_LIB = "native_lib"
    ASSET = "asset"
    OTHER = "other"


class ResourceExtractor:
    """资源提取器"""

    def __init__(self):
        self.image_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp'}
        self.layout_extensions = {'.xml', '.axml'}

    def extract_all(self, apk_path: str, output_dir: str = None) -> Dict[str, Any]:
        """提取APK中所有资源"""
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK文件不存在: {apk_path}")

        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="artoolkit_resources_")

        result = {
            "apk_path": apk_path,
            "output_dir": output_dir,
            "resources": [],
            "statistics": {},
            "errors": []
        }

        try:
            os.makedirs(output_dir, exist_ok=True)

            images = self.extract_images(apk_path, output_dir)
            layouts = self.extract_layouts(apk_path, output_dir)
            native_libs = self.extract_native_libs(apk_path, output_dir)
            assets = self.extract_assets(apk_path, output_dir)
            strings = self.extract_string_resources(apk_path, output_dir)

            result["resources"] = images + layouts + native_libs + assets + strings
            result["statistics"] = self._calculate_statistics(result["resources"])

        except Exception as e:
            result["errors"].append(str(e))

        return result

    def extract_images(self, apk_path: str, output_dir: str) -> List[Dict]:
        """提取图片资源"""
        resources = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for info in zf.infolist():
                    ext = os.path.splitext(info.filename)[1].lower()
                    if ext in self.image_extensions and info.file_size > 0:
                        resource = self._extract_file(zf, info, output_dir, ResourceType.IMAGE)
                        if resource:
                            resources.append(resource)
        except Exception:
            pass
        return resources

    def extract_layouts(self, apk_path: str, output_dir: str) -> List[Dict]:
        """提取布局文件"""
        resources = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for info in zf.infolist():
                    ext = os.path.splitext(info.filename)[1].lower()
                    if ext in self.layout_extensions and info.file_size > 0:
                        resource = self._extract_file(zf, info, output_dir, ResourceType.LAYOUT)
                        if resource:
                            resources.append(resource)
        except Exception:
            pass
        return resources

    def extract_native_libs(self, apk_path: str, output_dir: str) -> List[Dict]:
        """提取原生库"""
        resources = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for info in zf.infolist():
                    if info.filename.startswith('lib/') and info.filename.endswith('.so'):
                        resource = self._extract_file(zf, info, output_dir, ResourceType.NATIVE_LIB)
                        if resource:
                            resources.append(resource)
        except Exception:
            pass
        return resources

    def extract_assets(self, apk_path: str, output_dir: str) -> List[Dict]:
        """提取assets资源"""
        resources = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for info in zf.infolist():
                    if info.filename.startswith('assets/') and info.file_size > 0:
                        resource = self._extract_file(zf, info, output_dir, ResourceType.ASSET)
                        if resource:
                            resources.append(resource)
        except Exception:
            pass
        return resources

    def extract_string_resources(self, apk_path: str, output_dir: str) -> List[Dict]:
        """提取字符串资源"""
        resources = []
        try:
            result = subprocess.run(
                ['strings', apk_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                strings_content = result.stdout
                strings_path = os.path.join(output_dir, 'strings.txt')
                with open(strings_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(strings_content)

                resources.append({
                    "name": "strings.txt",
                    "resource_type": ResourceType.STRING.value,
                    "size": len(strings_content),
                    "path": strings_path,
                    "mime_type": "text/plain"
                })
        except Exception:
            pass
        return resources

    def _extract_file(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo,
                      output_dir: str, resource_type: ResourceType) -> Optional[Dict]:
        """提取单个文件"""
        try:
            safe_name = os.path.basename(info.filename)
            if not safe_name:
                return None

            target_dir = os.path.join(output_dir, resource_type.value)
            os.makedirs(target_dir, exist_ok=True)
            target_path = os.path.join(target_dir, safe_name)

            counter = 1
            while os.path.exists(target_path):
                name, ext = os.path.splitext(safe_name)
                target_path = os.path.join(target_dir, f"{name}_{counter}{ext}")
                counter += 1

            with zf.open(info) as source, open(target_path, 'wb') as dest:
                shutil.copyfileobj(source, dest)

            sha256_hash = hashlib.sha256()
            with open(target_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256_hash.update(chunk)

            return {
                "name": info.filename,
                "resource_type": resource_type.value,
                "size": info.file_size,
                "path": target_path,
                "sha256": sha256_hash.hexdigest(),
                "mime_type": self._get_mime_type(info.filename)
            }
        except Exception:
            return None

    def _get_mime_type(self, filename: str) -> str:
        """获取MIME类型"""
        ext = os.path.splitext(filename)[1].lower()
        mime_map = {
            '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
            '.gif': 'image/gif', '.webp': 'image/webp', '.bmp': 'image/bmp',
            '.xml': 'application/xml', '.so': 'application/x-sharedlib',
            '.txt': 'text/plain', '.json': 'application/json',
        }
        return mime_map.get(ext, 'application/octet-stream')

    def _calculate_statistics(self, resources: List[Dict]) -> Dict[str, Any]:
        """统计资源信息"""
        stats = {
            "total_count": len(resources),
            "total_size": 0,
            "by_type": {}
        }
        for r in resources:
            rtype = r.get("resource_type", "other")
            stats["by_type"][rtype] = stats["by_type"].get(rtype, 0) + 1
            stats["total_size"] += r.get("size", 0)
        return stats


def main():
    """命令行入口"""
    import argparse
    parser = argparse.ArgumentParser(description="APK资源提取工具")
    parser.add_argument("apk_path", help="APK文件路径")
    parser.add_argument("-o", "--output", help="输出目录")
    parser.add_argument("--json", action="store_true", help="JSON输出")
    args = parser.parse_args()

    extractor = ResourceExtractor()
    result = extractor.extract_all(args.apk_path, args.output)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"资源提取完成!")
        print(f"输出目录: {result['output_dir']}")
        print(f"资源总数: {result['statistics']['total_count']}")
        print(f"总大小: {result['statistics']['total_size']} 字节")


if __name__ == "__main__":
    main()