#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK Analysis Module - Android Reverse Engineering Toolkit

Provides structured APK analysis capabilities:
  - AndroidManifest.xml parsing (permissions, exported components)
  - APK metadata extraction (package, version, SDK targets)
  - Signature information
  - DEX file inventory
  - Security audit (exported components, dangerous permissions)

Usage:
    from apk_analysis import APKAnalyzer

    analyzer = APKAnalyzer()
    result = analyzer.analyze('/path/to/app.apk')
    print(result.to_json())

Requirements:
    - aapt (Android Asset Packaging Tool)
    - apktool (for fallback manifest parsing)
    - unzip (built-in)
    - jarsigner / keytool (for signature verification)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Dangerous Android permissions (API 23+) grouped by risk category
DANGEROUS_PERMISSION_GROUPS: dict[str, list[str]] = {
    "body_sensors": [
        "android.permission.BODY_SENSORS",
        "android.permission.BODY_TEMPERATURE",
    ],
    "calendar": [
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
    ],
    "camera": [
        "android.permission.CAMERA",
    ],
    "contacts": [
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
    ],
    "files_and_media": [
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_MEDIA_LOCATION",
    ],
    "location": [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS-background_LOCATION",
    ],
    "microphone": [
        "android.permission.RECORD_AUDIO",
    ],
    "phone": [
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.USE_SIP",
        "android.permission.PROCESS_OUTGOING_CALLS",
    ],
    "sms": [
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.WRITE_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
    ],
    "storage": [
        "android.permission.MANAGE_EXTERNAL_STORAGE",
    ],
}

# Permissions that are always considered high-risk regardless of API level
ALWAYS_DANGEROUS: list[str] = [
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.WRITE_SMS",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.BODY_SENSORS",
    "android.permission.USE_FINGERPRINT",
    "android.permission.USE_BIOMETRIC",
]

# Component types to audit
COMPONENT_TYPES: list[str] = ["activity", "receiver", "service", "provider"]


# ---------------------------------------------------------------------------
# Data classes for structured output
# ---------------------------------------------------------------------------

@dataclass
class PermissionInfo:
    """Represents a single Android permission declared in the manifest."""
    name: str
    max_sdk: Optional[int] = None
    min_sdk: Optional[int] = None
    is_deprecated: bool = False
    is_dangerous: bool = False
    danger_category: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComponentInfo:
    """Represents a single Android component (Activity/Service/Receiver/Provider)."""
    type: str                    # "activity", "receiver", "service", "provider"
    name: str                    # Full class name
    exported: bool = False       # Whether exported (visible to other apps)
    permission: Optional[str] = None  # Required permission to access
    intent_filters: list[dict[str, Any]] = field(default_factory=list)
    grant_uri_permissions: bool = False
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    protection_level: Optional[str] = None  # For providers

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SignatureInfo:
    """Represents APK signature information."""
    certificate_count: int = 0
    signatures: list[dict[str, Any]] = field(default_factory=list)
    digest_algorithm: Optional[str] = None
    is_signed: bool = False
    signing_certificate: Optional[str] = None  # Base64 SHA-1 of cert

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DexInfo:
    """Represents a single DEX file in the APK."""
    filename: str
    size_bytes: int = 0
    md5: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ApkMetadata:
    """Basic APK metadata extracted from the archive."""
    package_name: str = ""
    version_name: str = ""
    version_code: int = 0
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    compile_sdk: Optional[int] = None
    app_label: Optional[str] = None
    app_icon: Optional[str] = None
    file_size_bytes: int = 0
    file_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditResult:
    """Security audit summary for the APK."""
    dangerous_permissions: list[str] = field(default_factory=list)
    exported_components: list[str] = field(default_factory=list)
    exported_activities: int = 0
    exported_services: int = 0
    exported_receivers: int = 0
    exported_providers: int = 0
    has_intent_filter_without_export: bool = False
    risk_level: str = "low"  # low, medium, high, critical
    risk_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ApkAnalysisResult:
    """Complete structured analysis result."""
    apk_path: str = ""
    metadata: ApkMetadata = field(default_factory=ApkMetadata)
    permissions: list[PermissionInfo] = field(default_factory=list)
    components: list[ComponentInfo] = field(default_factory=list)
    dex_files: list[DexInfo] = field(default_factory=list)
    signature: SignatureInfo = field(default_factory=SignatureInfo)
    audit: AuditResult = field(default_factory=AuditResult)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "apk_path": self.apk_path,
            "metadata": self.metadata.to_dict(),
            "permissions": [p.to_dict() for p in self.permissions],
            "components": [c.to_dict() for c in self.components],
            "dex_files": [d.to_dict() for d in self.dex_files],
            "signature": self.signature.to_dict(),
            "audit": self.audit.to_dict(),
            "errors": self.errors,
            "warnings": self.warnings,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)


# ---------------------------------------------------------------------------
# APKAnalyzer
# ---------------------------------------------------------------------------

class APKAnalyzer:
    """
    Analyzes Android APK files and produces structured security/audit reports.

    Uses system-installed tools (aapt, apktool, unzip, jarsigner) via subprocess
    to extract manifest information, permissions, components, signatures, and
    DEX file inventory. All output is returned as structured dataclasses that
    can be serialized to JSON.

    Example:
        analyzer = APKAnalyzer()
        result = analyzer.analyze('app-release.apk')
        print(result.to_json())
    """

    def __init__(self, temp_dir: Optional[str] = None):
        """
        Initialize the APK analyzer.

        Args:
            temp_dir: Optional working directory for temporary extraction.
                      Defaults to system temp directory.
        """
        self._temp_dir = temp_dir
        self._aapt_path: Optional[str] = None
        self._apktool_path: Optional[str] = None
        self._unzip_path: Optional[str] = None
        self._jarsigner_path: Optional[str] = None
        self._keytool_path: Optional[str] = None
        self._detect_tools()

    # ------------------------------------------------------------------
    # Tool detection
    # ------------------------------------------------------------------

    def _detect_tools(self) -> None:
        """Detect available system tools. Warn if any are missing."""
        self._aapt_path = shutil.which("aapt") or shutil.which("aapt2")
        if not self._aapt_path:
            # aapt not found - will fall back to apktool
            pass

        self._apktool_path = shutil.which("apktool")
        if not self._apktool_path:
            # apktool is the fallback parser; warn if neither is available
            pass

        self._unzip_path = shutil.which("unzip")
        self._jarsigner_path = shutil.which("jarsigner")
        self._keytool_path = shutil.which("keytool")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, apk_path: str) -> ApkAnalysisResult:
        """
        Perform full APK analysis.

        Extracts metadata, permissions, components, signatures, and DEX
        inventory from the given APK file. Returns a structured result.

        Args:
            apk_path: Path to the APK file to analyze.

        Returns:
            ApkAnalysisResult containing all extracted information.

        Raises:
            FileNotFoundError: If the APK file does not exist.
            ValueError: If the file is not a valid APK (not a ZIP archive).
        """
        result = ApkAnalysisResult(apk_path=apk_path)

        # Validate input
        apk_file = Path(apk_path)
        if not apk_file.exists():
            raise FileNotFoundError(
                f"APK file not found: {apk_path}\n"
                f"  → Check the path and try again.\n"
                f"  → If the file was recently moved, update the path."
            )
        if not apk_file.is_file():
            raise ValueError(f"Path is not a file: {apk_path}")

        if not zipfile.is_zipfile(apk_path):
            raise ValueError(
                f"File is not a valid APK (not a ZIP archive): {apk_path}\n"
                f"  → Ensure you're passing an .apk file, not an extracted directory."
            )

        result.metadata.file_size_bytes = apk_file.stat().st_size

        # Extract metadata via aapt dump (fast, no extraction needed)
        result.metadata = self._extract_metadata(aapt_dump=apk_path, result=result)

        # Parse manifest
        manifest_xml = self._dump_manifest_xml(apk_path)
        if manifest_xml:
            result.permissions = self._parse_permissions(manifest_xml)
            result.components = self._parse_components(manifest_xml)
        else:
            result.add_warning(
                "Could not extract AndroidManifest.xml; "
                "permissions and components will be incomplete. "
                "Ensure aapt or apktool is installed."
            )

        # Signature analysis
        result.signature = self._analyze_signature(apk_path)

        # DEX inventory
        result.dex_files = self._list_dex_files(apk_path)

        # Audit summary
        result.audit = self._compute_audit(result)

        return result

    def get_manifest(self, apk_path: str) -> Optional[ET.Element]:
        """
        Extract and parse AndroidManifest.xml from an APK.

        Uses aapt to dump the binary XML, then parses it with ElementTree.

        Args:
            apk_path: Path to the APK file.

        Returns:
            Parsed manifest root element, or None if extraction failed.
        """
        return self._dump_manifest_xml(apk_path)

    def get_permissions(self, apk_path: str) -> list[PermissionInfo]:
        """
        Extract declared permissions from the APK manifest.

        Args:
            apk_path: Path to the APK file.

        Returns:
            List of PermissionInfo objects.
        """
        manifest = self._dump_manifest_xml(apk_path)
        if manifest is None:
            return []
        return self._parse_permissions(manifest)

    def get_components(self, apk_path: str) -> list[ComponentInfo]:
        """
        Extract exported components from the APK manifest.

        Analyzes activities, services, receivers, and providers for
        export status, intent filters, and permission requirements.

        Args:
            apk_path: Path to the APK file.

        Returns:
            List of ComponentInfo objects.
        """
        manifest = self._dump_manifest_xml(apk_path)
        if manifest is None:
            return []
        return self._parse_components(manifest)

    # ------------------------------------------------------------------
    # Metadata extraction
    # ------------------------------------------------------------------

    def _extract_metadata(
        self, aapt_dump: str, result: ApkAnalysisResult
    ) -> ApkMetadata:
        """
        Extract basic APK metadata using aapt dump xmltree.

        Args:
            aapt_dump: Path to the APK file.
            result: The result object to populate warnings on failure.

        Returns:
            ApkMetadata with extracted values.
        """
        meta = ApkMetadata()
        meta.file_size_bytes = result.metadata.file_size_bytes

        if not self._aapt_path:
            result.add_warning(
                "aapt not found; metadata extraction skipped. "
                "Install Android SDK Build Tools or aapt."
            )
            return meta

        try:
            cmd = [
                self._aapt_path,
                "dump",
                "xmltree",
                aapt_dump,
                "AndroidManifest.xml",
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode != 0:
                result.add_warning(
                    f"aapt dump failed (exit {proc.returncode}): "
                    f"{proc.stderr.strip()[:200]}"
                )
                return meta

            output = proc.stdout
            meta = self._parse_aapt_xmltree_output(output, meta)

        except subprocess.TimeoutExpired:
            result.add_warning("aapt dump timed out after 30s")
        except FileNotFoundError:
            result.add_warning("aapt binary not found")
        except Exception as exc:
            result.add_warning(f"Metadata extraction error: {exc}")

        return meta

    def _parse_aapt_xmltree_output(self, output: str, meta: ApkMetadata) -> ApkMetadata:
        """Parse aapt dump xmltree output for package metadata."""
        # Package name
        m = re.search(r'package:"([^"]+)"', output)
        if m:
            meta.package_name = m.group(1)

        # Version name
        m = re.search(r'versionName:"([^"]+)"', output)
        if m:
            meta.version_name = m.group(1)

        # Version code
        m = re.search(r'versionCode:"(\d+)"', output)
        if m:
            meta.version_code = int(m.group(1))

        # SDK versions
        m = re.search(r'minSdkVersion:"(\d+)"', output)
        if m:
            meta.min_sdk = int(m.group(1))

        m = re.search(r'targetSdkVersion:"(\d+)"', output)
        if m:
            meta.target_sdk = int(m.group(1))

        m = re.search(r'compileSdkVersion:"(\d+)"', output)
        if m:
            meta.compile_sdk = int(m.group(1))

        # App label
        m = re.search(r'appLabel:"([^"]+)"', output)
        if m:
            meta.app_label = m.group(1)

        return meta

    # ------------------------------------------------------------------
    # Manifest parsing
    # ------------------------------------------------------------------

    def _dump_manifest_xml(self, apk_path: str) -> Optional[ET.Element]:
        """
        Extract AndroidManifest.xml from the APK and parse it.

        Tries aapt first (fast, no extraction), falls back to apktool.

        Args:
            apk_path: Path to the APK file.

        Returns:
            Parsed manifest root element, or None on failure.
        """
        # Method 1: aapt (preferred - no extraction needed)
        manifest = self._dump_manifest_via_aapt(apk_path)
        if manifest is not None:
            return manifest

        # Method 2: apktool (extracts and decodes)
        manifest = self._dump_manifest_via_apktool(apk_path)
        if manifest is not None:
            return manifest

        return None

    def _dump_manifest_via_aapt(self, apk_path: str) -> Optional[ET.Element]:
        """Use aapt to dump and decode the manifest XML."""
        if not self._aapt_path:
            return None

        try:
            # aapt can dump the binary XML; we need to decode it
            # Use 'aapt dump xmltree' and parse the text output,
            # or use 'aapt decode' to get a proper XML file
            with tempfile.TemporaryDirectory(dir=self._temp_dir) as tmpdir:
                decoded_xml = os.path.join(tmpdir, "AndroidManifest.xml")
                cmd = [
                    self._aapt_path,
                    "decode",
                    "--output-dir",
                    tmpdir,
                    apk_path,
                ]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if proc.returncode != 0:
                    # Fall back to xmltree dump and parse manually
                    return self._parse_aapt_xmltree(apk_path)

                if os.path.exists(decoded_xml):
                    tree = ET.parse(decoded_xml)
                    return tree.getroot()
                else:
                    return self._parse_aapt_xmltree(apk_path)

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None

    def _parse_aapt_xmltree(self, apk_path: str) -> Optional[ET.Element]:
        """Parse aapt xmltree text output into an ElementTree (fallback)."""
        if not self._aapt_path:
            return None

        try:
            cmd = [
                self._aapt_path,
                "dump",
                "xmltree",
                apk_path,
                "AndroidManifest.xml",
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode != 0:
                return None

            # Parse the indented text output into a simple XML structure
            return self._build_element_from_aapt_output(proc.stdout)

        except Exception:
            return None

    def _build_element_from_aapt_output(self, output: str) -> Optional[ET.Element]:
        """
        Build an ElementTree from aapt xmltree text output.

        This is a simplified parser that handles the common manifest structure.
        For complex manifests, prefer apktool.
        """
        try:
            root = ET.Element("manifest")
            current_path: list[ET.Element] = [root]
            indent_level = 0

            for line in output.splitlines():
                stripped = line.rstrip()
                if not stripped:
                    continue

                # Count leading spaces to determine nesting
                leading_spaces = len(line) - len(line.lstrip())
                level = leading_spaces // 2

                # Adjust current path
                while len(current_path) > level + 1:
                    current_path.pop()

                # Extract tag name and attributes
                # Format: '  tag:"value"' or '  tag' or '  tag:{"val1","val2"}'
                content = stripped
                tag_match = re.match(r'^\s*([\w:]+)(?::\s*(.+))?$', content)
                if not tag_match:
                    continue

                tag_name = tag_match.group(1)
                attr_str = tag_match.group(2)

                # Create element
                elem = ET.SubElement(current_path[-1], tag_name)

                # Parse attributes if present
                if attr_str:
                    # Simple attribute parsing: key:"value" pairs
                    attr_pairs = re.findall(r'([\w:]+):"([^"]*)"', attr_str)
                    for key, value in attr_pairs:
                        elem.set(key, value)

                current_path.append(elem)

            return root

        except Exception:
            return None

    def _dump_manifest_via_apktool(self, apk_path: str) -> Optional[ET.Element]:
        """Use apktool to decode the APK and extract the manifest."""
        if not self._apktool_path:
            return None

        try:
            with tempfile.TemporaryDirectory(dir=self._temp_dir) as tmpdir:
                cmd = [
                    self._apktool_path,
                    "decode",
                    "-f",                    # Force overwrite
                    "-o",                    tmpdir,
                    apk_path,
                ]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if proc.returncode != 0:
                    return None

                manifest_path = os.path.join(tmpdir, "AndroidManifest.xml")
                if os.path.exists(manifest_path):
                    tree = ET.parse(manifest_path)
                    return tree.getroot()

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None

        return None

    # ------------------------------------------------------------------
    # Permission parsing
    # ------------------------------------------------------------------

    def _parse_permissions(self, manifest: ET.Element) -> list[PermissionInfo]:
        """
        Parse <uses-permission> elements from the manifest.

        Args:
            manifest: Parsed AndroidManifest.xml root element.

        Returns:
            List of PermissionInfo objects.
        """
        permissions: list[PermissionInfo] = []
        ns = self._get_namespace(manifest)

        for uses_perm in manifest.iter(f"{ns}uses-permission"):
            name = uses_perm.get(f"{ns}name") or uses_perm.get("name")
            if not name:
                continue

            max_sdk = self._safe_int(uses_perm.get(f"{ns}maxSdkVersion"))
            min_sdk = self._safe_int(uses_perm.get(f"{ns}minSdkVersion"))

            perm_info = PermissionInfo(
                name=name,
                max_sdk=max_sdk,
                min_sdk=min_sdk,
                is_deprecated=self._is_deprecated_permission(name),
                is_dangerous=self._is_dangerous_permission(name),
                danger_category=self._get_danger_category(name),
            )
            permissions.append(perm_info)

        return permissions

    def _is_deprecated_permission(self, perm_name: str) -> bool:
        """Check if a permission is deprecated."""
        deprecated = [
            "android.permission.ACCESS_LOCATION",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.BLUETOOTH_ADMIN",
            "android.permission.BLUETOOTH",
            "android.permission.READ_SYNC_SETTINGS",
            "android.permission.WRITE_SYNC_SETTINGS",
            "android.permission.READ_SYNC_STATE",
        ]
        return perm_name in deprecated

    def _is_dangerous_permission(self, perm_name: str) -> bool:
        """Check if a permission is in the dangerous list."""
        if perm_name in ALWAYS_DANGEROUS:
            return True
        for category_perms in DANGEROUS_PERMISSION_GROUPS.values():
            if perm_name in category_perms:
                return True
        return False

    def _get_danger_category(self, perm_name: str) -> Optional[str]:
        """Get the risk category for a dangerous permission."""
        for category, perms in DANGEROUS_PERMISSION_GROUPS.items():
            if perm_name in perms:
                return category
        if perm_name in ALWAYS_DANGEROUS:
            return "high_risk"
        return None

    # ------------------------------------------------------------------
    # Component parsing
    # ------------------------------------------------------------------

    def _parse_components(self, manifest: ET.Element) -> list[ComponentInfo]:
        """
        Parse all components from the manifest.

        Extracts activities, services, receivers, and providers with their
        export status, intent filters, and permission requirements.

        Args:
            manifest: Parsed AndroidManifest.xml root element.

        Returns:
            List of ComponentInfo objects.
        """
        components: list[ComponentInfo] = []
        ns = self._get_namespace(manifest)

        # Parse <activity> and <activity-alias>
        for elem in manifest.iter(f"{ns}activity"):
            comp = self._parse_component(elem, "activity", ns)
            if comp:
                components.append(comp)

        for elem in manifest.iter(f"{ns}activity-alias"):
            comp = self._parse_component(elem, "activity", ns)
            if comp:
                components.append(comp)

        # Parse <receiver>
        for elem in manifest.iter(f"{ns}receiver"):
            comp = self._parse_component(elem, "receiver", ns)
            if comp:
                components.append(comp)

        # Parse <service>
        for elem in manifest.iter(f"{ns}service"):
            comp = self._parse_component(elem, "service", ns)
            if comp:
                components.append(comp)

        # Parse <provider>
        for elem in manifest.iter(f"{ns}provider"):
            comp = self._parse_component(elem, "provider", ns)
            if comp:
                components.append(comp)

        return components

    def _parse_component(
        self, elem: ET.Element, comp_type: str, ns: str
    ) -> Optional[ComponentInfo]:
        """Parse a single component element."""
        name = elem.get(f"{ns}name") or elem.get("name")
        if not name:
            return None

        exported = self._is_exported(elem, ns)
        permission = elem.get(f"{ns}permission") or elem.get("permission")
        intent_filters = self._parse_intent_filters(elem, ns)
        grant_uri = self._parse_bool_attr(elem, f"{ns}grantUriPermissions", ns)
        read_perm = elem.get(f"{ns}readPermission") or elem.get("readPermission")
        write_perm = elem.get(f"{ns}writePermission") or elem.get("writePermission")
        protection = elem.get(f"{ns}protectionLevel") or elem.get("protectionLevel")

        return ComponentInfo(
            type=comp_type,
            name=name,
            exported=exported,
            permission=permission,
            intent_filters=intent_filters,
            grant_uri_permissions=grant_uri,
            read_permission=read_perm,
            write_permission=write_perm,
            protection_level=protection,
        )

    def _is_exported(self, elem: ET.Element, ns: str) -> bool:
        """
        Determine if a component is exported.

        A component is exported if:
          - android:exported="true"
          - It has intent filters (implicit export on older SDKs)
          - android:exported is not set but intent filters exist (pre-API 21 behavior)
        """
        exported_attr = elem.get(f"{ns}exported")
        if exported_attr is not None:
            return self._parse_bool(exported_attr)

        # Check for intent filters (implicit export on older APIs)
        for child in elem:
            tag = self._strip_ns(child.tag, ns)
            if tag == "intent-filter":
                return True  # Pre-API 21: intent filter implies exported

        return False

    def _parse_intent_filters(
        self, elem: ET.Element, ns: str
    ) -> list[dict[str, Any]]:
        """Parse <intent-filter> children of a component."""
        filters: list[dict[str, Any]] = []

        for child in elem:
            tag = self._strip_ns(child.tag, ns)
            if tag != "intent-filter":
                continue

            filt: dict[str, Any] = {
                "actions": [],
                "categories": [],
                "data": [],
            }

            for sub in child:
                sub_tag = self._strip_ns(sub.tag, ns)
                if sub_tag == "action":
                    action_name = sub.get(f"{ns}name") or sub.get("name")
                    if action_name:
                        filt["actions"].append(action_name)
                elif sub_tag == "category":
                    cat_name = sub.get(f"{ns}name") or sub.get("name")
                    if cat_name:
                        filt["categories"].append(cat_name)
                elif sub_tag == "data":
                    data_info: dict[str, Any] = {}
                    for attr in ["scheme", "host", "port", "path", "pathPattern",
                                  "pathPrefix", "mimeType"]:
                        val = sub.get(f"{ns}{attr}") or sub.get(attr)
                        if val:
                            data_info[attr] = val
                    if data_info:
                        filt["data"].append(data_info)

            filters.append(filt)

        return filters

    def _parse_bool_attr(
        self, elem: ET.Element, attr_name: str, ns: str
    ) -> bool:
        """Parse a boolean attribute that may be namespaced."""
        val = elem.get(attr_name)
        if val is not None:
            return self._parse_bool(val)
        return False

    @staticmethod
    def _parse_bool(val: str) -> bool:
        """Parse a boolean string value."""
        return val.lower() in ("true", "1", "yes", "on")

    @staticmethod
    def _strip_ns(tag: str, ns: str) -> str:
        """Strip namespace prefix from a tag name."""
        if ns and tag.startswith(f"{{{ns}}}"):
            return tag[len(f"{{{ns}}}"):].split("}")[-1]
        return tag.split("}")[-1] if "}" in tag else tag

    @staticmethod
    def _get_namespace(manifest: ET.Element) -> str:
        """Extract the Android namespace URI from the manifest."""
        for key, value in ET.register_namespace().items():
            pass  # noop
        # Try to get from manifest tag
        tag = manifest.tag
        if "}" in tag:
            return tag[1:tag.index("}")]
        return ""

    @staticmethod
    def _safe_int(val: Optional[str]) -> Optional[int]:
        """Safely convert a string to int, returning None on failure."""
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    # ------------------------------------------------------------------
    # Signature analysis
    # ------------------------------------------------------------------

    def _analyze_signature(self, apk_path: str) -> SignatureInfo:
        """
        Analyze APK signature using jarsigner.

        Extracts certificate information from the APK signature block.

        Args:
            apk_path: Path to the APK file.

        Returns:
            SignatureInfo with certificate details.
        """
        sig = SignatureInfo()

        if not self._jarsigner_path:
            return sig

        try:
            cmd = [
                self._jarsigner_path,
                "-verify",
                "-verbose",
                "-certs",
                apk_path,
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = proc.stdout + proc.stderr

            # Check if signed
            if "jar is unsigned" in output.lower() or proc.returncode != 0:
                sig.is_signed = False
                return sig

            sig.is_signed = True

            # Count certificates
            cert_count = output.count("Certificate #")
            sig.certificate_count = cert_count if cert_count > 0 else 1

            # Extract certificate details
            for match in re.finditer(
                r'Certificate #(\d+):\s*\n'
                r'.*?Owner: (.*?)\n'
                r'.*?Issuer: (.*?)\n'
                r'.*?Serial number: (.*?)\n'
                r'.*?Certificate fingerprints:\s*\n'
                r'.*?SHA1:\s*"([^"]+)"',
                output,
                re.DOTALL,
            ):
                sig.signatures.append({
                    "certificate_number": int(match.group(1)),
                    "owner": match.group(2).strip(),
                    "issuer": match.group(3).strip(),
                    "serial_number": match.group(4).strip(),
                    "sha1": match.group(5).strip(),
                })

            # Extract digest algorithm
            digest_match = re.search(r'Digest algorithm:\s*(\S+)', output)
            if digest_match:
                sig.digest_algorithm = digest_match.group(1)

            # Get signing certificate SHA-1 (base64)
            if sig.signatures:
                sig.signing_certificate = sig.signatures[0].get("sha1")

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        except Exception:
            pass

        return sig

    # ------------------------------------------------------------------
    # DEX inventory
    # ------------------------------------------------------------------

    def _list_dex_files(self, apk_path: str) -> list[DexInfo]:
        """
        List all DEX files in the APK.

        Args:
            apk_path: Path to the APK file.

        Returns:
            List of DexInfo objects.
        """
        dex_files: list[DexInfo] = []

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for info in zf.infolist():
                    if info.filename.endswith(".dex"):
                        dex_info = DexInfo(
                            filename=info.filename,
                            size_bytes=info.file_size,
                        )
                        dex_files.append(dex_info)

                # Sort by filename for consistent output
                dex_files.sort(key=lambda d: d.filename)

        except zipfile.BadZipFile:
            pass
        except Exception:
            pass

        return dex_files

    # ------------------------------------------------------------------
    # Audit computation
    # ------------------------------------------------------------------

    def _compute_audit(self, result: ApkAnalysisResult) -> AuditResult:
        """
        Compute a security audit summary from the analysis results.

        Args:
            result: The full analysis result.

        Returns:
            AuditResult with risk assessment.
        """
        audit = AuditResult()

        # Collect dangerous permissions
        for perm in result.permissions:
            if perm.is_dangerous:
                audit.dangerous_permissions.append(perm.name)

        # Count exported components by type
        for comp in result.components:
            if comp.exported:
                audit.exported_components.append(comp.name)
                if comp.type == "activity":
                    audit.exported_activities += 1
                elif comp.type == "service":
                    audit.exported_services += 1
                elif comp.type == "receiver":
                    audit.exported_receivers += 1
                elif comp.type == "provider":
                    audit.exported_providers += 1

        # Check for intent filters without explicit export
        for comp in result.components:
            if comp.intent_filters and not any(
                c.exported for c in result.components if c.name == comp.name
            ):
                # This is handled by _is_exported already
                pass

        # Compute risk level
        risk_factors: list[str] = []

        if audit.dangerous_permissions:
            risk_factors.append(
                f"{len(audit.dangerous_permissions)} dangerous permission(s) declared"
            )

        if audit.exported_activities > 0:
            risk_factors.append(
                f"{audit.exported_activities} exported activity(ies)"
            )

        if audit.exported_services > 0:
            risk_factors.append(
                f"{audit.exported_services} exported service(s)"
            )

        if audit.exported_receivers > 0:
            risk_factors.append(
                f"{audit.exported_receivers} exported receiver(s)"
            )

        if audit.exported_providers > 0:
            risk_factors.append(
                f"{audit.exported_providers} exported provider(s)"
            )

        # Check for exported components without permission protection
        unprotected_exported = [
            c for c in result.components
            if c.exported and not c.permission and not c.read_permission
            and not c.write_permission
        ]
        if unprotected_exported:
            risk_factors.append(
                f"{len(unprotected_exported)} exported component(s) "
                f"without permission protection"
            )

        audit.risk_factors = risk_factors

        # Determine overall risk level
        if not risk_factors:
            audit.risk_level = "low"
        elif len(risk_factors) <= 2 and audit.exported_activities == 0:
            audit.risk_level = "medium"
        elif audit.exported_activities > 0 or audit.exported_providers > 0:
            audit.risk_level = "high"
        else:
            audit.risk_level = "medium"

        # Escalate if too many dangerous permissions
        if len(audit.dangerous_permissions) >= 5:
            audit.risk_level = "critical" if audit.risk_level != "high" else "high"

        return audit


# ---------------------------------------------------------------------------
# CLI entry point (for standalone usage)
# ---------------------------------------------------------------------------

def main() -> None:
    """Command-line entry point for APK analysis."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="apk_analysis",
        description="APK Analysis Tool - Extract manifest, permissions, "
                    "components, signatures, and DEX inventory from Android APKs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s app-release.apk
  %(prog)s app-release.apk --output report.json
  %(prog)s app-release.apk --permissions --components --json
        """,
    )
    parser.add_argument(
        "apk_path",
        help="Path to the APK file to analyze",
    )
    parser.add_argument(
        "-o", "--output",
        help="Write JSON output to file (default: stdout)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON (default: pretty-printed JSON)",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Output compact JSON (no indentation)",
    )
    parser.add_argument(
        "--permissions",
        action="store_true",
        help="Only show permissions",
    )
    parser.add_argument(
        "--components",
        action="store_true",
        help="Only show components",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Only show security audit summary",
    )

    args = parser.parse_args()

    try:
        analyzer = APKAnalyzer()
        result = analyzer.analyze(args.apk_path)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(3)
    except Exception as exc:
        print(
            f"Error: Unexpected failure during analysis: {exc}\n"
            f"  → Run with --json for full error details.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Build output
    if args.permissions:
        output_data = [p.to_dict() for p in result.permissions]
    elif args.components:
        output_data = [c.to_dict() for c in result.components]
    elif args.audit:
        output_data = result.audit.to_dict()
    else:
        output_data = result.to_dict()

    indent = None if args.compact else 2
    json_str = json.dumps(output_data, indent=indent, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json_str)
        print(f"Report written to {args.output}")
    else:
        print(json_str)

    # Exit with error code if there were errors
    if result.errors:
        sys.exit(4)


if __name__ == "__main__":
    main()