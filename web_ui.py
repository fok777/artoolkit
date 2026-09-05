#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
artoolkit Web UI - 基于 Web 界面的逆向工具箱包装器
===================================================
在 Android 设备上通过浏览器访问 http://localhost:8080 使用图形界面
支持 Termux 环境
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# 确保模块可导入
sys.path.insert(0, str(Path(__file__).parent))

from modules.apk_analysis import APKAnalyzer
from modules.crypto_detect import CryptoDetector
from modules.frida_gen import FridaGenerator
from modules.shell_detect import ShellDetector
from modules.so_analysis import SOAnalyzer
from modules.resource_extract import ResourceExtractor
from modules.project_manager import ProjectManager
from modules.session_manager import SessionManager

# 全局工具实例
apk_analyzer = APKAnalyzer()
crypto_detector = CryptoDetector()
frida_gen = FridaGenerator()
shell_detector = ShellDetector()
so_analyzer = SOAnalyzer()
resource_extractor = ResourceExtractor()
project_mgr = ProjectManager()
session_mgr = SessionManager()

# HTML 模板
HTML_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>artoolkit - Android 逆向工具箱</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
.header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 20px; text-align: center; border-bottom: 2px solid #00d9ff; }
.header h1 { color: #00d9ff; font-size: 28px; margin-bottom: 5px; }
.header p { color: #8b949e; font-size: 14px; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 20px; transition: border-color 0.3s; }
.card:hover { border-color: #00d9ff; }
.card h3 { color: #00d9ff; margin-bottom: 10px; font-size: 18px; }
.card p { color: #8b949e; font-size: 13px; margin-bottom: 15px; }
.card .btn { display: inline-block; background: #00d9ff; color: #0d1117; padding: 8px 16px; border-radius: 6px; text-decoration: none; font-size: 14px; font-weight: bold; margin-right: 8px; margin-bottom: 8px; }
.card .btn.secondary { background: transparent; border: 1px solid #00d9ff; color: #00d9ff; }
.input-group { margin-bottom: 15px; }
.input-group label { display: block; margin-bottom: 5px; font-size: 14px; color: #c9d1d9; }
.input-group input, .input-group select { width: 100%; padding: 10px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 14px; }
.input-group input:focus { outline: none; border-color: #00d9ff; }
.form-group { margin-bottom: 20px; }
button { background: #00d9ff; color: #0d1117; border: none; padding: 12px 24px; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; }
button:hover { background: #00b8cc; }
.result { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 15px; margin-top: 15px; white-space: pre-wrap; font-family: monospace; font-size: 13px; max-height: 400px; overflow-y: auto; }
.nav { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
.nav a { color: #00d9ff; text-decoration: none; padding: 8px 16px; background: #161b22; border-radius: 6px; font-size: 14px; }
.nav a.active { background: #00d9ff; color: #0d1117; }
.footer { text-align: center; padding: 20px; color: #8b949e; font-size: 12px; border-top: 1px solid #30363d; margin-top: 40px; }
</style>
</head>
<body>
<div class="header">
    <h1>🔧 artoolkit</h1>
    <p>Android Reverse Engineering Toolkit v1.0.0</p>
</div>
<div class="container">
    <div class="nav">
        <a href="/" class="active">首页</a>
        <a href="/apk">APK 分析</a>
        <a href="/crypto">加密检测</a>
        <a href="/shell">加固检测</a>
        <a href="/frida">Frida 脚本</a>
        <a href="/so">SO 分析</a>
        <a href="/resource">资源提取</a>
        <a href="/project">项目管理</a>
    </div>
    <div id="content">
        {CONTENT}
    </div>
</div>
<div class="footer">
    <p>artoolkit v1.0.0 | Built with ❤️ for Android Reverse Engineering</p>
    <p>运行在: {PYTHON_VERSION} | 工具: {TOOLS_STATUS}</p>
</div>
</body>
</html>"""

HOMEPAGE = """
<div class="grid">
    <div class="card">
        <h3>📦 APK 分析</h3>
        <p>分析 APK 基本信息、权限、组件、签名等</p>
        <a href="/apk" class="btn">开始分析</a>
    </div>
    <div class="card">
        <h3>🔐 加密检测</h3>
        <p>检测 APK 中的加密算法、硬编码密钥、加密库</p>
        <a href="/crypto" class="btn">开始检测</a>
    </div>
    <div class="card">
        <h3>🛡️ 加固检测</h3>
        <p>检测 APK 加固方案（360、腾讯、百度等 19 种）</p>
        <a href="/shell" class="btn">开始检测</a>
    </div>
    <div class="card">
        <h3>🪝 Frida 脚本</h3>
        <p>生成 Hook、Trace、Intercept 等 Frida 脚本</p>
        <a href="/frida" class="btn">生成脚本</a>
    </div>
    <div class="card">
        <h3>📄 SO 分析</h3>
        <p>分析 SO 文件架构、符号、字符串、Unity 检测</p>
        <a href="/so" class="btn">开始分析</a>
    </div>
    <div class="card">
        <h3>📦 资源提取</h3>
        <p>提取 APK 中的图片、布局、原生库、字符串等资源</p>
        <a href="/resource" class="btn">提取资源</a>
    </div>
    <div class="card">
        <h3>📋 项目管理</h3>
        <p>创建、切换、删除逆向工程项目</p>
        <a href="/project" class="btn">管理项目</a>
    </div>
    <div class="card">
        <h3>🔍 综合分析</h3>
        <p>一键完整分析 APK（加固+加密+网络+SO）</p>
        <a href="/analyze" class="btn">综合分析</a>
    </div>
</div>
"""

APK_FORM = """
<div class="card">
    <h3>📦 APK 分析</h3>
    <form method="POST" action="/apk">
        <div class="input-group">
            <label>APK 文件路径:</label>
            <input type="text" name="apk_path" placeholder="/storage/emulated/0/app.apk" required>
        </div>
        <div class="input-group">
            <label>分析类型:</label>
            <select name="action">
                <option value="info">基本信息</option>
                <option value="manifest">Manifest 清单</option>
                <option value="permissions">权限列表</option>
            </select>
        </div>
        <button type="submit">开始分析</button>
    </form>
    <div id="result" class="result" style="display:none;"></div>
</div>
"""

CRYPTO_FORM = """
<div class="card">
    <h3>🔐 加密检测</h3>
    <form method="POST" action="/crypto">
        <div class="input-group">
            <label>目标文件 (APK 或 SO):</label>
            <input type="text" name="target" placeholder="/storage/emulated/0/app.apk" required>
        </div>
        <div class="input-group">
            <label>检测类型:</label>
            <select name="action">
                <option value="detect">加密算法检测</option>
                <option value="keys">硬编码密钥提取</option>
                <option value="libs">加密库检测</option>
            </select>
        </div>
        <button type="submit">开始检测</button>
    </form>
    <div id="result" class="result" style="display:none;"></div>
</div>
"""

SHELL_FORM = """
<div class="card">
    <h3>🛡️ 加固检测</h3>
    <form method="POST" action="/shell">
        <div class="input-group">
            <label>APK 文件路径:</label>
            <input type="text" name="apk_path" placeholder="/storage/emulated/0/app.apk" required>
        </div>
        <div class="input-group">
            <label>检测类型:</label>
            <select name="action">
                <option value="detect">加固方案检测</option>
                <option value="dex">DEX 完整性检查</option>
                <option value="frida">生成 Frida Dump 脚本</option>
            </select>
        </div>
        <button type="submit">开始检测</button>
    </form>
    <div id="result" class="result" style="display:none;"></div>
</div>
"""

FRIDA_FORM = """
<div class="card">
    <h3>🪝 Frida 脚本生成</h3>
    <form method="POST" action="/frida">
        <div class="input-group">
            <label>类名:</label>
            <input type="text" name="class_name" placeholder="com.example.Main" required>
        </div>
        <div class="input-group">
            <label>方法名:</label>
            <input type="text" name="method" placeholder="onCreate">
        </div>
        <div class="input-group">
            <label>脚本类型:</label>
            <select name="type">
                <option value="hook">Hook 函数</option>
                <option value="trace">Trace 追踪</option>
                <option value="intercept">Intercept 拦截</option>
                <option value="rpc">RPC 桩</option>
                <option value="memory">内存搜索</option>
            </select>
        </div>
        <button type="submit">生成脚本</button>
    </form>
    <div id="result" class="result" style="display:none;"></div>
</div>
"""

SO_FORM = """
<div class="card">
    <h3>📄 SO 分析</h3>
    <form method="POST" action="/so">
        <div class="input-group">
            <label>SO 文件路径:</label>
            <input type="text" name="so_path" placeholder="/data/app/libnative.so" required>
        </div>
        <div class="input-group">
            <label>分析类型:</label>
            <select name="action">
                <option value="info">基本信息</option>
                <option value="strings">字符串提取</option>
                <option value="unity">Unity 检测</option>
                <option value="symbols">符号提取</option>
            </select>
        </div>
        <button type="submit">开始分析</button>
    </form>
    <div id="result" class="result" style="display:none;"></div>
</div>
"""

RESOURCE_FORM = """
<div class="card">
    <h3>📦 资源提取</h3>
    <form method="POST" action="/resource">
        <div class="input-group">
            <label>APK 文件路径:</label>
            <input type="text" name="apk_path" placeholder="/storage/emulated/0/app.apk" required>
        </div>
        <div class="input-group">
            <label>输出目录:</label>
            <input type="text" name="dest" placeholder="./resources" required>
        </div>
        <button type="submit">开始提取</button>
    </form>
    <div id="result" class="result" style="display:none;"></div>
</div>
"""

PROJECT_FORM = """
<div class="card">
    <h3>📋 项目管理</h3>
    <form method="POST" action="/project">
        <div class="input-group">
            <label>操作:</label>
            <select name="action" onchange="showProjectForm(this.value)">
                <option value="create">创建项目</option>
                <option value="list">列出项目</option>
            </select>
        </div>
        <div id="create_form">
            <div class="input-group">
                <label>项目名:</label>
                <input type="text" name="name" placeholder="my-project">
            </div>
            <div class="input-group">
                <label>描述:</label>
                <input type="text" name="description" placeholder="项目描述">
            </div>
        </div>
        <button type="submit">执行</button>
    </form>
    <div id="result" class="result" style="display:none;"></div>
</div>
<script>
function showProjectForm(val) {
    document.getElementById('create_form').style.display = val === 'create' ? 'block' : 'none';
}
</script>
"""


class WebHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器"""

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "/home":
            self.serve_page(HOMEPAGE)
        elif path == "/apk":
            self.serve_page(APK_FORM)
        elif path == "/crypto":
            self.serve_page(CRYPTO_FORM)
        elif path == "/shell":
            self.serve_page(SHELL_FORM)
        elif path == "/frida":
            self.serve_page(FRIDA_FORM)
        elif path == "/so":
            self.serve_page(SO_FORM)
        elif path == "/resource":
            self.serve_page(RESOURCE_FORM)
        elif path == "/project":
            self.serve_page(PROJECT_FORM)
        elif path == "/analyze":
            self.serve_page("""
            <div class="card">
                <h3>🔍 综合分析</h3>
                <form method="POST" action="/analyze">
                    <div class="input-group">
                        <label>APK 文件路径:</label>
                        <input type="text" name="apk_path" placeholder="/storage/emulated/0/app.apk" required>
                    </div>
                    <button type="submit">开始综合分析</button>
                </form>
                <div id="result" class="result" style="display:none;"></div>
            </div>
            """)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        path = urlparse(self.path).path
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(body)

        result = ""
        if path == "/apk":
            result = self.handle_apk(params)
        elif path == "/crypto":
            result = self.handle_crypto(params)
        elif path == "/shell":
            result = self.handle_shell(params)
        elif path == "/frida":
            result = self.handle_frida(params)
        elif path == "/so":
            result = self.handle_so(params)
        elif path == "/resource":
            result = self.handle_resource(params)
        elif path == "/project":
            result = self.handle_project(params)
        elif path == "/analyze":
            result = self.handle_analyze(params)
        else:
            result = "未知操作"

        # 返回带结果的页面
        page = self.get_current_page(path)
        html = HTML_PAGE.replace("{CONTENT}", page.replace(
            '<div id="result" class="result" style="display:none;"></div>',
            f'<div id="result" class="result">{result}</div>'
        ))
        self.serve_raw(html)

    def handle_apk(self, params):
        apk_path = params.get("apk_path", [""])[0]
        action = params.get("action", ["info"])[0]
        if not os.path.exists(apk_path):
            return f"❌ 文件不存在: {apk_path}"
        try:
            if action == "info":
                result = apk_analyzer.analyze(apk_path)
                d = result.to_dict()
                meta = d.get("metadata", {})
                lines = [
                    f"📦 APK 信息",
                    f"  包名: {meta.get('package_name', 'N/A')}",
                    f"  版本: {meta.get('version_name', 'N/A')} (v{meta.get('version_code', 'N/A')})",
                    f"  最低 SDK: Android {meta.get('min_sdk', 'N/A')}",
                    f"  目标 SDK: Android {meta.get('target_sdk', 'N/A')}",
                    f"  文件大小: {os.path.getsize(apk_path) / 1024:.1f} KB",
                    "",
                    f"📋 权限 ({len(d.get('permissions', []))}):",
                ]
                for p in d.get("permissions", []):
                    lines.append(f"  - {p.get('name', 'N/A')}")
                return "\n".join(lines)
            elif action == "manifest":
                manifest = apk_analyzer.get_manifest(apk_path)
                import xml.etree.ElementTree as ET
                return ET.tostring(manifest, encoding='unicode')
            elif action == "permissions":
                perms = apk_analyzer.get_permissions(apk_path)
                lines = [f"📋 权限列表 ({len(perms)}):"]
                for p in perms:
                    lines.append(f"  - {p.name}")
                return "\n".join(lines)
        except Exception as e:
            return f"❌ 错误: {e}"
        return ""

    def handle_crypto(self, params):
        target = params.get("target", [""])[0]
        action = params.get("action", ["detect"])[0]
        if not os.path.exists(target):
            return f"❌ 文件不存在: {target}"
        try:
            if action == "detect":
                result = crypto_detector.detect_algorithms(target)
                algos = result.get("algorithms", [])
                lines = ["🔐 加密算法检测:"]
                if algos:
                    for a in algos:
                        lines.append(f"  - {a.get('name')}: {a.get('risk')} ({a.get('count', 0)} 处)")
                else:
                    lines.append("  未检测到已知加密算法")
                return "\n".join(lines)
            elif action == "keys":
                result = crypto_detector.extract_keys(target)
                keys = result.get("keys", [])
                lines = [f"🔑 硬编码密钥 ({len(keys)}):"]
                for k in keys:
                    lines.append(f"  - {k.get('type', 'Unknown')}: {k.get('value', '')[:40]}...")
                return "\n".join(lines)
            elif action == "libs":
                result = crypto_detector.detect_crypto_libraries(target)
                libs = result.get("libraries", [])
                lines = [f"📚 加密库 ({len(libs)}):"]
                for lib in libs:
                    lines.append(f"  - {lib.get('name')}: {lib.get('confidence')}")
                return "\n".join(lines)
        except Exception as e:
            return f"❌ 错误: {e}"
        return ""

    def handle_shell(self, params):
        apk_path = params.get("apk_path", [""])[0]
        action = params.get("action", ["detect"])[0]
        if not os.path.exists(apk_path):
            return f"❌ 文件不存在: {apk_path}"
        try:
            if action == "detect":
                result = shell_detector.analyze_all(apk_path)
                shells = result.get("shells", [])
                lines = ["🛡️ 加固检测结果:"]
                if shells:
                    for s in shells:
                        lines.append(f"  - {s.get('name')}: 置信度 {s.get('confidence')}")
                else:
                    lines.append("  未检测到常见加固方案")
                return "\n".join(lines)
            elif action == "dex":
                result = shell_detector.check_dex_integrity(apk_path)
                issues = result.get("issues", [])
                lines = ["📄 DEX 完整性检查:"]
                if issues:
                    for i in issues:
                        lines.append(f"  - {i.get('type')}: {i.get('description')}")
                else:
                    lines.append("  DEX 文件完整")
                return "\n".join(lines)
            elif action == "frida":
                script = shell_detector.generate_dump_script(apk_path)
                return f"✅ Frida Dump 脚本已生成:\n\n{script[:500]}..."
        except Exception as e:
            return f"❌ 错误: {e}"
        return ""

    def handle_frida(self, params):
        cls = params.get("class_name", [""])[0]
        method = params.get("method", [""])[0]
        gen_type = params.get("type", ["hook"])[0]
        try:
            if gen_type == "hook":
                script = frida_gen.generate_hook_function(cls, method)
            elif gen_type == "trace":
                script = frida_gen.generate_hook_class(cls, method)
            elif gen_type == "intercept":
                script = frida_gen.generate_hook_function(cls, method, intercept=True)
            elif gen_type == "rpc":
                script = frida_gen.generate_rpc_stub()
            elif gen_type == "memory":
                script = frida_gen.generate_memory_search()
            else:
                return f"❌ 未知类型: {gen_type}"
            return f"✅ Frida 脚本已生成:\n\n{script[:800]}..."
        except Exception as e:
            return f"❌ 错误: {e}"

    def handle_so(self, params):
        so_path = params.get("so_path", [""])[0]
        action = params.get("action", ["info"])[0]
        if not os.path.exists(so_path):
            return f"❌ 文件不存在: {so_path}"
        try:
            if action == "info":
                result = so_analyzer.analyze(so_path)
                info = result.get("file_info", {})
                lines = [
                    "📄 SO 文件信息:",
                    f"  架构: {info.get('architecture', 'N/A')}",
                    f"  类型: {info.get('file_type', 'N/A')}",
                    f"  大小: {info.get('size', 0) / 1024:.1f} KB",
                ]
                return "\n".join(lines)
            elif action == "strings":
                result = so_analyzer.extract_strings(so_path)
                strings = result.get("strings", [])
                lines = [f"📄 SO 字符串 ({len(strings)}):"]
                for s in strings[:20]:
                    lines.append(f"  - {s}")
                return "\n".join(lines)
            elif action == "unity":
                result = so_analyzer.detect_unity(so_path)
                if result.get("is_unity"):
                    lines = ["🎮 是 Unity 工程"]
                    symbols = result.get("il2cpp_symbols", [])
                    lines.append(f"  Il2CPP 符号: {len(symbols)} 个")
                    return "\n".join(lines)
                return "❌ 非 Unity 工程"
            elif action == "symbols":
                result = so_analyzer.extract_il2cpp_symbols(so_path)
                symbols = result if isinstance(result, list) else result.get("symbols", [])
                lines = [f"📄 函数符号 ({len(symbols)}):"]
                for s in symbols[:20]:
                    lines.append(f"  - {s}")
                return "\n".join(lines)
        except Exception as e:
            return f"❌ 错误: {e}"
        return ""

    def handle_resource(self, params):
        apk_path = params.get("apk_path", [""])[0]
        dest = params.get("dest", ["./resources"])[0]
        if not os.path.exists(apk_path):
            return f"❌ 文件不存在: {apk_path}"
        try:
            result = resource_extractor.extract_all(apk_path, dest)
            stats = result.get("statistics", {})
            lines = [f"📦 资源提取完成:"]
            lines.append(f"  输出目录: {dest}")
            for k, v in stats.items():
                lines.append(f"  {k}: {v}")
            return "\n".join(lines)
        except Exception as e:
            return f"❌ 错误: {e}"

    def handle_project(self, params):
        action = params.get("action", ["list"])[0]
        try:
            if action == "create":
                name = params.get("name", [""])[0]
                desc = params.get("description", [""])[0]
                if not name:
                    return "❌ 请输入项目名"
                result = project_mgr.create(name, desc)
                return f"✅ 项目已创建: {name}"
            elif action == "list":
                projects = project_mgr.list_projects()
                lines = ["📋 项目列表:"]
                if not projects:
                    lines.append("  (无项目)")
                for p in projects:
                    lines.append(f"  - {p.get('name')}: {p.get('description', '')}")
                return "\n".join(lines)
        except Exception as e:
            return f"❌ 错误: {e}"
        return ""

    def handle_analyze(self, params):
        apk_path = params.get("apk_path", [""])[0]
        if not os.path.exists(apk_path):
            return f"❌ 文件不存在: {apk_path}"
        lines = [f"🔍 综合分析: {apk_path}", ""]
        try:
            # APK 信息
            lines.append("📦 APK 信息:")
            apk_result = apk_analyzer.analyze(apk_path)
            meta = apk_result.metadata
            lines.append(f"  包名: {meta.package_name}")
            lines.append(f"  版本: {meta.version_name} (v{meta.version_code})")
            lines.append("")
            # 加固检测
            lines.append("🛡️ 加固检测:")
            shell_result = shell_detector.analyze_all(apk_path)
            shells = shell_result.get("shells", [])
            if shells:
                for s in shells:
                    lines.append(f"  - {s.get('name')}: {s.get('confidence')}")
            else:
                lines.append("  未检测到常见加固")
            lines.append("")
            # 加密检测
            lines.append("🔐 加密检测:")
            crypto_result = crypto_detector.detect_algorithms(apk_path)
            algos = crypto_result.get("algorithms", [])
            if algos:
                for a in algos:
                    lines.append(f"  - {a.get('name')}: {a.get('risk')}")
            else:
                lines.append("  未检测到已知加密算法")
            lines.append("")
            lines.append("=" * 40)
            lines.append("✅ 分析完成")
        except Exception as e:
            lines.append(f"❌ 错误: {e}")
        return "\n".join(lines)

    def get_current_page(self, path):
        """获取当前页面对应的 HTML 片段"""
        pages = {
            "/apk": APK_FORM,
            "/crypto": CRYPTO_FORM,
            "/shell": SHELL_FORM,
            "/frida": FRIDA_FORM,
            "/so": SO_FORM,
            "/resource": RESOURCE_FORM,
            "/project": PROJECT_FORM,
            "/analyze": """
            <div class="card">
                <h3>🔍 综合分析</h3>
                <form method="POST" action="/analyze">
                    <div class="input-group">
                        <label>APK 文件路径:</label>
                        <input type="text" name="apk_path" placeholder="/storage/emulated/0/app.apk" required>
                    </div>
                    <button type="submit">开始综合分析</button>
                </form>
                <div id="result" class="result" style="display:none;"></div>
            </div>
            """,
        }
        return pages.get(path, HOMEPAGE)

    def serve_page(self, content):
        """服务 HTML 页面"""
        html = HTML_PAGE.replace("{CONTENT}", content)
        self.serve_raw(html)

    def serve_raw(self, html):
        """发送原始 HTML"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def log_message(self, format, *args):
        """自定义日志"""
        print(f"[Web] {args[0]}")


def get_tools_status():
    """获取工具状态摘要"""
    tools = ["aapt", "apktool", "baksmali", "java", "node", "strings"]
    status = []
    for t in tools:
        available = subprocess.run(["which", t], capture_output=True).returncode == 0
        status.append(f"{t}:{'✓' if available else '✗'}")
    return " ".join(status)


def run_web_ui(host="0.0.0.0", port=8080):
    """启动 Web UI"""
    server = HTTPServer((host, port), WebHandler)
    print(f"""
╔══════════════════════════════════════════════════════╗
║         artoolkit Web UI v1.0.0                      ║
╠══════════════════════════════════════════════════════╣
║  在浏览器中访问:                                      ║
║  http://localhost:{port}                               ║
║  http://127.0.0.1:{port}                               ║
╠══════════════════════════════════════════════════════╣
║  按 Ctrl+C 停止服务                                  ║
╚══════════════════════════════════════════════════════╝
    """)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Web UI 已停止")
        server.shutdown()


def main():
    parser = argparse.ArgumentParser(
        description="artoolkit Web UI - Android 逆向工具箱 Web 界面"
    )
    parser.add_argument("--host", default="0.0.0.0", help="监听地址")
    parser.add_argument("--port", type=int, default=8080, help="监听端口")
    args = parser.parse_args()

    # 设置 Python 版本信息
    global HTML_PAGE
    import platform
    HTML_PAGE = HTML_PAGE.replace("{PYTHON_VERSION}", platform.python_version())
    HTML_PAGE = HTML_PAGE.replace("{TOOLS_STATUS}", get_tools_status())

    run_web_ui(args.host, args.port)


if __name__ == "__main__":
    main()