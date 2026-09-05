#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
artoolkit Android APK 构建器
============================
使用 Python 的 Kivy 框架构建 artoolkit Android APK
支持通过 buildozer 或 p4a 构建
"""

import os
import subprocess
import sys
from pathlib import Path

# 项目根目录
ROOT = Path(__file__).parent.resolve()

# Kivy 应用主文件 - 科技感 UI
KIVY_MAIN = '''# -*- coding: utf-8 -*-
"""
逆向MCP Android 应用主入口
基于 Kivy 框架，科技感 UI，适合新手
"""

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.core.window import Window
from kivy.metrics import dp
from kivy.graphics import Color, Rectangle, RoundedRectangle, Line
import os
import sys
import subprocess
import json

# 添加模块路径
sys.path.insert(0, os.path.dirname(__file__))


# 科技感配色
COLOR_BG = (0.03, 0.03, 0.08, 1)        # 深蓝黑背景
COLOR_PRIMARY = (0, 0.8, 1, 1)           # 青色主色
COLOR_SECONDARY = (0.2, 0.8, 1, 0.3)     # 半透明青
COLOR_CARD = (0.05, 0.05, 0.12, 0.8)     # 卡片背景
COLOR_TEXT = (0.9, 0.95, 1, 1)           # 文字颜色
COLOR_ACCENT = (0, 1, 0.8, 1)            # 强调色


class TechBackground(BoxLayout):
    """科技感背景"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        with self.canvas:
            Color(*COLOR_BG)
            Rectangle(pos=self.pos, size=self.size)
        # 绑定尺寸更新
        self.bind(size=self._update_bg)
        self.bind(pos=self._update_bg)

    def _update_bg(self, instance, value):
        self.canvas.clear()
        with self.canvas:
            Color(*COLOR_BG)
            Rectangle(pos=self.pos, size=self.size)
            # 绘制网格线
            Color(0, 0.5, 0.8, 0.1)
            grid_size = dp(20)
            for x in range(0, int(self.width), int(grid_size)):
                Line(points=[x, 0, x, self.height], width=1)
            for y in range(0, int(self.height), int(grid_size)):
                Line(points=[0, y, self.width, y], width=1)


class ToolCard(BoxLayout):
    """科技感工具卡片"""
    def __init__(self, title, description, icon="🔧", **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.height = dp(120)
        self.padding = dp(10)
        self.spacing = dp(5)

        # 卡片背景
        with self.canvas:
            Color(*COLOR_CARD)
            RoundedRectangle(pos=self.pos, size=self.size, radius=dp(10))
            Color(*COLOR_PRIMARY)
            Line(points=[self.pos[0], self.pos[1], self.pos[0]+self.size[0], self.pos[1]], width=1)
        self.bind(size=self._update_card)
        self.bind(pos=self._update_card)

        # 图标和标题
        title_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=dp(40))
        icon_label = Label(
            text=icon,
            font_size='28sp',
            size_hint_x=None,
            width=dp(50),
            color=COLOR_PRIMARY
        )
        title_label = Label(
            text=title,
            font_size='18sp',
            bold=True,
            color=COLOR_TEXT
        )
        title_layout.add_widget(icon_label)
        title_layout.add_widget(title_label)
        self.add_widget(title_layout)

        # 描述
        desc_label = Label(
            text=description,
            font_size='12sp',
            size_hint_y=None,
            height=dp(35),
            color=(0.7, 0.7, 0.75, 1),
            halign='left',
            valign='top'
        )
        self.add_widget(desc_label)

        # 运行按钮
        run_btn = Button(
            text="运行",
            size_hint_y=None,
            height=dp(40),
            background_color=(0, 0.5, 0.8, 0.8),
            color=(1, 1, 1, 1),
            font_size='14sp'
        )
        run_btn.bind(on_press=self.run_tool)
        self.add_widget(run_btn)

    def _update_card(self, instance, value):
        self.canvas.clear()
        with self.canvas:
            Color(*COLOR_CARD)
            RoundedRectangle(pos=self.pos, size=self.size, radius=dp(10))
            Color(*COLOR_PRIMARY)
            Line(points=[self.pos[0], self.pos[1], self.pos[0]+self.size[0], self.pos[1]], width=1)

    def run_tool(self, instance):
        """运行工具"""
        app = App.get_running_app()
        app.show_output(f"运行工具: {self.children[2].text}")


class OutputArea(ScrollView):
    """科技感输出区域"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.label = Label(
            text="准备就绪...",
            font_size='12sp',
            size_hint_y=None,
            text_size=(self.width, None),
            halign='left',
            valign='top',
            color=(0.8, 0.9, 1, 1)
        )
        self.label.bind(size=self._update_text_size)
        self.add_widget(self.label)

    def _update_text_size(self, instance, value):
        self.label.text_size = (self.width, None)

    def append_text(self, text):
        """追加文本"""
        self.label.text += f"\n{text}"
        self.scroll_to(self.label)


class ReverseMCPApp(App):
    """逆向MCP 应用"""

    def __init__(self):
        super().__init__()
        self.title = "逆向MCP - 安卓逆向工具箱"

    def build(self):
        # 设置窗口大小
        Window.size = (400, 650)
        Window.minimum_width = 350
        Window.minimum_height = 550
        Window.background_color = COLOR_BG

        layout = BoxLayout(
            orientation='vertical',
            spacing=dp(10),
            padding=dp(10)
        )

        # 顶部标题
        title_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=dp(60))
        title_label = Label(
            text="🔧 逆向MCP",
            font_size='28sp',
            bold=True,
            color=COLOR_PRIMARY,
            halign='left',
            valign='center'
        )
        # 添加发光效果
        with title_label.canvas:
            Color(*COLOR_SECONDARY)
            Rectangle(pos=title_label.pos, size=title_label.size)
        title_layout.add_widget(title_label)
        layout.add_widget(title_layout)

        # 工具列表区域
        tools_scroll = ScrollView()
        tools_layout = BoxLayout(
            orientation='vertical',
            spacing=dp(10),
            size_hint_y=None
        )

        tools = [
            ("APK 分析", "分析 APK 基本信息、权限、组件", "📦"),
            ("加密检测", "检测加密算法和硬编码密钥", "🔐"),
            ("加固检测", "检测 APK 加固方案", "🛡️"),
            ("Frida 脚本", "生成 Hook/Trace/Intercept 脚本", "🪝"),
            ("SO 分析", "分析 SO 文件架构和符号", "📄"),
            ("资源提取", "提取 APK 中的图片、布局等资源", "📦"),
            ("字符串解密", "XOR/Base64/RC4 解密", "🔓"),
            ("项目管理", "创建和管理逆向项目", "📋"),
        ]

        for title, desc, icon in tools:
            card = ToolCard(title, desc, icon)
            tools_layout.add_widget(card)

        tools_layout.height = dp(len(tools) * 130)
        tools_scroll.add_widget(tools_layout)
        layout.add_widget(tools_scroll)

        # 输出区域
        self.output = OutputArea()
        layout.add_widget(self.output)

        # 底部按钮
        btn_layout = BoxLayout(
            size_hint_y=None,
            height=dp(50),
            spacing=dp(10)
        )

        clear_btn = Button(
            text="清空输出",
            background_color=(0.3, 0.3, 0.35, 1),
            color=(1, 1, 1, 1)
        )
        clear_btn.bind(on_press=self.clear_output)
        btn_layout.add_widget(clear_btn)

        exit_btn = Button(
            text="退出应用",
            background_color=(0.6, 0.2, 0.2, 1),
            color=(1, 1, 1, 1)
        )
        exit_btn.bind(on_press=self.stop)
        btn_layout.add_widget(exit_btn)

        layout.add_widget(btn_layout)

        return layout

    def show_output(self, text):
        """显示输出"""
        self.output.append_text(text)

    def clear_output(self, instance):
        """清空输出"""
        self.output.label.text = "准备就绪..."


if __name__ == '__main__':
    ReverseMCPApp().run()
'''


def create_kivy_project(output_dir: str = "./kivy_build"):
    """创建 Kivy 项目"""
    project_dir = Path(output_dir)
    project_dir.mkdir(parents=True, exist_ok=True)

    # 创建 main.py
    main_path = project_dir / "main.py"
    main_path.write_text(KIVY_MAIN, encoding='utf-8')

    # 创建 buildozer.spec
    spec_content = """[app]
title = 逆向MCP
package.name = mcp.reverse
package.domain = org.mcp.reverse
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0.0
description = Android Reverse Engineering Toolkit
author.name = artoolkit
author.email = artoolkit@example.com
orientation = all
android.api = 34
android.min_api = 21
android.sdk = 34
android.ndk = 25b
android.build_tools = 34.0.0
p4a.source.symlinks = True
requirements = python3,kivy
android.add_src = $(src.dir)
android.add_assets = assets
android.add_native_libraries = armeabi-v7a,arm64-v8a
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE
android.manifest.orientation = all
android.icon = assets/ic_launcher.png
"""
    spec_path = project_dir / "buildozer.spec"
    spec_path.write_text(spec_content, encoding='utf-8')

    # 复制模块
    modules_dir = project_dir / "modules"
    modules_dir.mkdir(exist_ok=True)
    src_modules = ROOT / "modules"
    if src_modules.exists():
        import shutil
        for f in src_modules.glob("*.py"):
            shutil.copy(f, modules_dir / f.name)

    # 复制主 CLI
    cli_path = project_dir / "artoolkit.py"
    if (ROOT / "artoolkit.py").exists():
        import shutil
        shutil.copy(ROOT / "artoolkit.py", cli_path)

    # 复制图标资源
    assets_dir = project_dir / "assets"
    assets_dir.mkdir(exist_ok=True)
    src_assets = ROOT / "assets"
    if src_assets.exists():
        import shutil
        # 复制所有图标文件
        for f in src_assets.rglob("*.png"):
            dest = assets_dir / f.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(f, dest)

    print(f"[+] Kivy 项目已创建: {project_dir}")
    print(f"  主文件: {main_path}")
    print(f"  配置: {spec_path}")
    print(f"  模块: {modules_dir}")

    return project_dir


def build_with_buildozer(project_dir: str):
    """使用 buildozer 构建"""
    print("[*] 开始 buildozer 构建...")
    result = subprocess.run(
        ["buildozer", "-v", "android", "debug"],
        cwd=project_dir,
        capture_output=True,
        text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print("[-] 构建失败:")
        print(result.stderr)
    return result.returncode == 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description="artoolkit APK 构建器")
    parser.add_argument("--output", default="./kivy_build", help="输出目录")
    parser.add_argument("--build", action="store_true", help="构建 APK")
    args = parser.parse_args()

    project_dir = create_kivy_project(args.output)

    if args.build:
        if build_with_buildozer(str(project_dir)):
            print("[+] APK 构建成功!")
        else:
            print("[-] APK 构建失败")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())