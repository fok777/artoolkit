#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成科技感 APP 图标
"""

from PIL import Image, ImageDraw, ImageFilter, ImageFont
import os
import math

def create_tech_icon(size=1024, output_path="ic_launcher.png"):
    """创建科技感图标"""
    # 创建图像
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # 背景渐变（深蓝到黑色）
    for i in range(size):
        # 颜色从 (10, 15, 30) 到 (5, 5, 10)
        r = int(10 - 5 * i / size)
        g = int(15 - 10 * i / size)
        b = int(30 - 20 * i / size)
        draw.line([(i, 0), (i, size)], fill=(r, g, b, 255))

    # 绘制网格背景
    grid_color = (20, 30, 50, 100)
    grid_spacing = size // 20
    for i in range(0, size, grid_spacing):
        draw.line([(i, 0), (i, size)], fill=grid_color, width=1)
        draw.line([(0, i), (size, i)], fill=grid_color, width=1)

    # 绘制中心六边形
    center = size // 2
    radius = size * 0.35
    points = []
    for i in range(6):
        angle = math.pi / 6 + i * math.pi / 3  # 从30度开始，使六边形尖端朝上
        x = center + radius * math.cos(angle)
        y = center + radius * math.sin(angle)
        points.append((x, y))

    # 六边形发光效果（多层）
    for offset in range(5, 0, -1):
        alpha = 255 - offset * 40
        color = (0, 200 - offset*30, 255 - offset*50, alpha)
        # 放大一点绘制
        scaled_points = [
            (center + (px - center) * (1 + offset * 0.02),
             center + (py - center) * (1 + offset * 0.02))
            for px, py in points
        ]
        draw.polygon(scaled_points, outline=color, width=2)

    # 填充六边形内部渐变
    inner_points = [
        (center + (px - center) * 0.92,
         center + (py - center) * 0.92)
        for px, py in points
    ]
    # 创建渐变遮罩
    mask = Image.new('L', (size, size), 0)
    mask_draw = ImageDraw.Draw(mask)
    mask_draw.polygon(inner_points, fill=255)
    # 应用径向渐变
    gradient = Image.new('L', (size, size), 0)
    grad_draw = ImageDraw.Draw(gradient)
    for i in range(size):
        dist = math.sqrt((i - center)**2)  # 简化，只沿对角线
        # 实际上我们创建一个从中心向外的渐变
        pass
    # 简化：用纯色填充多边形
    draw.polygon(inner_points, fill=(10, 40, 60, 200))

    # 绘制六边形边框（亮青色）
    draw.polygon(points, outline=(0, 255, 255, 255), width=8)

    # 绘制中心"M"文字
    m_text = "M"
    # 尝试使用较大字体
    font_size = int(size * 0.3)
    try:
        # 尝试加载系统字体
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", font_size)
    except:
        font = ImageFont.load_default()

    # 计算文字位置居中
    bbox = draw.textbbox((0, 0), m_text, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    text_x = center - text_w / 2
    text_y = center - text_h / 2 - size * 0.05

    # 文字发光效果
    for offset_x, offset_y, alpha in [(0,0,255), (2,2,150), (-2,-2,150), (0,4,100), (0,-4,100)]:
        draw.text((text_x + offset_x, text_y + offset_y), m_text,
                  fill=(100, 200, 255, alpha), font=font)

    # 绘制角落装饰线
    corner_size = size * 0.1
    line_width = 4
    # 左上角
    draw.line([(0, 0), (corner_size, 0)], fill=(0, 255, 255, 200), width=line_width)
    draw.line([(0, 0), (0, corner_size)], fill=(0, 255, 255, 200), width=line_width)
    # 右上角
    draw.line([(size, 0), (size - corner_size, 0)], fill=(0, 255, 255, 200), width=line_width)
    draw.line([(size, 0), (size, corner_size)], fill=(0, 255, 255, 200), width=line_width)
    # 左下角
    draw.line([(0, size), (corner_size, size)], fill=(0, 255, 255, 200), width=line_width)
    draw.line([(0, size), (0, size - corner_size)], fill=(0, 255, 255, 200), width=line_width)
    # 右下角
    draw.line([(size, size), (size - corner_size, size)], fill=(0, 255, 255, 200), width=line_width)
    draw.line([(size, size), (size, size - corner_size)], fill=(0, 255, 255, 200), width=line_width)

    # 保存
    img.save(output_path, "PNG")
    print(f"[+] 图标已生成: {output_path} ({size}x{size})")

if __name__ == "__main__":
    import sys
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "/workspace/artoolkit/assets"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "ic_launcher.png")
    create_tech_icon(1024, output_path)

    # 同时生成不同尺寸（用于 Android 适配）
    sizes = {
        "mdpi": 48,
        "hdpi": 72,
        "xhdpi": 96,
        "xxhdpi": 144,
        "xxxhdpi": 192,
    }
    for name, size in sizes.items():
        sub_dir = os.path.join(output_dir, name)
        os.makedirs(sub_dir, exist_ok=True)
        sub_path = os.path.join(sub_dir, "ic_launcher.png")
        # 从1024缩放
        img = Image.open(output_path)
        img = img.resize((size, size), Image.LANCZOS)
        img.save(sub_path, "PNG")
        print(f"[+] 已生成 {name} 图标: {sub_path}")