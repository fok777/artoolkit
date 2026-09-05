#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
项目管理模块 - Project Manager Module

提供项目创建、列出、切换、删除和信息查询功能。
使用纯Python标准库 + JSON存储项目元数据。

项目结构：
    projects/
        <project_name>/
            apk/        - APK文件存储目录
            output/     - 分析输出目录
            config/     - 配置文件目录
            meta.json   - 项目元数据文件
"""

import os
import json
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any


class ProjectManager:
    """
    项目管理类，负责项目的全生命周期管理。

    Attributes:
        base_dir (str): 项目根目录路径
        projects_dir (str): 项目存储目录
        current_project (str): 当前活动项目名称
    """

    def __init__(self, base_dir: str = "/root/artoolkit"):
        """
        初始化项目管理器。

        Args:
            base_dir: 基础目录路径，默认为 /root/artoolkit
        """
        self.base_dir = base_dir
        self.projects_dir = os.path.join(base_dir, "projects")
        self._ensure_projects_dir()
        self.current_project = self._load_current_project()

    def _ensure_projects_dir(self) -> None:
        """确保项目目录存在。"""
        if not os.path.exists(self.projects_dir):
            os.makedirs(self.projects_dir, exist_ok=True)

    def _load_current_project(self) -> Optional[str]:
        """从文件加载当前活动项目名称。"""
        current_file = os.path.join(self.base_dir, ".current_project")
        if os.path.exists(current_file):
            try:
                with open(current_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    project_name = data.get("current_project")
                    if project_name and self._project_exists(project_name):
                        return project_name
            except (json.JSONDecodeError, IOError):
                pass
        return None

    def _save_current_project(self) -> None:
        """保存当前活动项目名称到文件。"""
        current_file = os.path.join(self.base_dir, ".current_project")
        try:
            with open(current_file, 'w', encoding='utf-8') as f:
                json.dump({"current_project": self.current_project}, f, ensure_ascii=False, indent=2)
        except IOError as e:
            raise IOError(f"无法保存当前项目状态: {e}")

    def _project_exists(self, project_name: str) -> bool:
        """检查项目是否存在。"""
        project_dir = os.path.join(self.projects_dir, project_name)
        return os.path.isdir(project_dir)

    def _get_project_meta_path(self, project_name: str) -> str:
        """获取项目元数据文件路径。"""
        return os.path.join(self.projects_dir, project_name, "meta.json")

    def _load_project_meta(self, project_name: str) -> Dict[str, Any]:
        """加载项目元数据。"""
        meta_path = self._get_project_meta_path(project_name)
        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"项目元数据文件不存在: {meta_path}")

        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"项目元数据格式错误: {e}")
        except IOError as e:
            raise IOError(f"无法读取项目元数据: {e}")

    def _save_project_meta(self, project_name: str, meta: Dict[str, Any]) -> None:
        """保存项目元数据。"""
        meta_path = self._get_project_meta_path(project_name)
        try:
            with open(meta_path, 'w', encoding='utf-8') as f:
                json.dump(meta, f, ensure_ascii=False, indent=2)
        except IOError as e:
            raise IOError(f"无法保存项目元数据: {e}")

    def _create_project_structure(self, project_name: str) -> None:
        """创建项目目录结构。"""
        project_dir = os.path.join(self.projects_dir, project_name)

        # 创建主项目目录
        os.makedirs(project_dir, exist_ok=True)

        # 创建子目录
        subdirs = ["apk", "output", "config"]
        for subdir in subdirs:
            os.makedirs(os.path.join(project_dir, subdir), exist_ok=True)

    def create(self, name: str, description: str = "") -> Dict[str, Any]:
        """
        创建新项目。

        Args:
            name: 项目名称，必须唯一且非空
            description: 项目描述（可选）

        Returns:
            Dict[str, Any]: 创建成功的项目信息

        Raises:
            ValueError: 项目名称无效或已存在
            IOError: 无法创建项目目录或元数据
        """
        # 验证项目名称
        if not name or not isinstance(name, str):
            raise ValueError("项目名称不能为空")

        name = name.strip()
        if not name:
            raise ValueError("项目名称不能为空")

        # 检查项目是否已存在
        if self._project_exists(name):
            raise ValueError(f"项目已存在: {name}")

        # 创建项目目录结构
        try:
            self._create_project_structure(name)
        except OSError as e:
            raise IOError(f"无法创建项目目录: {e}")

        # 创建项目元数据
        now = datetime.now().isoformat()
        meta = {
            "name": name,
            "description": description.strip() if description else "",
            "created_at": now,
            "updated_at": now,
            "status": "active",
            "version": "1.0"
        }

        try:
            self._save_project_meta(name, meta)
        except IOError as e:
            # 回滚：删除已创建的项目目录
            project_dir = os.path.join(self.projects_dir, name)
            if os.path.exists(project_dir):
                shutil.rmtree(project_dir, ignore_errors=True)
            raise IOError(f"创建项目元数据失败，已回滚: {e}")

        return {
            "success": True,
            "message": f"项目创建成功: {name}",
            "project": meta
        }

    def list_projects(self) -> List[Dict[str, Any]]:
        """
        列出所有项目。

        Returns:
            List[Dict[str, Any]]: 项目信息列表，按创建时间倒序排列
        """
        if not os.path.exists(self.projects_dir):
            return []

        projects = []
        try:
            for entry in os.listdir(self.projects_dir):
                project_dir = os.path.join(self.projects_dir, entry)
                if os.path.isdir(project_dir):
                    try:
                        meta = self._load_project_meta(entry)
                        # 添加当前项目标记
                        meta["is_current"] = (entry == self.current_project)
                        projects.append(meta)
                    except (FileNotFoundError, ValueError, IOError):
                        # 跳过元数据损坏的项目
                        continue
        except OSError:
            return []

        # 按创建时间倒序排列
        projects.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return projects

    def switch(self, project_name: str) -> Dict[str, Any]:
        """
        切换到指定项目。

        Args:
            project_name: 要切换的项目名称

        Returns:
            Dict[str, Any]: 操作结果和项目信息

        Raises:
            ValueError: 项目不存在
            IOError: 无法保存切换状态
        """
        if not self._project_exists(project_name):
            raise ValueError(f"项目不存在: {project_name}")

        self.current_project = project_name
        try:
            self._save_current_project()
        except IOError as e:
            self.current_project = None
            raise IOError(f"无法切换项目: {e}")

        meta = self._load_project_meta(project_name)
        return {
            "success": True,
            "message": f"已切换到项目: {project_name}",
            "project": meta
        }

    def remove(self, project_name: str, force: bool = False) -> Dict[str, Any]:
        """
        删除项目。

        Args:
            project_name: 要删除的项目名称
            force: 是否强制删除（跳过确认），默认False

        Returns:
            Dict[str, Any]: 操作结果

        Raises:
            ValueError: 项目不存在或为当前项目
            IOError: 无法删除项目目录
        """
        if not self._project_exists(project_name):
            raise ValueError(f"项目不存在: {project_name}")

        if project_name == self.current_project:
            raise ValueError("不能删除当前活动项目，请先切换到其他项目")

        # 如果不是强制删除，这里可以添加确认逻辑
        # 当前实现默认为强制删除，实际使用时可根据需要调整

        project_dir = os.path.join(self.projects_dir, project_name)
        try:
            shutil.rmtree(project_dir, ignore_errors=False)
        except OSError as e:
            raise IOError(f"无法删除项目目录: {e}")

        # 如果删除的是当前项目，清除当前项目设置
        if project_name == self.current_project:
            self.current_project = None
            self._save_current_project()

        return {
            "success": True,
            "message": f"项目已删除: {project_name}"
        }

    def get_info(self, project_name: str) -> Dict[str, Any]:
        """
        获取项目详细信息。

        Args:
            project_name: 项目名称

        Returns:
            Dict[str, Any]: 项目详细信息，包含元数据和目录结构

        Raises:
            ValueError: 项目不存在
            IOError: 无法读取项目信息
        """
        if not self._project_exists(project_name):
            raise ValueError(f"项目不存在: {project_name}")

        meta = self._load_project_meta(project_name)

        # 获取目录结构信息
        project_dir = os.path.join(self.projects_dir, project_name)
        dir_info = {}
        for subdir in ["apk", "output", "config"]:
            subdir_path = os.path.join(project_dir, subdir)
            if os.path.exists(subdir_path):
                file_count = 0
                try:
                    file_count = len([f for f in os.listdir(subdir_path)
                                     if os.path.isfile(os.path.join(subdir_path, f))])
                except OSError:
                    file_count = 0
                dir_info[subdir] = {
                    "path": subdir_path,
                    "file_count": file_count
                }

        meta["is_current"] = (project_name == self.current_project)
        meta["directory_structure"] = dir_info
        meta["project_path"] = project_dir

        return meta

    def get_current_project(self) -> Optional[str]:
        """
        获取当前活动项目名称。

        Returns:
            Optional[str]: 当前项目名称，无则返回None
        """
        return self.current_project

    def project_exists(self, project_name: str) -> bool:
        """
        检查项目是否存在。

        Args:
            project_name: 项目名称

        Returns:
            bool: 项目是否存在
        """
        return self._project_exists(project_name)


# 使用示例（仅在直接运行此模块时执行）
if __name__ == "__main__":
    # 创建项目管理器实例
    pm = ProjectManager()

    # 列出所有项目
    print("=== 所有项目列表 ===")
    projects = pm.list_projects()
    for p in projects:
        current_mark = " [当前]" if p.get("is_current") else ""
        print(f"  - {p['name']}: {p.get('description', '无描述')}{current_mark}")

    # 创建一个示例项目
    print("\n=== 创建示例项目 ===")
    try:
        result = pm.create("test_project", "这是一个测试项目")
        print(f"创建结果: {result['message']}")
    except ValueError as e:
        print(f"创建失败: {e}")

    # 获取项目信息
    print("\n=== 获取项目信息 ===")
    try:
        info = pm.get_info("test_project")
        print(f"项目名称: {info['name']}")
        print(f"项目描述: {info.get('description', '无')}")
        print(f"创建时间: {info.get('created_at', '未知')}")
        print(f"项目路径: {info.get('project_path', '未知')}")
    except ValueError as e:
        print(f"获取信息失败: {e}")

    # 切换项目
    print("\n=== 切换项目 ===")
    try:
        result = pm.switch("test_project")
        print(f"切换结果: {result['message']}")
    except ValueError as e:
        print(f"切换失败: {e}")