#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK会话管理模块 - Session Manager
===================================
基于纯Python标准库的APK分析会话管理器，支持创建、列出、切换和关闭会话。
使用JSON文件存储会话元数据，无需额外依赖。
"""

import os
import json
import uuid
import time
from typing import Dict, List, Optional, Any


class SessionManager:
    """
    APK会话管理器类
    
    管理多个APK分析会话，每个会话包含：
    - session_id: 唯一会话标识符
    - apk_path: APK文件路径
    - apk_metadata: APK元数据（名称、大小、加载时间等）
    - loaded_modules: 已加载的分析模块列表
    - analysis_cache: 分析结果缓存
    
    会话数据以JSON格式存储在指定目录中。
    """
    
    def __init__(self, session_dir: str = None):
        """
        初始化SessionManager
        
        Args:
            session_dir: 会话存储目录路径，默认为 artoolkit/sessions
        """
        if session_dir is None:
            # 使用相对于当前工作目录的路径
            session_dir = os.path.join(os.getcwd(), 'artoolkit', 'sessions')
        
        self.session_dir = session_dir
        self.sessions: Dict[str, Dict[str, Any]] = {}  # 内存中的会话缓存
        self.current_session_id: Optional[str] = None  # 当前活跃会话ID
        
        # 确保会话目录存在
        os.makedirs(self.session_dir, exist_ok=True)
        
        # 加载已有会话
        self._load_sessions()
    
    def _load_sessions(self) -> None:
        """从磁盘加载所有会话到内存"""
        try:
            for filename in os.listdir(self.session_dir):
                if filename.endswith('.json'):
                    session_path = os.path.join(self.session_dir, filename)
                    try:
                        with open(session_path, 'r', encoding='utf-8') as f:
                            session_data = json.load(f)
                            session_id = session_data.get('session_id')
                            if session_id:
                                self.sessions[session_id] = session_data
                    except (json.JSONDecodeError, IOError) as e:
                        print(f"[WARN] 加载会话文件失败: {filename}, 错误: {e}")
        except OSError as e:
            print(f"[ERROR] 读取会话目录失败: {e}")
    
    def _save_session(self, session_id: str) -> bool:
        """
        将单个会话保存到磁盘
        
        Args:
            session_id: 会话ID
            
        Returns:
            是否保存成功
        """
        try:
            session_data = self.sessions.get(session_id)
            if not session_data:
                print(f"[ERROR] 会话不存在: {session_id}")
                return False
            
            session_path = os.path.join(self.session_dir, f"{session_id}.json")
            with open(session_path, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, ensure_ascii=False, indent=2)
            return True
        except IOError as e:
            print(f"[ERROR] 保存会话失败: {session_id}, 错误: {e}")
            return False
    
    def _generate_session_id(self) -> str:
        """生成唯一的会话ID"""
        return str(uuid.uuid4())
    
    def _get_apk_metadata(self, apk_path: str) -> Optional[Dict[str, Any]]:
        """
        获取APK文件的元数据信息
        
        Args:
            apk_path: APK文件路径
            
        Returns:
            APK元数据字典，如果文件不存在或读取失败则返回None
        """
        if not os.path.exists(apk_path):
            print(f"[ERROR] APK文件不存在: {apk_path}")
            return None
        
        try:
            stat_info = os.stat(apk_path)
            metadata = {
                'file_name': os.path.basename(apk_path),
                'file_size': stat_info.st_size,
                'file_size_mb': round(stat_info.st_size / (1024 * 1024), 2),
                'modified_time': stat_info.st_mtime,
                'modified_time_str': time.strftime(
                    '%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_mtime)
                ),
                'absolute_path': os.path.abspath(apk_path),
                'loaded_time': time.time(),
                'loaded_time_str': time.strftime(
                    '%Y-%m-%d %H:%M:%S', time.localtime()
                )
            }
            return metadata
        except OSError as e:
            print(f"[ERROR] 获取APK元数据失败: {apk_path}, 错误: {e}")
            return None
    
    def create_session(self, apk_path: str, name: Optional[str] = None) -> Optional[str]:
        """
        创建新的APK会话
        
        加载指定的APK文件并创建一个新的分析会话。
        会话会自动设为当前活跃会话。
        
        Args:
            apk_path: APK文件路径
            name: 会话名称（可选，默认使用APK文件名）
            
        Returns:
            新创建的会话ID，如果创建失败则返回None
        """
        # 验证APK文件
        if not apk_path:
            print("[ERROR] APK路径不能为空")
            return None
        
        if not os.path.isfile(apk_path):
            print(f"[ERROR] APK文件不存在或不是文件: {apk_path}")
            return None
        
        # 获取APK元数据
        apk_metadata = self._get_apk_metadata(apk_path)
        if not apk_metadata:
            return None
        
        # 生成会话ID和名称
        session_id = self._generate_session_id()
        if name is None:
            name = apk_metadata['file_name']
        
        # 创建会话数据
        session_data = {
            'session_id': session_id,
            'name': name,
            'apk_path': apk_metadata['absolute_path'],
            'apk_metadata': apk_metadata,
            'loaded_modules': [],
            'analysis_cache': {},
            'created_time': time.time(),
            'created_time_str': time.strftime('%Y-%m-%d %H:%M:%S'),
            'last_accessed': time.time(),
            'last_accessed_str': time.strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'active'  # active, closed
        }
        
        # 保存到内存和磁盘
        self.sessions[session_id] = session_data
        if not self._save_session(session_id):
            return None
        
        # 设置为当前会话
        old_session_id = self.current_session_id
        self.current_session_id = session_id
        
        print(f"[INFO] 会话创建成功: {session_id}, 名称: {name}")
        if old_session_id:
            print(f"[INFO] 已切换会话: {old_session_id} -> {session_id}")
        
        return session_id
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        列出所有会话
        
        Returns:
            会话信息列表，每个元素为会话的简要信息
        """
        session_list = []
        for session_id, session_data in self.sessions.items():
            session_list.append({
                'session_id': session_id,
                'name': session_data.get('name', 'Unknown'),
                'apk_name': session_data.get('apk_metadata', {}).get('file_name', 'Unknown'),
                'status': session_data.get('status', 'unknown'),
                'created_time': session_data.get('created_time_str', 'Unknown'),
                'loaded_modules_count': len(session_data.get('loaded_modules', [])),
                'is_current': session_id == self.current_session_id
            })
        
        # 按创建时间倒序排列（这里按session_id倒序近似）
        session_list.sort(key=lambda x: x['session_id'], reverse=True)
        return session_list
    
    def switch_session(self, session_id: str) -> bool:
        """
        切换到指定会话
        
        Args:
            session_id: 要切换到的会话ID
            
        Returns:
            是否切换成功
        """
        if session_id not in self.sessions:
            print(f"[ERROR] 会话不存在: {session_id}")
            return False
        
        session_data = self.sessions[session_id]
        if session_data.get('status') == 'closed':
            print(f"[ERROR] 会话已关闭: {session_id}")
            return False
        
        old_session_id = self.current_session_id
        self.current_session_id = session_id
        
        # 更新最后访问时间
        session_data['last_accessed'] = time.time()
        session_data['last_accessed_str'] = time.strftime('%Y-%m-%d %H:%M:%S')
        self._save_session(session_id)
        
        print(f"[INFO] 已切换会话: {old_session_id} -> {session_id}")
        return True
    
    def close_session(self, session_id: str) -> bool:
        """
        关闭指定会话
        
        将会话标记为关闭状态，但不删除数据。
        关闭后无法再切换到该会话。
        
        Args:
            session_id: 要关闭的会话ID
            
        Returns:
            是否关闭成功
        """
        if session_id not in self.sessions:
            print(f"[ERROR] 会话不存在: {session_id}")
            return False
        
        session_data = self.sessions[session_id]
        
        # 如果是当前会话，先清除当前会话标记
        if self.current_session_id == session_id:
            self.current_session_id = None
            print(f"[INFO] 当前会话已关闭: {session_id}")
        
        # 标记为关闭
        session_data['status'] = 'closed'
        session_data['closed_time'] = time.time()
        session_data['closed_time_str'] = time.strftime('%Y-%m-%d %H:%M:%S')
        
        if not self._save_session(session_id):
            return False
        
        print(f"[INFO] 会话已关闭: {session_id}, 名称: {session_data.get('name')}")
        return True
    
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        获取会话详细信息
        
        Args:
            session_id: 会话ID
            
        Returns:
            会话完整信息，如果会话不存在则返回None
        """
        if session_id not in self.sessions:
            print(f"[ERROR] 会话不存在: {session_id}")
            return None
        
        session_data = self.sessions[session_id]
        
        # 返回会话信息的副本，避免外部修改
        return {
            'session_id': session_data.get('session_id'),
            'name': session_data.get('name'),
            'apk_path': session_data.get('apk_path'),
            'apk_metadata': session_data.get('apk_metadata', {}).copy(),
            'loaded_modules': session_data.get('loaded_modules', []).copy(),
            'analysis_cache_keys': list(session_data.get('analysis_cache', {}).keys()),
            'analysis_cache_size': len(session_data.get('analysis_cache', {})),
            'created_time': session_data.get('created_time_str'),
            'last_accessed': session_data.get('last_accessed_str'),
            'status': session_data.get('status'),
            'is_current': session_id == self.current_session_id
        }
    
    def get_current_session_id(self) -> Optional[str]:
        """
        获取当前活跃的会话ID
        
        Returns:
            当前会话ID，如果没有则返回None
        """
        return self.current_session_id
    
    def add_loaded_module(self, session_id: str, module_name: str) -> bool:
        """
        向会话添加已加载的分析模块
        
        Args:
            session_id: 会话ID
            module_name: 模块名称
            
        Returns:
            是否添加成功
        """
        if session_id not in self.sessions:
            print(f"[ERROR] 会话不存在: {session_id}")
            return False
        
        session_data = self.sessions[session_id]
        loaded_modules = session_data.get('loaded_modules', [])
        
        if module_name not in loaded_modules:
            loaded_modules.append(module_name)
            session_data['loaded_modules'] = loaded_modules
            session_data['last_accessed'] = time.time()
            session_data['last_accessed_str'] = time.strftime('%Y-%m-%d %H:%M:%S')
            self._save_session(session_id)
            print(f"[INFO] 已添加模块到会话: {session_id}, 模块: {module_name}")
        
        return True
    
    def cache_analysis_result(self, session_id: str, key: str, data: Any) -> bool:
        """
        缓存分析结果到会话
        
        Args:
            session_id: 会话ID
            key: 缓存键名
            data: 要缓存的数据（必须可JSON序列化）
            
        Returns:
            是否缓存成功
        """
        if session_id not in self.sessions:
            print(f"[ERROR] 会话不存在: {session_id}")
            return False
        
        try:
            # 测试JSON序列化
            json.dumps(data)
        except (TypeError, ValueError) as e:
            print(f"[ERROR] 数据无法JSON序列化: {e}")
            return False
        
        session_data = self.sessions[session_id]
        analysis_cache = session_data.get('analysis_cache', {})
        analysis_cache[key] = data
        session_data['analysis_cache'] = analysis_cache
        session_data['last_accessed'] = time.time()
        session_data['last_accessed_str'] = time.strftime('%Y-%m-%d %H:%M:%S')
        
        if not self._save_session(session_id):
            return False
        
        print(f"[INFO] 已缓存分析结果: {session_id}, 键: {key}")
        return True
    
    def get_cached_analysis(self, session_id: str, key: str) -> Optional[Any]:
        """
        获取缓存的分析结果
        
        Args:
            session_id: 会话ID
            key: 缓存键名
            
        Returns:
            缓存的数据，如果不存在则返回None
        """
        if session_id not in self.sessions:
            print(f"[ERROR] 会话不存在: {session_id}")
            return None
        
        session_data = self.sessions[session_id]
        analysis_cache = session_data.get('analysis_cache', {})
        return analysis_cache.get(key)
    
    def delete_session(self, session_id: str) -> bool:
        """
        删除会话（永久删除数据）
        
        注意：此操作不可逆，会删除所有会话数据。
        一般情况下应使用close_session()关闭会话。
        
        Args:
            session_id: 要删除的会话ID
            
        Returns:
            是否 deletion 成功
        """
        if session_id not in self.sessions:
            print(f"[ERROR] 会话不存在: {session_id}")
            return False
        
        # 从内存中移除
        del self.sessions[session_id]
        
        # 从磁盘删除文件
        session_path = os.path.join(self.session_dir, f"{session_id}.json")
        try:
            if os.path.exists(session_path):
                os.remove(session_path)
        except OSError as e:
            print(f"[ERROR] 删除会话文件失败: {e}")
            return False
        
        # 如果是当前会话，清除标记
        if self.current_session_id == session_id:
            self.current_session_id = None
        
        print(f"[INFO] 会话已删除: {session_id}")
        return True
    
    def cleanup_closed_sessions(self, max_age_days: int = 7) -> int:
        """
        清理超过指定天数的已关闭会话
        
        Args:
            max_age_days: 最大保留天数
            
        Returns:
            清理的会话数量
        """
        cleaned = 0
        current_time = time.time()
        max_age_seconds = max_age_days * 24 * 60 * 60
        
        for session_id in list(self.sessions.keys()):
            session_data = self.sessions[session_id]
            if session_data.get('status') == 'closed':
                closed_time = session_data.get('closed_time', 0)
                if current_time - closed_time > max_age_seconds:
                    if self.delete_session(session_id):
                        cleaned += 1
        
        print(f"[INFO] 清理了 {cleaned} 个过期会话")
        return cleaned
    
    def get_session_count(self) -> int:
        """
        获取会话总数
        
        Returns:
            会话数量
        """
        return len(self.sessions)
    
    def get_active_session_count(self) -> int:
        """
        获取活跃会话数量
        
        Returns:
            活跃（未关闭）会话数量
        """
        count = 0
        for session_data in self.sessions.values():
            if session_data.get('status') == 'active':
                count += 1
        return count


# 使用示例（仅在直接运行此模块时执行）
if __name__ == "__main__":
    # 创建会话管理器
    manager = SessionManager()
    
    # 列出会话
    print("=== 所有会话 ===")
    sessions = manager.list_sessions()
    for s in sessions:
        print(f"  {s['session_id'][:8]}... - {s['name']} ({s['status']})")
    
    # 获取统计信息
    print(f"\n总会话数: {manager.get_session_count()}")
    print(f"活跃会话数: {manager.get_active_session_count()}")