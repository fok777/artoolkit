#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
网络流量捕获与分析模块 - Network Capture & Analysis Module
============================================================================
功能：
  1. 网络请求特征提取 - 从APK中提取URL、IP、域名等网络端点
  2. HTTPS证书分析 - 分析APK中嵌入的证书信息
  3. API端点识别 - 识别API接口地址和参数
  4. 流量统计 - 分析PCAP文件中的流量特征
  5. Frida脚本生成 - 生成用于Hook网络函数的Frida脚本

使用Python标准库 + 正则表达式，输出结构化JSON结果
============================================================================
"""

import os
import re
import json
import struct
import zipfile
import argparse
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import Counter
from xml.etree import ElementTree as ET


class NetworkAnalyzer:
    """
    网络分析器类 - 提供APK网络特征提取和流量分析功能
    Network Analyzer class - provides APK network feature extraction and traffic analysis
    """

    # 常见网络相关模式正则表达式
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"\']+',
        re.IGNORECASE
    )
    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    DOMAIN_PATTERN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,}\b'
    )
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    CERT_PATTERN = re.compile(
        r'-----BEGIN (?:CERTIFICATE|RSA PRIVATE KEY|PRIVATE KEY|EC PRIVATE KEY)-----'
        r'.*?-----END (?:CERTIFICATE|RSA PRIVATE KEY|PRIVATE KEY|EC PRIVATE KEY)-----',
        re.DOTALL
    )
    API_PATH_PATTERN = re.compile(
        r'["\']((?:/[\w\-./]+)+)["\']'
    )

    # 常见端口列表
    COMMON_PORTS = {
        80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
        22: 'SSH', 21: 'FTP', 23: 'TELNET', 25: 'SMTP', 53: 'DNS',
        3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
        1433: 'MSSQL', 3389: 'RDP', 5900: 'VNC'
    }

    def __init__(self):
        """初始化网络分析器 / Initialize network analyzer"""
        self.endpoints = []
        self.certs = []
        self.api_endpoints = []
        self.traffic_stats = {}
        self.frida_hooks = []

    # =========================================================================
    # APK 网络特征提取 / APK Network Feature Extraction
    # =========================================================================

    def extract_endpoints(self, apk_path: str) -> Dict[str, Any]:
        """
        从APK文件中提取网络端点信息
        Extract network endpoint information from APK file

        参数 / Args:
            apk_path: APK文件路径 / APK file path

        返回 / Returns:
            Dict: 包含URLs、IPs、域名、API端点等结构化数据 / Structured data with URLs, IPs, domains, API endpoints
        """
        result = {
            'apk_path': apk_path,
            'file_size': 0,
            'extraction_time': datetime.now().isoformat(),
            'urls': [],
            'ips': set(),
            'domains': set(),
            'api_endpoints': [],
            'certificates': [],
            'permissions': [],
            'network_security_config': {},
            'errors': []
        }

        try:
            if not os.path.exists(apk_path):
                raise FileNotFoundError(f"APK文件不存在 / APK file not found: {apk_path}")

            result['file_size'] = os.path.getsize(apk_path)

            # 检查是否为有效的ZIP/APK文件
            if not zipfile.is_zipfile(apk_path):
                raise ValueError(f"无效的APK文件 / Invalid APK file: {apk_path}")

            with zipfile.ZipFile(apk_path, 'r') as zf:
                # 遍历APK中的所有文件 / Iterate through all files in APK
                for file_info in zf.infolist():
                    file_name = file_info.filename

                    # 跳过二进制文件和大文件 / Skip binary and large files
                    if self._should_skip_file(file_name, file_info.file_size):
                        continue

                    try:
                        content = zf.read(file_info).decode('utf-8', errors='ignore')
                    except Exception:
                        continue

                    # 提取URL / Extract URLs
                    urls = self.URL_PATTERN.findall(content)
                    for url in urls:
                        if url not in result['urls']:
                            result['urls'].append(url)

                    # 提取IP地址 / Extract IP addresses
                    ips = self.IP_PATTERN.findall(content)
                    for ip in ips:
                        if not ip.startswith('0.') and ip not in result['ips']:
                            result['ips'].add(ip)

                    # 提取域名 / Extract domains
                    domains = self.DOMAIN_PATTERN.findall(content)
                    for domain in domains:
                        if domain not in result['domains']:
                            result['domains'].add(domain)

                    # 提取API路径 / Extract API paths
                    if any(keyword in file_name.lower() for keyword in
                            ['url', 'api', 'endpoint', 'config', 'network', 'host']):
                        paths = self.API_PATH_PATTERN.findall(content)
                        for path in paths:
                            if path.startswith('/') and len(path) > 1:
                                if path not in result['api_endpoints']:
                                    result['api_endpoints'].append(path)

                    # 提取证书 / Extract certificates
                    if file_name.endswith(('.pem', '.crt', '.cer', '.key', '.p12')) or \
                       'cert' in file_name.lower():
                        certs = self.CERT_PATTERN.findall(content)
                        for cert in certs:
                            cert_info = self._parse_certificate(cert)
                            if cert_info:
                                result['certificates'].append(cert_info)

                    # 提取AndroidManifest.xml权限 / Extract AndroidManifest.xml permissions
                    if file_name == 'AndroidManifest.xml':
                        try:
                            manifest = ET.fromstring(zf.read(file_info))
                            for elem in manifest.iter():
                                if 'permission' in elem.tag:
                                    perm_name = elem.get('{android}name', '')
                                    if perm_name:
                                        result['permissions'].append(perm_name)
                        except Exception:
                            pass

                    # 提取network_security_config.xml / Extract network security config
                    if 'network_security_config' in file_name.lower():
                        try:
                            ns_config = ET.fromstring(zf.read(file_info))
                            result['network_security_config'] = \
                                self._parse_network_security_config(ns_config)
                        except Exception:
                            pass

                # 处理classes.dex文件中的字符串 / Process strings in classes.dex
                if 'classes.dex' in zf.namelist():
                    dex_strings = self._extract_dex_strings(zf.read('classes.dex'))
                    for s in dex_strings:
                        urls = self.URL_PATTERN.findall(s)
                        for url in urls:
                            if url not in result['urls']:
                                result['urls'].append(url)
                        ips = self.IP_PATTERN.findall(s)
                        for ip in ips:
                            if not ip.startswith('0.') and ip not in result['ips']:
                                result['ips'].add(ip)
                        domains = self.DOMAIN_PATTERN.findall(s)
                        for domain in domains:
                            if domain not in result['domains']:
                                result['domains'].add(domain)

            # 转换set为list以便JSON序列化 / Convert set to list for JSON serialization
            result['ips'] = list(result['ips'])
            result['domains'] = list(result['domains'])

            # 按类型对URL进行分类 / Classify URLs by type
            result['url_categories'] = self._categorize_urls(result['urls'])

            # 识别API端点模式 / Identify API endpoint patterns
            result['api_patterns'] = self._identify_api_patterns(
                result['api_endpoints'], result['urls']
            )

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def get_network_stats(self, apk_path: str) -> Dict[str, Any]:
        """
        获取APK的网络统计信息 / Get network statistics for APK

        参数 / Args:
            apk_path: APK文件路径 / APK file path

        返回 / Returns:
            Dict: 网络统计信息 / Network statistics
        """
        stats = {
            'apk_path': apk_path,
            'analysis_time': datetime.now().isoformat(),
            'total_urls': 0,
            'unique_ips': 0,
            'unique_domains': 0,
            'api_endpoints_count': 0,
            'certificates_count': 0,
            'network_permissions': [],
            'protocol_distribution': {},
            'port_distribution': {},
            'errors': []
        }

        try:
            endpoints = self.extract_endpoints(apk_path)

            stats['total_urls'] = len(endpoints.get('urls', []))
            stats['unique_ips'] = len(endpoints.get('ips', []))
            stats['unique_domains'] = len(endpoints.get('domains', []))
            stats['api_endpoints_count'] = len(endpoints.get('api_endpoints', []))
            stats['certificates_count'] = len(endpoints.get('certificates', []))

            # 提取网络相关权限 / Extract network-related permissions
            network_perms = [
                'INTERNET', 'ACCESS_NETWORK_STATE', 'ACCESS_WIFI_STATE',
                'CHANGE_NETWORK_STATE', 'CHANGE_WIFI_STATE', 'CONNECTIVITY_SYNC',
                'VOLUME_SETTINGS', 'SYSTEM_ALERT_WINDOW', 'WRITE_EXTERNAL_STORAGE'
            ]
            for perm in endpoints.get('permissions', []):
                if any(np.lower() in perm.lower() for np in network_perms):
                    stats['network_permissions'].append(perm)

            # 协议分布 / Protocol distribution
            protocols = Counter()
            ports = Counter()

            for url in endpoints.get('urls', []):
                if url.startswith('https://'):
                    protocols['https'] += 1
                elif url.startswith('http://'):
                    protocols['http'] += 1
                elif url.startswith('ws://'):
                    protocols['websocket'] += 1
                elif url.startswith('wss://'):
                    protocols['wss'] += 1

            stats['protocol_distribution'] = dict(protocols)
            stats['port_distribution'] = dict(ports)

        except Exception as e:
            stats['errors'].append(str(e))

        return stats

    # =========================================================================
    # PCAP 流量分析 / PCAP Traffic Analysis
    # =========================================================================

    def analyze_traffic(self, pcap_path: str) -> Dict[str, Any]:
        """
        分析PCAP文件中的网络流量 / Analyze network traffic in PCAP file

        参数 / Args:
            pcap_path: PCAP文件路径 / PCAP file path

        返回 / Returns:
            Dict: 流量统计和特征信息 / Traffic statistics and feature information
        """
        result = {
            'pcap_path': pcap_path,
            'file_size': 0,
            'analysis_time': datetime.now().isoformat(),
            'packet_count': 0,
            'traffic_stats': {},
            'sessions': [],
            'errors': []
        }

        try:
            if not os.path.exists(pcap_path):
                raise FileNotFoundError(f"PCAP文件不存在 / PCAP file not found: {pcap_path}")

            result['file_size'] = os.path.getsize(pcap_path)

            # 解析PCAP文件 / Parse PCAP file
            packets = self._parse_pcap(pcap_path)
            result['packet_count'] = len(packets)

            # 统计流量 / Traffic statistics
            result['traffic_stats'] = self._calculate_traffic_stats(packets)

            # 提取会话信息 / Extract session information
            result['sessions'] = self._extract_sessions(packets)

            # 检测协议 / Detect protocols
            result['protocol_distribution'] = self._detect_protocols(packets)

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def _parse_pcap(self, pcap_path: str) -> List[Dict]:
        """
        解析PCAP文件 / Parse PCAP file

        参数 / Args:
            pcap_path: PCAP文件路径

        返回 / Returns:
            List[Dict]: 数据包列表 / List of packets
        """
        packets = []

        try:
            with open(pcap_path, 'rb') as f:
                # 读取全局头 / Read global header
                header = f.read(24)
                if len(header) < 24:
                    return packets

                magic_number = struct.unpack('<I', header[:4])[0]
                if magic_number == 0xa1b2c3d4:
                    byte_order = '<'  # 小端 / Little endian
                elif magic_number == 0xd4c3b2a1:
                    byte_order = '>'  # 大端 / Big endian
                else:
                    return packets  # 未知格式 / Unknown format

                # 解析数据包 / Parse packets
                while True:
                    # 读取数据包头 / Read packet header
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break

                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                        f'{byte_order}IIII', pkt_header
                    )

                    # 读取数据包数据 / Read packet data
                    pkt_data = f.read(incl_len)
                    if len(pkt_data) < incl_len:
                        break

                    packet = {
                        'timestamp': ts_sec + ts_usec / 1000000.0,
                        'length': incl_len,
                        'original_length': orig_len,
                        'data': pkt_data
                    }

                    # 解析以太网头 / Parse Ethernet header
                    if len(pkt_data) >= 14:
                        eth_type = struct.unpack('!H', pkt_data[12:14])[0]
                        packet['eth_type'] = eth_type

                        # IPv4 / IPv4
                        if eth_type == 0x0800 and len(pkt_data) >= 34:
                            ip_header = pkt_data[14:]
                            version_ihl = ip_header[0]
                            ip_version = version_ihl >> 4
                            ihl = (version_ihl & 0x0F) * 4

                            if ip_version == 4:
                                protocol = ip_header[9]
                                src_ip = '.'.join(map(str, ip_header[12:16]))
                                dst_ip = '.'.join(map(str, ip_header[16:20]))
                                packet['ip_version'] = 4
                                packet['protocol'] = protocol
                                packet['src_ip'] = src_ip
                                packet['dst_ip'] = dst_ip

                                # TCP/UDP端口 / TCP/UDP ports
                                if protocol in (6, 17) and len(ip_header) >= ihl + 4:
                                    transport_header = ip_header[ihl:]
                                    if len(transport_header) >= 4:
                                        src_port = struct.unpack('!H', transport_header[0:2])[0]
                                        dst_port = struct.unpack('!H', transport_header[2:4])[0]
                                        packet['src_port'] = src_port
                                        packet['dst_port'] = dst_port

                                        # TCP标志 / TCP flags
                                        if protocol == 6 and len(transport_header) >= 14:
                                            flags = transport_header[13]
                                            packet['tcp_flags'] = {
                                                'fin': bool(flags & 0x01),
                                                'syn': bool(flags & 0x02),
                                                'rst': bool(flags & 0x04),
                                                'psh': bool(flags & 0x08),
                                                'ack': bool(flags & 0x10),
                                                'urg': bool(flags & 0x20)
                                            }

                    packets.append(packet)

        except Exception as e:
            # 如果无法解析PCAP，返回空列表 / Return empty list if cannot parse PCAP
            pass

        return packets

    def _calculate_traffic_stats(self, packets: List[Dict]) -> Dict[str, Any]:
        """
        计算流量统计 / Calculate traffic statistics

        参数 / Args:
            packets: 数据包列表 / Packet list

        返回 / Returns:
            Dict: 统计信息 / Statistics
        """
        stats = {
            'total_packets': len(packets),
            'total_bytes': sum(p['length'] for p in packets),
            'start_time': None,
            'end_time': None,
            'duration': 0,
            'unique_src_ips': set(),
            'unique_dst_ips': set(),
            'protocol_counts': Counter(),
            'port_counts': Counter(),
            'tcp_flags_count': Counter()
        }

        if packets:
            stats['start_time'] = packets[0]['timestamp']
            stats['end_time'] = packets[-1]['timestamp']
            stats['duration'] = stats['end_time'] - stats['start_time']

        for pkt in packets:
            if 'src_ip' in pkt:
                stats['unique_src_ips'].add(pkt['src_ip'])
            if 'dst_ip' in pkt:
                stats['unique_dst_ips'].add(pkt['dst_ip'])
            if 'protocol' in pkt:
                proto_name = self._protocol_name(pkt['protocol'])
                stats['protocol_counts'][proto_name] += 1
            if 'dst_port' in pkt:
                stats['port_counts'][pkt['dst_port']] += 1
            if 'tcp_flags' in pkt:
                for flag, value in pkt['tcp_flags'].items():
                    if value:
                        stats['tcp_flags_count'][flag] += 1

        # 转换set为list / Convert set to list
        stats['unique_src_ips'] = list(stats['unique_src_ips'])
        stats['unique_dst_ips'] = list(stats['unique_dst_ips'])
        stats['protocol_counts'] = dict(stats['protocol_counts'])
        stats['port_counts'] = dict(stats['port_counts'])
        stats['tcp_flags_count'] = dict(stats['tcp_flags_count'])

        return stats

    def _extract_sessions(self, packets: List[Dict]) -> List[Dict]:
        """
        提取会话信息 / Extract session information

        参数 / Args:
            packets: 数据包列表 / Packet list

        返回 / Returns:
            List[Dict]: 会话列表 / Session list
        """
        sessions = {}
        session_key_template = '{src_ip}:{src_port}->{dst_ip}:{dst_port}'

        for pkt in packets:
            if 'src_ip' in pkt and 'src_port' in pkt:
                key = session_key_template.format(
                    src_ip=pkt['src_ip'],
                    src_port=pkt['src_port'],
                    dst_ip=pkt['dst_ip'],
                    dst_port=pkt['dst_port']
                )

                if key not in sessions:
                    sessions[key] = {
                        'src_ip': pkt['src_ip'],
                        'src_port': pkt['src_port'],
                        'dst_ip': pkt['dst_ip'],
                        'dst_port': pkt['dst_port'],
                        'protocol': pkt.get('protocol', 0),
                        'packet_count': 0,
                        'byte_count': 0,
                        'start_time': pkt['timestamp'],
                        'end_time': pkt['timestamp'],
                        'flags': set()
                    }

                sessions[key]['packet_count'] += 1
                sessions[key]['byte_count'] += pkt['length']
                sessions[key]['end_time'] = pkt['timestamp']

                if 'tcp_flags' in pkt:
                    for flag, value in pkt['tcp_flags'].items():
                        if value:
                            sessions[key]['flags'].add(flag)

        # 转换set为list / Convert set to list
        result = []
        for session in sessions.values():
            session['flags'] = list(session['flags'])
            result.append(session)

        return result

    def _detect_protocols(self, packets: List[Dict]) -> Dict[str, int]:
        """
        检测应用层协议 / Detect application layer protocols

        参数 / Args:
            packets: 数据包列表 / Packet list

        返回 / Returns:
            Dict[str, int]: 协议计数 / Protocol counts
        """
        protocols = Counter()

        for pkt in packets:
            if 'data' in pkt and len(pkt['data']) > 14:
                payload = pkt['data'][14:]  # 跳过以太网头 / Skip Ethernet header

                # 检测HTTP / Detect HTTP
                if payload.startswith(b'GET ') or payload.startswith(b'POST ') or \
                   payload.startswith(b'HTTP/'):
                    protocols['http'] += 1
                # 检测TLS / Detect TLS
                elif len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
                    protocols['tls'] += 1
                # 检测DNS / Detect DNS
                elif len(payload) > 40 and payload[12:14] == b'\x00\x35':
                    protocols['dns'] += 1

        return dict(protocols)

    def _protocol_name(self, proto_num: int) -> str:
        """
        获取协议名称 / Get protocol name

        参数 / Args:
            proto_num: 协议号 / Protocol number

        返回 / Returns:
            str: 协议名称 / Protocol name
        """
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
        }
        return protocol_map.get(proto_num, f'UNKNOWN({proto_num})')

    # =========================================================================
    # Frida 脚本生成 / Frida Script Generation
    # =========================================================================

    def generate_hook_script(self, target_info: Optional[Dict] = None) -> Dict[str, Any]:
        """
        生成用于Hook网络函数的Frida脚本 / Generate Frida script for hooking network functions

        参数 / Args:
            target_info: 目标信息（可选）/ Target information (optional)

        返回 / Returns:
            Dict: 包含Frida脚本和说明 / Frida script and instructions
        """
        result = {
            'generation_time': datetime.now().isoformat(),
            'scripts': [],
            'instructions': [],
            'errors': []
        }

        try:
            # 生成通用网络Hook脚本 / Generate general network hook script
            general_script = self._generate_general_hook_script()
            result['scripts'].append({
                'name': 'general_network_hook',
                'description': '通用网络函数Hook脚本 / General network function hook script',
                'content': general_script
            })

            # 生成HTTPS证书Hook脚本 / Generate HTTPS certificate hook script
            cert_script = self._generate_cert_hook_script()
            result['scripts'].append({
                'name': 'https_cert_hook',
                'description': 'HTTPS证书验证Hook脚本 / HTTPS certificate verification hook script',
                'content': cert_script
            })

            # 生成API端点Hook脚本 / Generate API endpoint hook script
            api_script = self._generate_api_hook_script()
            result['scripts'].append({
                'name': 'api_endpoint_hook',
                'description': 'API端点识别Hook脚本 / API endpoint identification hook script',
                'content': api_script
            })

            # 如果提供了目标信息，生成针对性的脚本 / Generate targeted script if target info provided
            if target_info:
                targeted_script = self._generate_targeted_hook_script(target_info)
                result['scripts'].append({
                    'name': 'targeted_hook',
                    'description': '针对性Hook脚本 / Targeted hook script',
                    'content': targeted_script
                })

            # 生成使用说明 / Generate instructions
            result['instructions'] = self._generate_frida_instructions()

        except Exception as e:
            result['errors'].append(str(e))

        return result

    def _generate_general_hook_script(self) -> str:
        """生成通用网络Hook脚本 / Generate general network hook script"""
        return '''// 通用网络函数Hook脚本 / General network function hook script
// 用于拦截和记录应用的网络请求 / Used to intercept and log application network requests

Interceptor.attach(Module.findExportByName(null, "connect"), {
    onEnter: function (args) {
        var sockaddr = args[1];
        var family = Memory.readU16(sockaddr);
        var port = Memory.readU16(sockaddr.add(2));
        var addr = "";

        if (family === 2) { // IPv4
            addr = Socket.inet_ntop(family, sockaddr.add(4));
        } else if (family === 10) { // IPv6
            addr = Socket.inet_ntop(family, sockaddr.add(8));
        }

        console.log("[CONNECT] " + addr + ":" + port);
        this.addr = addr;
        this.port = port;
    },
    onLeave: function (retval) {
        var ret = retval.toInt32();
        if (ret === 0) {
            console.log("[CONNECT] Success: " + this.addr + ":" + this.port);
        } else {
            console.log("[CONNECT] Failed: " + this.addr + ":" + this.port + " (errno: " + ret + ")");
        }
    }
});

// Hook SSL_read 和 SSL_write / Hook SSL_read and SSL_write
var SSL_read = Module.findExportByName("libssl.so", "SSL_read");
if (SSL_read) {
    Interceptor.attach(SSL_read, {
        onEnter: function (args) {
            this.ssl = args[0];
            this.buf = args[1];
            this.num = args[2].toInt32();
        },
        onLeave: function (retval) {
            var ret = retval.toInt32();
            if (ret > 0) {
                var data = Memory.readUtf8String(this.buf, Math.min(ret, 256));
                console.log("[SSL_READ] " + data);
            }
        }
    });
}

var SSL_write = Module.findExportByName("libssl.so", "SSL_write");
if (SSL_write) {
    Interceptor.attach(SSL_write, {
        onEnter: function (args) {
            this.buf = args[1];
            this.num = args[2].toInt32();
        },
        onLeave: function (retval) {
            var ret = retval.toInt32();
            if (ret > 0) {
                var data = Memory.readUtf8String(this.buf, Math.min(ret, 256));
                console.log("[SSL_WRITE] " + data);
            }
        }
    });
}'''

    def _generate_cert_hook_script(self) -> str:
        """生成HTTPS证书Hook脚本 / Generate HTTPS certificate hook script"""
        return '''// HTTPS证书验证Hook脚本 / HTTPS certificate verification hook script
// 用于绕过证书验证或提取证书信息 / Used to bypass certificate verification or extract certificate info

// Hook X509_verify_cert
var X509_verify_cert = Module.findExportByName("libssl.so", "X509_verify_cert");
if (X509_verify_cert) {
    Interceptor.attach(X509_verify_cert, {
        onEnter: function (args) {
            console.log("[X509_verify_cert] Called");
        },
        onLeave: function (args) {
            // 返回0表示成功，非0表示失败 / Return 0 for success, non-zero for failure
            args[0] = ptr(0);  // 强制成功 / Force success
        }
    });
}

// Hook SSL_CTX_set_verify
var SSL_CTX_set_verify = Module.findExportByName("libssl.so", "SSL_CTX_set_verify");
if (SSL_CTX_set_verify) {
    Interceptor.attach(SSL_CTX_set_verify, {
        onEnter: function (args) {
            console.log("[SSL_CTX_set_verify] Called");
        }
    });
}

// 提取证书信息 / Extract certificate information
var SSL_get_peer_certificate = Module.findExportByName("libssl.so", "SSL_get_peer_certificate");
if (SSL_get_peer_certificate) {
    Interceptor.attach(SSL_get_peer_certificate, {
        onEnter: function (args) {
            this.ssl = args[0];
        },
        onLeave: function (retval) {
            var cert = retval;
            if (!cert.isNull()) {
                console.log("[CERT] Peer certificate obtained: " + cert);
                // 这里可以进一步解析证书 / Further certificate parsing can be done here
            }
        }
    });
}'''

    def _generate_api_hook_script(self) -> str:
        """生成API端点Hook脚本 / Generate API endpoint hook script"""
        return '''// API端点识别Hook脚本 / API endpoint identification hook script
// 用于自动发现和记录应用的API请求 / Used to automatically discover and log application API requests

// Hook OkHttp
var OkHttp = Module.findExportByName("okhttp", "OkHttpClient");
if (OkHttp) {
    console.log("[API] OkHttp library detected");
}

// Hook HttpURLConnection
var HttpURLConnection = Module.findExportByName("libjava.net", "HttpURLConnection");
if (HttpURLConnection) {
    Interceptor.attach(HttpURLConnection, {
        onEnter: function (args) {
            this.conn = args[0];
        },
        onLeave: function (retval) {
            // 记录连接信息 / Log connection info
            console.log("[HTTP] HttpURLConnection used");
        }
    });
}

// Hook Volley (如果使用 / if used)
var Volley = Module.findExportByName("volley", "RequestQueue");
if (Volley) {
    console.log("[API] Volley library detected");
}

// Hook 自定义网络库（示例）/ Hook custom network library (example)
// 根据实际应用进行调整 / Adjust according to actual application
var CustomNetwork = Module.findExportByName("libcustom_network.so", "network_request");
if (CustomNetwork) {
    Interceptor.attach(CustomNetwork, {
        onEnter: function (args) {
            var url = Memory.readUtf8String(args[0]);
            console.log("[CUSTOM] URL: " + url);
        }
    });
}'''

    def _generate_targeted_hook_script(self, target_info: Dict) -> str:
        """生成针对性的Hook脚本 / Generate targeted hook script"""
        script = '// 针对性Hook脚本 / Targeted hook script\n'
        script += '// 目标信息 / Target information:\n'
        script += f'// {json.dumps(target_info, indent=2)}\n\n'

        # 根据目标信息生成特定Hook / Generate specific hooks based on target info
        if 'urls' in target_info:
            script += '// Hook 特定URL / Hook specific URLs\n'
            for url in target_info['urls'][:5]:  # 限制数量 / Limit count
                script += f'// URL: {url}\n'

        return script

    def _generate_frida_instructions(self) -> List[str]:
        """生成Frida使用说明 / Generate Frida usage instructions"""
        return [
            "1. 安装Frida: pip install frida-tools",
            "2. 确保设备已Root或已安装Frida",
            "3. 使用以下命令附加到目标应用:",
            "   frida -U -n <应用包名> -l <脚本文件>",
            "4. 或者在Python中使用Frida API:",
            "   import frida; session = frida.attach(pkg_name); script = session.create_script(script_content); script.load()",
            "5. 观察控制台输出以获取网络请求信息 / Observe console output for network request information"
        ]

    # =========================================================================
    # 辅助函数 / Helper Functions
    # =========================================================================

    def _should_skip_file(self, file_name: str, file_size: int) -> bool:
        """
        判断是否应该跳过文件 / Determine if file should be skipped

        参数 / Args:
            file_name: 文件名 / File name
            file_size: 文件大小 / File size

        返回 / Returns:
            bool: 是否跳过 / Whether to skip
        """
        # 跳过大型二进制文件 / Skip large binary files
        if file_size > 10 * 1024 * 1024:  # 10MB
            return True

        # 跳过特定扩展名 / Skip specific extensions
        skip_extensions = {
            '.dex', '.so', '.o', '.a', '.lib', '.dll', '.exe',
            '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp',
            '.mp3', '.mp4', '.wav', '.ogg', '.avi', '.mov',
            '.zip', '.tar', '.gz', '.bz2', '.7z',
            '.arsc', '.dat', '.bin'
        }

        ext = os.path.splitext(file_name)[1].lower()
        if ext in skip_extensions:
            return True

        return False

    def _parse_certificate(self, cert_text: str) -> Optional[Dict]:
        """
        解析证书文本 / Parse certificate text

        参数 / Args:
            cert_text: 证书文本 / Certificate text

        返回 / Returns:
            Optional[Dict]: 证书信息 / Certificate information
        """
        try:
            cert_info = {
                'type': '',
                'size': len(cert_text),
                'fingerprint': hashlib.sha256(cert_text.encode()).hexdigest()
            }

            if 'BEGIN CERTIFICATE' in cert_text:
                cert_info['type'] = 'X.509 Certificate'
            elif 'BEGIN RSA PRIVATE KEY' in cert_text:
                cert_info['type'] = 'RSA Private Key'
            elif 'BEGIN PRIVATE KEY' in cert_text:
                cert_info['type'] = 'Private Key'
            elif 'BEGIN EC PRIVATE KEY' in cert_text:
                cert_info['type'] = 'EC Private Key'

            return cert_info

        except Exception:
            return None

    def _extract_dex_strings(self, dex_data: bytes) -> List[str]:
        """
        从DEX文件中提取字符串 / Extract strings from DEX file

        参数 / Args:
            dex_data: DEX文件数据 / DEX file data

        返回 / Returns:
            List[str]: 字符串列表 / String list
        """
        strings = []

        try:
            # 简单的字符串提取：查找可打印字符序列 / Simple string extraction: find printable character sequences
            # 这不是完整的DEX解析，但可以提取大多数字符串 / This is not complete DEX parsing but extracts most strings
            pattern = re.compile(rb'[\x20-\x7E]{4,}')
            matches = pattern.findall(dex_data)

            for match in matches:
                try:
                    s = match.decode('utf-8')
                    if s not in strings:
                        strings.append(s)
                except Exception:
                    continue

        except Exception:
            pass

        return strings

    def _parse_network_security_config(self, root: ET.Element) -> Dict:
        """
        解析network_security_config.xml / Parse network_security_config.xml

        参数 / Args:
            root: XML根元素 / XML root element

        返回 / Returns:
            Dict: 网络安全配置 / Network security config
        """
        config = {
            'base_config': {},
            'domain_configs': [],
            'debug_overrides': {}
        }

        try:
            # 解析base-config / Parse base-config
            base_config = root.find('.//base-config')
            if base_config is not None:
                config['base_config'] = {
                    'trustUserCerts': base_config.get('trustUserCerts', 'false'),
                    'cleartextTrafficPermitted': base_config.get('cleartextTrafficPermitted', 'false')
                }

            # 解析domain-config / Parse domain-config
            for domain_config in root.findall('.//domain-config'):
                dc_info = {
                    'domain': domain_config.get('domain', ''),
                    'includeSubdomains': domain_config.get('includeSubdomains', 'false'),
                    'trustUserCerts': domain_config.get('trustUserCerts', 'false')
                }
                config['domain_configs'].append(dc_info)

            # 解析debug-overrides / Parse debug-overrides
            debug_overrides = root.find('.//debug-overrides')
            if debug_overrides is not None:
                config['debug_overrides'] = {
                    'trustUserCerts': debug_overrides.get('trustUserCerts', 'false')
                }

        except Exception:
            pass

        return config

    def _categorize_urls(self, urls: List[str]) -> Dict[str, List[str]]:
        """
        对URL进行分类 / Categorize URLs

        参数 / Args:
            urls: URL列表 / URL list

        返回 / Returns:
            Dict[str, List[str]]: 分类后的URL / Categorized URLs
        """
        categories = {
            'api': [],
            'cdn': [],
            'static': [],
            'social': [],
            'analytics': [],
            'other': []
        }

        for url in urls:
            url_lower = url.lower()

            if any(keyword in url_lower for keyword in ['api', 'graphql', 'rest']):
                categories['api'].append(url)
            elif any(keyword in url_lower for keyword in ['cdn', 'static', 'assets', 'images']):
                categories['cdn'].append(url)
            elif any(keyword in url_lower for keyword in ['analytics', 'track', 'stats', 'metrics']):
                categories['analytics'].append(url)
            elif any(keyword in url_lower for keyword in ['facebook', 'twitter', 'weibo', 'google']):
                categories['social'].append(url)
            else:
                categories['other'].append(url)

        return categories

    def _identify_api_patterns(self, api_endpoints: List[str], urls: List[str]) -> List[Dict]:
        """
        识别API端点模式 / Identify API endpoint patterns

        参数 / Args:
            api_endpoints: API端点列表 / API endpoint list
            urls: URL列表 / URL list

        返回 / Returns:
            List[Dict]: API模式列表 / API pattern list
        """
        patterns = []

        # 常见的API路径模式 / Common API path patterns
        api_patterns = [
            r'/api/.*',
            r'/v\d+/.*',
            r'/rest/.*',
            r'/graphql',
            r'/soap',
            r'/rpc'
        ]

        for endpoint in api_endpoints:
            for pattern in api_patterns:
                if re.match(pattern, endpoint, re.IGNORECASE):
                    patterns.append({
                        'endpoint': endpoint,
                        'pattern': pattern,
                        'type': 'api'
                    })
                    break

        return patterns

    # =========================================================================
    # 命令行接口 / Command Line Interface
    # =========================================================================

    @staticmethod
    def main():
        """命令行入口 / Command line entry point"""
        parser = argparse.ArgumentParser(
            description='网络流量捕获与分析模块 / Network Capture & Analysis Module',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
使用示例 / Usage examples:
  # 提取APK网络端点 / Extract APK network endpoints
  python network_capture.py extract endpoints app.apk

  # 分析PCAP流量 / Analyze PCAP traffic
  python network_capture.py analyze traffic capture.pcap

  # 生成Frida脚本 / Generate Frida script
  python network_capture.py generate frida-script

  # 获取网络统计 / Get network statistics
  python network_capture.py stats app.apk
            """
        )

        subparsers = parser.add_subparsers(dest='command', help='子命令 / Sub commands')

        # extract endpoints 命令 / extract endpoints command
        extract_parser = subparsers.add_parser('extract', help='提取网络端点 / Extract network endpoints')
        extract_parser.add_argument('apk_path', help='APK文件路径 / APK file path')
        extract_parser.add_argument('-o', '--output', help='输出JSON文件路径 / Output JSON file path')

        # analyze traffic 命令 / analyze traffic command
        analyze_parser = subparsers.add_parser('analyze', help='分析流量 / Analyze traffic')
        analyze_parser.add_argument('pcap_path', help='PCAP文件路径 / PCAP file path')
        analyze_parser.add_argument('-o', '--output', help='输出JSON文件路径 / Output JSON file path')

        # generate 命令 / generate command
        generate_parser = subparsers.add_parser('generate', help='生成脚本 / Generate scripts')
        generate_parser.add_argument('type', choices=['frida-script', 'hook'],
                                     help='生成类型 / Generation type')
        generate_parser.add_argument('-t', '--target', help='目标信息JSON / Target info JSON')
        generate_parser.add_argument('-o', '--output', help='输出文件路径 / Output file path')

        # stats 命令 / stats command
        stats_parser = subparsers.add_parser('stats', help='网络统计 / Network statistics')
        stats_parser.add_argument('apk_path', help='APK文件路径 / APK file path')
        stats_parser.add_argument('-o', '--output', help='输出JSON文件路径 / Output JSON file path')

        args = parser.parse_args()

        if not args.command:
            parser.print_help()
            return

        analyzer = NetworkAnalyzer()

        try:
            if args.command == 'extract':
                result = analyzer.extract_endpoints(args.apk_path)
                output = json.dumps(result, indent=2, ensure_ascii=False, default=str)
                if args.output:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(output)
                    print(f"结果已保存到 / Result saved to: {args.output}")
                else:
                    print(output)

            elif args.command == 'analyze':
                result = analyzer.analyze_traffic(args.pcap_path)
                output = json.dumps(result, indent=2, ensure_ascii=False, default=str)
                if args.output:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(output)
                    print(f"结果已保存到 / Result saved to: {args.output}")
                else:
                    print(output)

            elif args.command == 'generate':
                target_info = None
                if args.target:
                    with open(args.target, 'r', encoding='utf-8') as f:
                        target_info = json.load(f)

                result = analyzer.generate_hook_script(target_info)
                output = json.dumps(result, indent=2, ensure_ascii=False, default=str)

                if args.output:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(output)
                    print(f"结果已保存到 / Result saved to: {args.output}")
                else:
                    print(output)

            elif args.command == 'stats':
                result = analyzer.get_network_stats(args.apk_path)
                output = json.dumps(result, indent=2, ensure_ascii=False, default=str)
                if args.output:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(output)
                    print(f"结果已保存到 / Result saved to: {args.output}")
                else:
                    print(output)

        except Exception as e:
            print(f"错误 / Error: {e}", file=__import__('sys').stderr)
            __import__('sys').exit(1)


if __name__ == '__main__':
    NetworkAnalyzer.main()