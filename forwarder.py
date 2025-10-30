# forwarder.py
# -*- coding: utf-8 -*-

import asyncio
import re
import socket
import time
import datetime
import os
import sys

# 从共享模块导入所有需要的变量和函数
from shared_state import (
    ACTIVE_CONNS, DEVICE_USAGE, SETTINGS, CONFIG, GLOBAL_BYTES_SENT, GLOBAL_BYTES_RECEIVED,
    print
)

# 定义响应常量
FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\n\r\nOK'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\r\n\r\n'

def set_socket_options_from_writer(writer: asyncio.StreamWriter):
    """为给定的StreamWriter设置TCP套接字选项。"""
    sock = writer.get_extra_info('socket')
    if sock:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # 根据系统设置 keep-alive 参数 (Linux)
            if sys.platform == "linux" or sys.platform == "linux2":
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        except OSError as e:
            print(f"[*] Could not set socket options: {e}")

async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, key: str, counter: str, is_upload: bool):
    """数据管道，负责在两个流之间转发数据并统计流量。"""
    global GLOBAL_BYTES_SENT, GLOBAL_BYTES_RECEIVED
    buffer_size = SETTINGS.get("buffer_size", 8192)
    timeout = SETTINGS.get("timeout", 300)
    device_id = ACTIVE_CONNS.get(key, {}).get('device_id')
    
    try:
        while True:
            data = await asyncio.wait_for(src.read(buffer_size), timeout=timeout)
            if not data:
                break
            
            data_len = len(data)
            
            # 更新全局流量
            if is_upload:
                GLOBAL_BYTES_SENT += data_len
            else:
                GLOBAL_BYTES_RECEIVED += data_len
            
            # 更新连接特定流量
            if key in ACTIVE_CONNS:
                ACTIVE_CONNS[key][counter] += data_len
            
            # 更新设备特定流量
            if device_id and device_id in DEVICE_USAGE:
                DEVICE_USAGE[device_id] += data_len
                
            dst.write(data)
            await dst.drain()
            
    except asyncio.TimeoutError:
        print(f"[-] Pipe timeout for {key} (device: {device_id})")
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    except Exception as e:
        if "Bad file descriptor" not in str(e): # 忽略套接字已关闭的常见错误
            print(f"[!] Pipe error for {key} (device: {device_id}): {type(e).__name__} - {e}")
    finally:
        if dst:
            try:
                dst.close()
                await dst.wait_closed()
            except Exception:
                pass # 忽略关闭错误

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    """处理新的客户端连接：握手、验证和转发。"""
    
    set_socket_options_from_writer(writer)
    
    peer = writer.get_extra_info('peername')
    if not peer:
        print("[!] Could not get peer address, closing.")
        writer.close(); await writer.wait_closed(); return
        
    ip_str, port = peer[0], peer[1]
    conn_key = f"{ip_str}:{port}"
    pipe_tasks = []
    
    try:
        # --- 1. IP 黑白名单检查 ---
        if SETTINGS.get("enable_ip_blacklist") and ip_str in SETTINGS.get("ip_blacklist", []):
            print(f"[-] Forbidden: {ip_str} is in blacklist.")
            writer.write(FORBIDDEN_RESPONSE); await writer.drain()
            return
        if SETTINGS.get("enable_ip_whitelist") and ip_str not in SETTINGS.get("ip_whitelist", []):
            print(f"[-] Forbidden: {ip_str} is not in whitelist.")
            writer.write(FORBIDDEN_RESPONSE); await writer.drain()
            return

        # --- 2. 握手和头部解析 ---
        full_request = b''
        forwarding_started = False
        
        while not forwarding_started:
            data_chunk = await asyncio.wait_for(reader.read(SETTINGS.get("buffer_size", 8192)), timeout=10.0)
            if not data_chunk:
                break
                
            full_request += data_chunk
            header_end_index = full_request.find(b'\r\n\r\n')
            
            if header_end_index != -1:
                headers_raw = full_request[:header_end_index]
                rest = full_request[header_end_index + 4:]
                headers_text = headers_raw.decode('latin-1')
                break
            
            # 如果请求太大且未找到头部，则视为无效
            if len(full_request) > 8192:
                raise ValueError("Request too large without headers.")
        else:
            # 客户端在发送完整头部之前断开连接
            return

        # --- 3. 验证逻辑 ---
        device_id = None
        device_info = {}
        host_header = None
        
        # 3a. 解析头部
        ua_value = ""
        for line in headers_text.split('\r\n'):
            if line.lower().startswith('user-agent:'):
                ua_value = line.split(':', 1)[1].strip()
            elif line.lower().startswith('host:'):
                host_header = line.split(':', 1)[1].strip()

        # 3b. 检查是否为 WebSocket 升级请求 (基于UA关键字)
        ua_probe = SETTINGS.get("ua_keyword_probe", "1.0")
        ua_ws = SETTINGS.get("ua_keyword_ws", "26.4.0")
        
        if ua_probe in ua_value and ua_ws not in ua_value:
            # 探测请求，返回 200 OK
            writer.write(FIRST_RESPONSE); await writer.drain()
            return
        
        if ua_ws not in ua_value:
            # 既不是探测也不是WS，返回 403
            print(f"[-] Forbidden: {ip_str} UA '{ua_value}' did not match WS keyword.")
            writer.write(FORBIDDEN_RESPONSE); await writer.drain()
            return

        # 3c. 设备 ID 认证 (如果启用)
        if SETTINGS.get("enable_device_id_auth"):
            # 假设 device_id 在 User-Agent 中
            # (注意: 这是一个示例, 实际中可能在 'Sec-WebSocket-Protocol' 或 'Authorization' 中)
            match = re.search(r'DeviceID/([\w-]+)', ua_value)
            device_id = match.group(1) if match else None
            
            if not device_id or device_id not in CONFIG.get("device_ids", {}):
                print(f"[-] Forbidden: {ip_str} invalid or missing DeviceID.")
                writer.write(FORBIDDEN_RESPONSE); await writer.drain()
                return
            
            device_info = CONFIG["device_ids"][device_id]

            # 3d. 检查设备状态 (过期, 超额, 暂停)
            now = datetime.datetime.utcnow().date()
            expiry_date = datetime.datetime.strptime(device_info.get("expiry_date", "1970-01-01"), '%Y-%m-%d').date()
            limit_gb = device_info.get("limit_gb", 0)
            used_bytes = DEVICE_USAGE.get(device_id, 0)
            
            if device_info.get("status") == "paused":
                print(f"[-] Forbidden: {ip_str} DeviceID {device_id} is paused.")
                writer.write(FORBIDDEN_RESPONSE); await writer.drain()
                return
            if expiry_date < now:
                print(f"[-] Forbidden: {ip_str} DeviceID {device_id} expired on {expiry_date}.")
                writer.write(FORBIDDEN_RESPONSE); await writer.drain()
                return
            if limit_gb > 0 and (used_bytes / (1024**3)) >= limit_gb:
                print(f"[-] Forbidden: {ip_str} DeviceID {device_id} exceeded quota ({limit_gb} GB).")
                writer.write(FORBIDDEN_RESPONSE); await writer.drain()
                return

            # 3e. 检查并发连接
            if not SETTINGS.get("allow_simultaneous_connections", False):
                existing_conn = next((k for k, v in ACTIVE_CONNS.items() if v.get('device_id') == device_id), None)
                if existing_conn:
                    print(f"[-] Forbidden: {ip_str} DeviceID {device_id} already connected from {existing_conn}.")
                    writer.write(FORBIDDEN_RESPONSE); await writer.drain()
                    return

        # --- 4. 验证通过，建立连接 ---
        writer.write(SWITCH_RESPONSE)
        await writer.drain()
        
        # 记录活动连接
        ACTIVE_CONNS[conn_key] = {
            'device_id': device_id,
            'start_time': time.time(),
            'bytes_sent': 0,
            'bytes_received': 0,
            'tls': tls
        }
        
        # --- 5. 建立到目标服务器的管道 ---
        target_host = SETTINGS.get("default_target_host", "127.0.0.1")
        target_port = SETTINGS.get("default_target_port", 22)
        target = (target_host, target_port)

        if host_header:
            try:
                host, port_str = host_header.split(':', 1) if ':' in host_header else (host_header, target_port)
                target = (host.strip(), int(port_str))
            except ValueError:
                print(f"[!] Invalid Host header format: '{host_header}'")
                return

        print(f"[*] Tunneling {ip_str} -> {target[0]}:{target[1]} (Device: {device_id or 'N/A'})")
        tr, tw = await asyncio.open_connection(*target)
        
        if rest: tw.write(rest); await tw.drain()
        
        pipe_tasks = [
            asyncio.create_task(pipe(reader, tw, conn_key, 'bytes_sent', True)),
            asyncio.create_task(pipe(tr, writer, conn_key, 'bytes_received', False))
        ]
        await asyncio.wait(pipe_tasks, return_when=asyncio.FIRST_COMPLETED)

    except (ValueError, asyncio.TimeoutError) as e:
        print(f"[-] Handshake failed for {ip_str}: {e}")
    except Exception as e:
        if not isinstance(e, (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError)):
            print(f"[!] Unhandled error in handle_client for {ip_str}: {type(e).__name__} - {e}")
    finally:
        if conn_key in ACTIVE_CONNS:
            ACTIVE_CONNS.pop(conn_key, None)
        for t in pipe_tasks:
            if not t.done():
                t.cancel()
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
