import socket
import threading
import shutil
import tempfile
import zipfile
from encryption_core import encrypt_with_rsa_aes
import os


class NetworkTransfer:
    def __init__(self, on_status_update=None, on_file_received=None):
        """网络文件传输模块初始化

        参数:
            on_status_update: 状态更新回调函数
            on_file_received: 文件接收完成回调函数
        """
        self.is_listening = False
        self.is_connected = False
        self.client_socket = None
        self.server_socket = None
        self.listening_thread = None
        self.receive_thread = None
        self.on_status_update = on_status_update
        self.on_file_received = on_file_received
        self.suppress_status_messages = False

    def start_listening(self):
        """启动监听模式(服务器端)"""
        if self.is_listening or self.is_connected:
            self._show_status("已处于连接或监听状态")
            return

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', 12345))
            self.server_socket.listen(1)
            self.server_socket.settimeout(1)  # 设置超时，实现非阻塞监听
            self.is_listening = True

            self._show_status("正在监听端口12345...")
            self.listening_thread = threading.Thread(target=self.accept_connections, daemon=True)
            self.listening_thread.start()

        except Exception as e:
            self._show_status(f"监听启动失败: {str(e)}", "error")
            self.stop_listening()

    def accept_connections(self):
        """接受客户端连接(监听线程)"""
        while self.is_listening and self.server_socket:
            try:
                conn, addr = self.server_socket.accept()
                self.stop_listening()  # 停止监听
                self.client_socket = conn
                self.is_connected = True

                self._show_status(f"已连接: {addr[0]}:{addr[1]}", "info")
                self.start_receive_thread()  # 启动接收线程

            except socket.timeout:
                continue  # 超时继续检查退出标志
            except Exception as e:
                if self.is_listening:
                    self._show_status(f"连接错误: {str(e)}", "error")
                break

        self._update_connection_status()

    def connect_to_ip(self, ip):
        """连接到指定IP(客户端)"""
        if self.is_listening or self.is_connected:
            self._show_status("已处于连接或监听状态")
            return

        if not ip:
            self._show_status("IP地址不能为空")
            return

        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((ip, 12345))
            self.is_connected = True

            self._show_status(f"已连接到 {ip}:12345", "info")
            self.start_receive_thread()  # 启动接收线程

        except Exception as e:
            self._show_status(f"连接到 {ip} 失败: {str(e)}", "error")
            self.close_connection()

        self._update_connection_status()

    def start_receive_thread(self):
        """启动文件接收线程"""
        self.receive_thread = threading.Thread(target=self.receive_files, daemon=True)
        self.receive_thread.start()

    def receive_files(self):
        """文件接收线程"""
        try:
            while self.is_connected and self.client_socket:
                try:
                    # 接收文件元数据
                    name_len_bytes = self.client_socket.recv(4)
                    if not name_len_bytes or not self.is_connected:
                        break
                    name_len = int.from_bytes(name_len_bytes, 'big')
                    filename = self.client_socket.recv(name_len).decode()

                    size_bytes = self.client_socket.recv(8)
                    if not size_bytes or not self.is_connected:
                        break
                    filesize = int.from_bytes(size_bytes, 'big')

                    # 选择保存路径需要在UI层处理，这里通过回调传递
                    if self.on_file_received:
                        save_path = self.on_file_received(filename)
                        if not save_path or not self.is_connected:
                            return

                        filepath = save_path
                        with open(filepath, 'wb') as f:
                            remaining = filesize
                            while remaining > 0 and self.is_connected:
                                chunk = self.client_socket.recv(min(4096, remaining))
                                if not chunk or not self.is_connected:
                                    break
                                f.write(chunk)
                                remaining -= len(chunk)

                        if self.is_connected:
                            self._show_status(f"文件已保存: {filepath}", "info")

                except (ConnectionResetError, socket.timeout):
                    self._show_status("对方已断开连接", "info")
                    break
                except Exception as e:
                    if self.is_connected:
                        self._show_status(f"接收错误: {str(e)}", "error")
                    break

        finally:
            self.close_connection()

    def send_file(self, file_path, use_encryption=True, pub_key_path=None, save_dir=None):
        """通过网络发送文件

        参数:
            file_path: 要发送的文件路径
            use_encryption: 是否使用加密
            pub_key_path: 公钥路径(加密时使用)
            save_dir: 临时文件保存目录
        """
        if not self.client_socket:
            self._show_status("请先建立连接", "warning")
            return

        if not file_path or not os.path.exists(file_path):
            self._show_status("请选择有效的文件或文件夹", "warning")
            return

        tmp_dir = tempfile.mkdtemp() if save_dir is None else save_dir
        try:
            if use_encryption and pub_key_path:
                # 加密模式：使用RSA+AES混合加密
                send_path = encrypt_with_rsa_aes(file_path, pub_key_path, tmp_dir)
                filename = os.path.basename(send_path)
            else:
                # 明文模式：如果是文件夹则先压缩
                if os.path.isdir(file_path):
                    zip_path = os.path.join(tmp_dir, 'plain_folder')
                    shutil.make_archive(zip_path, 'zip', file_path)
                    send_path = zip_path + '.zip'
                else:
                    # 复制文件到临时目录
                    send_path = os.path.join(tmp_dir, os.path.basename(file_path))
                    shutil.copy(file_path, send_path)
                filename = os.path.basename(send_path)

            # 读取文件数据
            with open(send_path, 'rb') as f:
                data = f.read()

            # 发送文件元数据和内容(协议设计)
            self.client_socket.send(len(filename.encode()).to_bytes(4, 'big'))
            self.client_socket.send(filename.encode())
            self.client_socket.send(len(data).to_bytes(8, 'big'))
            self.client_socket.sendall(data)

            self._show_status(f"文件已发送：{filename}", "info")
        except Exception as e:
            self._show_status(f"发送失败: {str(e)}", "error")
        finally:
            # 清理临时文件
            if save_dir is None:
                shutil.rmtree(tmp_dir)

    def stop_listening(self):
        """停止监听"""
        self.is_listening = False
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None

    def close_connection(self):
        """关闭所有连接"""
        self.is_connected = False
        self.is_listening = False

        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None

        self.stop_listening()

        # 只有在非退出程序时才更新状态消息
        if not self.suppress_status_messages:
            self._update_connection_status()
        else:
            # 程序退出时不显示消息
            pass

    def _show_status(self, message, status_type="info"):
        """显示状态消息(通过回调函数)"""
        if self.on_status_update:
            self.on_status_update(message, status_type)

    def _update_connection_status(self):
        """更新连接状态(通过回调函数)"""
        if not self.suppress_status_messages and self.on_status_update:
            if self.is_connected:
                self.on_status_update("已连接，可发送/接收文件", "info")
            elif self.is_listening:
                self.on_status_update("正在监听，等待连接...", "info")
            else:
                self.on_status_update("未连接", "info")

    def set_suppress_messages(self, suppress):
        """设置是否抑制状态消息"""
        self.suppress_status_messages = suppress
