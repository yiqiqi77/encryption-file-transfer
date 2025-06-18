import os
from encryption_core import (
    generate_rsa_keys,
    sign_file,
    verify_signature,
    sha256sum
)
import logging


class SecurityTools:
    def __init__(self, on_status_update=None):
        """安全工具模块初始化

        参数:
            on_status_update: 状态更新回调函数
        """
        self.on_status_update = on_status_update
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def generate_rsa_keys(self, output_dir):
        """生成RSA密钥对（不加密私钥）

        参数:
            output_dir: 密钥对保存目录

        返回:
            (private_key_path, public_key_path): 密钥文件路径元组，失败时返回(None, None)
        """
        try:
            # 确保输出目录存在
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                self.logger.info(f"创建密钥保存目录: {output_dir}")

            # 调用底层密钥生成函数（不传递密码参数）
            generate_rsa_keys(output_dir)

            # 构建密钥文件完整路径
            private_key_path = os.path.join(output_dir, "private_key.pem")
            public_key_path = os.path.join(output_dir, "public_key.pem")

            # 验证文件是否生成成功
            if not all([os.path.exists(private_key_path), os.path.exists(public_key_path)]):
                raise FileNotFoundError("密钥文件生成失败")

            # 生成成功提示
            status_msg = "RSA密钥对已生成:\n"
            status_msg += f"私钥: {private_key_path}\n"
            status_msg += f"公钥: {public_key_path}"

            self._show_status(status_msg, "info")
            self.logger.info(status_msg)

            return private_key_path, public_key_path

        except Exception as e:
            error_msg = f"生成RSA密钥对失败: {str(e)}"
            self._show_status(error_msg, "error")
            self.logger.error(error_msg)
            return None, None

    def sign_file(self, file_path, private_key_path):
        """对文件进行数字签名

        参数:
            file_path: 要签名的文件路径
            private_key_path: 私钥文件路径

        返回:
            bool: 签名是否成功
        """
        try:
            if not os.path.exists(file_path):
                self._show_status(f"文件不存在: {file_path}", "error")
                return False

            if not os.path.exists(private_key_path):
                self._show_status(f"私钥文件不存在: {private_key_path}", "error")
                return False

            signature_path = sign_file(file_path, private_key_path)
            self._show_status(f"文件签名成功，签名文件: {signature_path}", "info")
            return True
        except Exception as e:
            self._show_status(f"签名失败: {str(e)}", "error")
            return False

    def verify_signature(self, file_path, signature_path, public_key_path):
        """验证文件的数字签名

        参数:
            file_path: 原始文件路径
            signature_path: 签名文件路径
            public_key_path: 公钥文件路径

        返回:
            bool: 签名是否有效
        """
        try:
            if not os.path.exists(file_path):
                self._show_status(f"文件不存在: {file_path}", "error")
                return False

            if not os.path.exists(signature_path):
                self._show_status(f"签名文件不存在: {signature_path}", "error")
                return False

            if not os.path.exists(public_key_path):
                self._show_status(f"公钥文件不存在: {public_key_path}", "error")
                return False

            valid = verify_signature(file_path, signature_path, public_key_path)
            status = "有效" if valid else "无效"
            self._show_status(f"签名验证结果: {status}", "info")
            return valid
        except Exception as e:
            self._show_status(f"验证失败: {str(e)}", "error")
            return False

    def calculate_sha256(self, file_path):
        """计算文件的SHA256哈希值

        参数:
            file_path: 文件路径

        返回:
            str: 文件的SHA256哈希值，失败时返回None
        """
        try:
            if not os.path.exists(file_path):
                self._show_status(f"文件不存在: {file_path}", "error")
                return None

            hash_value = sha256sum(file_path)
            self._show_status(f"SHA256哈希值: {hash_value}", "info")
            return hash_value
        except Exception as e:
            self._show_status(f"计算哈希值失败: {str(e)}", "error")
            return None

    def _show_status(self, message, status_type="info"):
        """显示状态消息(通过回调函数)

        参数:
            message: 状态消息内容
            status_type: 状态类型(info/warning/error)
        """
        if self.on_status_update:
            self.on_status_update(message, status_type)
        # 同时记录到日志
        if status_type == "info":
            self.logger.info(message)
        elif status_type == "warning":
            self.logger.warning(message)
        elif status_type == "error":
            self.logger.error(message)

