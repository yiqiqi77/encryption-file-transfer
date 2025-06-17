import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import os
from encryption_core import (
    encrypt_with_aes, decrypt_with_aes,
    encrypt_with_rsa_aes, decrypt_with_rsa_aes
)
from network_transfer import NetworkTransfer  # 导入网络传输模块
from security_tools import SecurityTools  # 导入安全工具模块


class SecureZipApp:
    def __init__(self, root):
        """安全文件传输工具主类初始化"""
        self.root = root
        self.root.title("安全文件传输工具")
        self.root.geometry("600x600")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)  # 绑定窗口关闭事件

        # 初始化网络传输模块
        self.network_transfer = NetworkTransfer(
            on_status_update=self.show_status_message,
            on_file_received=self.choose_file_save_path
        )

        # 初始化安全工具模块
        self.security_tools = SecurityTools(
            on_status_update=self.show_status_message
        )

        # 连接状态标记
        self.path = ''  # 存储选择的文件/文件夹路径
        self.output_dir = os.getcwd()  # 默认输出目录为当前工作目录
        self.use_default_output_dir = tk.BooleanVar(value=True)  # 是否使用默认输出目录的标记

        # 配置界面样式
        style = ttk.Style()
        style.configure("TButton", font=("微软雅黑", 10), padding=6)
        style.configure("TLabel", font=("微软雅黑", 10))
        style.configure("TCheckbutton", font=("微软雅黑", 10))

        self.setup_ui()  # 初始化用户界面

    def setup_ui(self):
        """设置主界面布局"""
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill='both', expand=True)

        # 文件选择框架
        path_frame = ttk.LabelFrame(main_frame, text="文件选择", padding=10)
        path_frame.grid(row=0, column=0, sticky='ew', padx=5, pady=5)
        path_frame.columnconfigure(1, weight=1)  # 使第二列可扩展

        ttk.Label(path_frame, text="文件或文件夹:").grid(row=0, column=0, sticky='w')
        self.path_label = ttk.Label(path_frame, text="未选择", foreground="gray")
        self.path_label.grid(row=0, column=1, sticky='ew', padx=5)
        ttk.Button(path_frame, text="浏览", command=self.browse_file, width=10).grid(row=0, column=2, sticky='e')

        ttk.Label(path_frame, text="输出目录:").grid(row=1, column=0, sticky='w', pady=8)
        self.output_label = ttk.Label(path_frame, text=self.output_dir, foreground="gray")
        self.output_label.grid(row=1, column=1, sticky='ew', padx=5)
        ttk.Button(path_frame, text="选择目录", command=self.select_output_dir, width=10).grid(row=1, column=2,
                                                                                               sticky='e')

        # 进度条
        self.progress = ttk.Progressbar(main_frame, mode='determinate')
        self.progress.grid(row=1, column=0, sticky='ew', pady=(5, 10))

        # 标签页界面
        self.sections = ttk.Notebook(main_frame)
        self.sections.grid(row=2, column=0, sticky='nsew')
        main_frame.rowconfigure(2, weight=1)  # 使标签页区域可扩展
        main_frame.columnconfigure(0, weight=1)

        # 创建四个功能标签页
        self.aes_tab = ttk.Frame(self.sections, padding=15)
        self.rsa_tab = ttk.Frame(self.sections, padding=15)
        self.tools_tab = ttk.Frame(self.sections, padding=15)
        self.network_tab = ttk.Frame(self.sections, padding=15)

        self.sections.add(self.aes_tab, text="简单加密")
        self.sections.add(self.rsa_tab, text="混合加密")
        self.sections.add(self.tools_tab, text="工具箱")
        self.sections.add(self.network_tab, text="文件传输")

        # 初始化每个标签页的界面
        self.setup_aes_tab()
        self.setup_rsa_tab()
        self.setup_tools_tab()
        self.setup_network_tab()

    def setup_aes_tab(self):
        """设置AES加密标签页界面"""
        self.aes_tab.columnconfigure(1, weight=1)  # 使第二列可扩展

        ttk.Label(self.aes_tab, text="密码:").grid(row=0, column=0, sticky='w', pady=5)
        self.aes_password_var = tk.StringVar()  # 存储AES密码的变量
        # 密码输入框(默认显示为*)
        self.aes_password_entry = ttk.Entry(self.aes_tab, textvariable=self.aes_password_var, show='*')
        self.aes_password_entry.grid(row=0, column=1, sticky='ew', pady=5)

        self.show_password = tk.BooleanVar()  # 控制密码显示状态的变量
        # 显示/隐藏密码的复选框
        cb_show = ttk.Checkbutton(self.aes_tab, text="显示密码", variable=self.show_password,
                                  command=self.toggle_password)
        cb_show.grid(row=1, column=1, sticky='w')

        # 按钮框架
        btn_frame = ttk.Frame(self.aes_tab)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=15)
        ttk.Button(btn_frame, text="加密", command=self.aes_encrypt, width=15).grid(row=0, column=0, padx=10)
        ttk.Button(btn_frame, text="解密", command=self.aes_decrypt, width=15).grid(row=0, column=1, padx=10)

    def toggle_password(self):
        """切换密码输入框的显示状态"""
        # 根据复选框状态决定显示密码还是*
        self.aes_password_entry.config(show='' if self.show_password.get() else '*')

    def setup_rsa_tab(self):
        """设置RSA混合加密标签页界面"""
        for i, (text, cmd) in enumerate([
            ("生成密钥对", self.generate_rsa),
            ("公钥加密", self.rsa_encrypt),
            ("私钥解密", self.rsa_decrypt)
        ]):
            # 创建RSA功能按钮
            ttk.Button(self.rsa_tab, text=text, command=cmd, width=20).grid(row=i, column=0, pady=8, sticky='ew')

    def setup_tools_tab(self):
        """设置工具箱标签页界面"""
        for i, (text, cmd) in enumerate([
            ("计算 SHA256 校验码", self.sha256_calc),
            ("签名文件", self.sign),
            ("验证签名", self.verify)
        ]):
            # 创建工具功能按钮
            ttk.Button(self.tools_tab, text=text, command=cmd, width=25).grid(row=i, column=0, pady=8, sticky='ew')

    def setup_network_tab(self):
        """设置文件传输标签页界面"""
        # 创建独立的监听和连接按钮
        ttk.Button(self.network_tab, text="等待连接", command=self.network_transfer.start_listening, width=20).grid(
            row=0, column=0, pady=8)
        ttk.Button(self.network_tab, text="建立连接", command=self.connect_to_ip, width=20).grid(row=1, column=0,
                                                                                                 pady=8)
        ttk.Button(self.network_tab, text="发送文件", command=self.send_file, width=20).grid(row=2, column=0, pady=8)
        ttk.Button(self.network_tab, text="关闭连接", command=self.network_transfer.close_connection, width=20).grid(
            row=3, column=0, pady=8)

        # 选择是否使用默认输出目录的复选框
        ttk.Checkbutton(self.network_tab, text="保存至默认输出目录", variable=self.use_default_output_dir).grid(row=4,
                                                                                                                column=0,
                                                                                                                pady=8)

    def browse_file(self):
        """打开文件/文件夹选择对话框"""
        # 允许选择文件或文件夹
        path = filedialog.askopenfilename() or filedialog.askdirectory()
        if path:
            self.path = path
            self.path_label.config(text=path)  # 更新路径显示

    def select_output_dir(self):
        """打开输出目录选择对话框"""
        folder = filedialog.askdirectory(title="选择输出目录")
        if folder:
            self.output_dir = folder
            self.output_label.config(text=folder)  # 更新输出目录显示

    def aes_encrypt(self):
        """使用AES算法加密文件"""
        if not self.path:
            messagebox.showwarning("提示", "请先选择文件或文件夹")
            return
        password = self.aes_password_var.get()
        if not password:
            messagebox.showwarning("提示", "请输入加密密码")
            return

        self.progress.start()  # 启动进度条动画
        try:
            # 调用加密核心模块的AES加密函数
            encrypt_with_aes(self.path, password, self.output_dir)
            messagebox.showinfo("完成", "加密成功")
        except Exception as e:
            messagebox.showerror("失败", str(e))
        finally:
            self.progress.stop()  # 停止进度条动画

    def aes_decrypt(self):
        """使用AES算法解密文件"""
        if not self.path:
            messagebox.showwarning("提示", "请先选择加密文件")
            return
        password = self.aes_password_var.get()
        if not password:
            messagebox.showwarning("提示", "请输入解密密码")
            return

        self.progress.start()  # 启动进度条动画
        try:
            # 调用加密核心模块的AES解密函数
            decrypt_with_aes(self.path, password, self.output_dir)
            messagebox.showinfo("完成", "解密成功")
        except Exception as e:
            messagebox.showerror("失败", str(e))
        finally:
            self.progress.stop()  # 停止进度条动画

    def generate_rsa(self):
        """生成RSA密钥对"""
        folder = filedialog.askdirectory(title="选择保存密钥的文件夹")
        if folder:
            # 调用安全工具模块的RSA密钥生成函数
            self.security_tools.generate_rsa_keys(folder)

    def rsa_encrypt(self):
        """使用RSA+AES混合加密文件"""
        if not self.path:
            messagebox.showwarning("提示", "请先选择文件")
            return
        # 选择RSA公钥文件
        pub_path = filedialog.askopenfilename(title="选择公钥", filetypes=[("PEM", "*.pem")])
        if pub_path:
            self.progress.start()  # 启动进度条动画
            try:
                # 调用加密核心模块的混合加密函数
                encrypt_with_rsa_aes(self.path, pub_path, self.output_dir)
                messagebox.showinfo("完成", "加密成功")
            except Exception as e:
                messagebox.showerror("失败", str(e))
            finally:
                self.progress.stop()  # 停止进度条动画

    def rsa_decrypt(self):
        """使用RSA+AES混合解密文件"""
        if not self.path:
            messagebox.showwarning("提示", "请先选择加密文件")
            return
        # 选择RSA私钥文件
        priv_path = filedialog.askopenfilename(title="选择私钥", filetypes=[("PEM", "*.pem")])
        if priv_path:
            self.progress.start()  # 启动进度条动画
            try:
                # 调用加密核心模块的混合解密函数
                decrypt_with_rsa_aes(self.path, priv_path, self.output_dir)
                messagebox.showinfo("完成", "解密成功")
            except Exception as e:
                messagebox.showerror("失败", str(e))
            finally:
                self.progress.stop()  # 停止进度条动画

    def sha256_calc(self):
        """计算文件的SHA256哈希值"""
        if self.path:
            # 调用安全工具模块的SHA256计算函数
            self.security_tools.calculate_sha256(self.path)
        else:
            messagebox.showwarning("提示", "请先选择文件")

    def sign(self):
        """对文件进行数字签名"""
        if not self.path:
            messagebox.showwarning("提示", "请先选择文件")
            return
        # 选择RSA私钥文件
        priv = filedialog.askopenfilename(title="选择私钥", filetypes=[("PEM", "*.pem")])
        if priv:
            # 调用安全工具模块的签名函数
            self.security_tools.sign_file(self.path, priv)

    def verify(self):
        """验证文件的数字签名"""
        # 分别选择原始文件、签名文件和公钥文件
        filepath = filedialog.askopenfilename(title="选择原始文件")
        sigpath = filedialog.askopenfilename(title="选择签名文件", filetypes=[("SIG", "*.sig")])
        pub = filedialog.askopenfilename(title="选择公钥", filetypes=[("PEM", "*.pem")])
        if filepath and sigpath and pub:
            # 调用安全工具模块的签名验证函数
            self.security_tools.verify_signature(filepath, sigpath, pub)

    def connect_to_ip(self):
        """连接到指定IP(客户端)"""
        ip = simpledialog.askstring("连接设置", "请输入对方IP地址:")
        if ip:
            self.network_transfer.connect_to_ip(ip)

    def choose_file_save_path(self, filename):
        """选择文件保存路径(供网络传输模块调用)"""
        save_dir = self.output_dir if self.use_default_output_dir.get() else filedialog.askdirectory()
        if not save_dir:
            return None
        return os.path.join(save_dir, filename)

    def send_file(self):
        """通过网络发送文件"""
        if not self.network_transfer.client_socket:
            messagebox.showwarning("未连接", "请先建立连接")
            return

        if not self.path:
            messagebox.showwarning("提示", "请先选择文件")
            return

        # 询问用户是否对文件进行加密
        mode = messagebox.askyesnocancel("是否加密", "是否使用混合加密方式发送？\n是：加密发送\n否：直接发送\n取消：中止")
        if mode is None:
            return

        pub_key_path = None
        if mode:
            # 加密模式：选择对方公钥
            pub_key_path = filedialog.askopenfilename(title="选择对方公钥", filetypes=[("PEM", "*.pem")])
            if not pub_key_path:
                messagebox.showwarning("提示", "未选择公钥")
                return

        # 调用网络传输模块的发送文件功能
        self.network_transfer.send_file(
            self.path,
            use_encryption=mode,
            pub_key_path=pub_key_path,
            save_dir=None  # 使用临时目录
        )

    def show_status_message(self, message, status_type="info"):
        """显示状态消息(供网络传输模块和安全工具模块回调)"""
        # 根据状态类型显示不同的消息框
        if status_type == "info":
            messagebox.showinfo("状态", message)
        elif status_type == "warning":
            messagebox.showwarning("警告", message)
        elif status_type == "error":
            messagebox.showerror("错误", message)

    def on_closing(self):
        """窗口关闭时清理资源"""
        # 设置标志以抑制状态消息
        self.network_transfer.set_suppress_messages(True)
        self.network_transfer.close_connection()
        self.root.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    app = SecureZipApp(root)
    root.mainloop()
