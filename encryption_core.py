import os
import hashlib
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def sha256sum(filepath):
    """计算文件的SHA-256哈希值

    参数:
        filepath: 要计算哈希的文件路径

    返回:
        十六进制格式的SHA-256哈希值字符串
    """
    h = hashlib.sha256()
    # 分块读取文件以处理大文件
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()


def generate_rsa_keys(folder):
    """生成RSA密钥对并保存到指定文件夹

    参数:
        folder: 保存密钥的文件夹路径

    生成文件:
        private_key.pem - 私钥文件(需妥善保管)
        public_key.pem - 公钥文件(可公开)
    """
    # 生成私钥(2048位强度)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # 将私钥序列化为PEM格式
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # 未加密存储，实际应用建议加密
    )

    # 将公钥序列化为PEM格式
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 保存密钥到文件
    with open(os.path.join(folder, "private_key.pem"), 'wb') as f:
        f.write(priv_bytes)
    with open(os.path.join(folder, "public_key.pem"), 'wb') as f:
        f.write(pub_bytes)


def derive_key(password, salt):
    """从密码派生加密密钥(使用PBKDF2-HMAC-SHA256)

    参数:
        password: 用户提供的密码字符串
        salt: 随机盐值(16字节)

    返回:
        派生的32字节加密密钥
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 生成32字节(256位)密钥
        salt=salt,
        iterations=100000,  # 迭代10万次，平衡安全性和性能
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_with_aes(filepath, password, output_dir):
    """使用AES-CFB算法加密文件(基于密码)

    参数:
        filepath: 待加密的文件路径
        password: 用户密码(用于派生密钥)
        output_dir: 加密文件输出目录

    返回:
        加密后的文件路径
    """
    # 生成随机盐值和初始化向量
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(16)

    # 创建AES-CFB加密器
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 读取并加密文件内容
    with open(filepath, 'rb') as f:
        plaintext = f.read()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # 输出格式: [盐值(16字节)][IV(16字节)][密文]
    output_path = os.path.join(output_dir, os.path.basename(filepath) + ".enc")
    with open(output_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    return output_path


def decrypt_with_aes(filepath, password, output_dir):
    """使用AES-CFB算法解密文件(基于密码)

    参数:
        filepath: 待解密的文件路径
        password: 用户密码(用于派生密钥)
        output_dir: 解密文件输出目录

    返回:
        解密后的文件路径
    """
    # 读取加密文件
    with open(filepath, 'rb') as f:
        raw = f.read()
    # 解析数据结构: [盐值(16字节)][IV(16字节)][密文]
    salt, iv, ciphertext = raw[:16], raw[16:32], raw[32:]
    key = derive_key(password, salt)

    # 创建AES-CFB解密器
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # 生成输出文件名(移除.enc后缀)
    original_filename = os.path.basename(filepath)
    if original_filename.endswith(".enc"):
        output_filename = original_filename[:-4]
    else:
        output_filename = original_filename + ".dec"

    output_path = os.path.join(output_dir, output_filename)
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    return output_path


def encrypt_with_rsa_aes(filepath, pub_key_path, output_dir):
    """混合加密: 使用RSA加密AES密钥，使用AES加密文件内容

    参数:
        filepath: 待加密的文件路径
        pub_key_path: RSA公钥文件路径
        output_dir: 加密文件输出目录

    返回:
        加密后的文件路径

    加密结构:
        [RSA加密的AES密钥长度(4字节)][RSA加密的AES密钥][AES IV(16字节)][AES加密的文件内容]
    """
    # 文件路径检查
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"源文件不存在: {filepath}")

    if not os.path.isfile(pub_key_path):
        raise FileNotFoundError(f"公钥文件不存在: {pub_key_path}")

    # 确保输出目录存在
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 加载RSA公钥
    with open(pub_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())

    # 生成一次性AES密钥和IV
    aes_key = secrets.token_bytes(32)  # 256位AES密钥
    iv = secrets.token_bytes(16)

    # 读取文件内容
    with open(filepath, 'rb') as f:
        plaintext = f.read()

    # 使用AES-CFB加密文件内容
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # 使用RSA-OAEP加密AES密钥
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 构建输出文件结构
    output_path = os.path.join(output_dir, os.path.basename(filepath) + ".rsa.enc")
    with open(output_path, 'wb') as f:
        f.write(len(encrypted_key).to_bytes(4, 'big'))  # 写入密钥长度(4字节)
        f.write(encrypted_key)  # 写入RSA加密的AES密钥
        f.write(iv)  # 写入AES初始化向量
        f.write(ciphertext)  # 写入AES加密的文件内容

    return output_path


def decrypt_with_rsa_aes(filepath, priv_key_path, output_dir):
    """混合解密: 使用RSA解密AES密钥，使用AES解密文件内容

    参数:
        filepath: 待解密的文件路径
        priv_key_path: RSA私钥文件路径
        output_dir: 解密文件输出目录

    返回:
        解密后的文件路径
    """
    # 加载RSA私钥
    with open(priv_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # 读取加密文件
    with open(filepath, 'rb') as f:
        data = f.read()

    # 解析文件结构
    key_len = int.from_bytes(data[:4], 'big')  # 读取密钥长度
    encrypted_key = data[4:4 + key_len]  # 读取RSA加密的AES密钥
    iv = data[4 + key_len:4 + key_len + 16]  # 读取AES初始化向量
    ciphertext = data[4 + key_len + 16:]  # 读取AES加密的文件内容

    # 使用RSA-OAEP解密AES密钥
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 使用AES-CFB解密文件内容
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # 生成输出文件名(移除.rsa.enc后缀)
    original_filename = os.path.basename(filepath)
    if original_filename.endswith(".rsa.enc"):
        output_filename = original_filename[:-8]
    else:
        output_filename = original_filename + ".dec"

    output_path = os.path.join(output_dir, output_filename)
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    return output_path


def sign_file(filepath, privkey_path):
    """使用RSA私钥对文件内容进行数字签名

    参数:
        filepath: 待签名的文件路径
        privkey_path: RSA私钥文件路径

    返回:
        签名文件路径(原文件名+.sig)
    """
    # 读取文件内容
    with open(filepath, 'rb') as f:
        data = f.read()

    # 加载RSA私钥
    with open(privkey_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # 使用PSS填充和SHA-256哈希进行签名
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),  # 掩码生成函数
            salt_length=padding.PSS.MAX_LENGTH  # 最大盐长度
        ),
        hashes.SHA256()
    )

    # 保存签名到文件
    with open(filepath + '.sig', 'wb') as f:
        f.write(signature)

    return filepath + '.sig'


def verify_signature(filepath, sigpath, pubkey_path):
    """验证文件的数字签名

    参数:
        filepath: 原始文件路径
        sigpath: 签名文件路径
        pubkey_path: RSA公钥文件路径

    返回:
        True: 签名验证通过
        False: 签名验证失败
    """
    # 读取文件内容、签名和公钥
    with open(filepath, 'rb') as f:
        data = f.read()
    with open(sigpath, 'rb') as f:
        signature = f.read()
    with open(pubkey_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        # 验证签名
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # 验证成功
    except Exception:
        return False  # 验证失败
