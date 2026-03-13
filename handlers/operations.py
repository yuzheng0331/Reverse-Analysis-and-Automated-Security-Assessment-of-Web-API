#!/usr/bin/env python3
"""
Crypto Operations - 加密原语实现
=================================
实现常见的加密算法原语
"""

import base64
import hashlib
import hmac
import json
import binascii
from typing import Any

try:
    from Crypto.Cipher import AES, DES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
except ImportError:
    print("Warning: pycryptodome not installed. Run: pip install pycryptodome")

from .base import CryptoOperation, CryptoContext, HandlerResult
from .registry import register_operation


def _ensure_bytes(val: Any) -> bytes:
    """
    智能转换 Key/IV 为 bytes。
    如果看起来像 Hex 字符串 (且长度符合常见 Key/IV 尺寸)，尝试 unhexlify。
    否则按 utf-8 编码。
    """
    if isinstance(val, bytes):
        return val
    if not isinstance(val, str):
        return str(val).encode('utf-8')

    val = val.strip()
    # 尝试检测 Hex
    # AES Key: 16bytes(32hex), 24bytes(48hex), 32bytes(64hex)
    # AES IV / DES IV: 8bytes(16hex), 16bytes(32hex)
    target_lens = {16, 32, 48, 64}
    if len(val) in target_lens:
        try:
            # 只有当它是有效的 hex 且 unhex 后长度也就合理时才转换
            return binascii.unhexlify(val)
        except binascii.Error:
            pass

    return val.encode('utf-8')


def _rsa_encrypt_chunked(cipher: Any, plaintext: bytes, key_size_bytes: int) -> bytes:
    """对超长 RSA 明文执行 PKCS#1 v1.5 分块加密，避免单块长度超限。"""
    max_chunk = key_size_bytes - 11
    if max_chunk <= 0:
        raise ValueError("Invalid RSA key size")
    blocks = []
    for index in range(0, len(plaintext), max_chunk):
        chunk = plaintext[index:index + max_chunk]
        blocks.append(cipher.encrypt(chunk))
    return b"".join(blocks)


# =============================================================================
# Symmetric Encryption
# =============================================================================


@register_operation("aes_encrypt")
class AESEncryptOperation(CryptoOperation):
    """AES 加密操作"""

    def __init__(self):
        super().__init__("aes_encrypt")

    def validate_context(self, context: CryptoContext) -> tuple[bool, str]:
        if not context.key and not context.extra_params.get("key"):
             return False, "Missing key"
        if context.mode.upper() == "CBC" and not context.iv:
            return False, "CBC mode requires IV"
        if not context.plaintext:
            return False, "Missing plaintext"
        return True, None

    def execute(self, context: CryptoContext) -> HandlerResult:
        try:
            # 验证参数
            is_valid, error = self.validate_context(context)
            if not is_valid:
                return HandlerResult(success=False, error=error)

            # 获取参数并转换为 bytes (使用 _ensure_bytes 处理 Hex 情况)
            key = _ensure_bytes(context.key or context.extra_params.get("key"))
            iv = _ensure_bytes(context.iv or context.extra_params.get("iv"))

            mode_str = context.mode.upper() if context.mode else "CBC"

            # 选择模式
            if mode_str == "CBC":
                cipher = AES.new(key, AES.MODE_CBC, iv)
            elif mode_str == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
            else:
                return HandlerResult(success=False, error=f"Unsupported mode: {mode_str}")

            # 准备明文
            plaintext = context.plaintext
            if isinstance(plaintext, dict):
                plaintext = json.dumps(plaintext, separators=(',', ':'), ensure_ascii=False)
            if isinstance(plaintext, str):
                plaintext = plaintext.encode(context.input_encoding)

            # 填充
            block_size = AES.block_size
            plaintext = pad(plaintext, block_size)

            # 加密
            ciphertext = cipher.encrypt(plaintext)

            # 编码输出
            if context.output_encoding == "base64":
                output = base64.b64encode(ciphertext).decode('ascii')
            elif context.output_encoding == "hex":
                output = ciphertext.hex()
            else:
                output = ciphertext

            return HandlerResult(
                success=True,
                output=output,
                context=context,
                metadata={"algorithm": "AES", "mode": mode_str}
            )

        except Exception as e:
            return HandlerResult(success=False, error=str(e))


@register_operation("des_encrypt")
class DESEncryptOperation(CryptoOperation):
    """DES 加密操作"""

    def __init__(self):
        super().__init__("des_encrypt")

    def execute(self, context: CryptoContext) -> HandlerResult:
        try:
            key = _ensure_bytes(context.key or context.extra_params.get("key"))
            iv = _ensure_bytes(context.iv or context.extra_params.get("iv"))

            mode_str = context.mode.upper() if context.mode else "CBC"

            # 创建 cipher
            if mode_str == "CBC":
                cipher = DES.new(key, DES.MODE_CBC, iv)
            elif mode_str == "ECB":
                cipher = DES.new(key, DES.MODE_ECB)
            else:
                return HandlerResult(success=False, error=f"Unsupported mode: {mode_str}")

            # 准备明文
            plaintext = context.plaintext
            if isinstance(plaintext, dict):
                plaintext = json.dumps(plaintext, separators=(',', ':'))
            if isinstance(plaintext, str):
                plaintext = plaintext.encode(context.input_encoding)

            # 填充
            plaintext = pad(plaintext, DES.block_size)

            # 加密
            ciphertext = cipher.encrypt(plaintext)

            # 编码
            if context.output_encoding == "base64":
                output = base64.b64encode(ciphertext).decode('ascii')
            elif context.output_encoding == "hex":
                output = ciphertext.hex()
            else:
                output = ciphertext

            return HandlerResult(
                success=True,
                output=output,
                context=context,
                metadata={"algorithm": "DES", "mode": mode_str}
            )

        except Exception as e:
            return HandlerResult(success=False, error=str(e))


# =============================================================================
# Asymmetric Encryption
# =============================================================================


@register_operation("rsa_encrypt")
class RSAEncryptOperation(CryptoOperation):
    """RSA 加密操作"""

    def __init__(self):
        super().__init__("rsa_encrypt")

    def execute(self, context: CryptoContext) -> HandlerResult:
        try:
            # 获取公钥
            # Prioritize explicit public_key from extra_params (from pipeline config)
            # over context.key (which might be a symmetric key from previous step)
            public_key_pem = context.extra_params.get("public_key")
            if not public_key_pem:
                 public_key_pem = context.key

            if not public_key_pem:
                return HandlerResult(success=False, error="Missing public_key")

            # Robust PEM handling (Fix newlines and headers)
            if isinstance(public_key_pem, str):
                public_key_pem = public_key_pem.strip()
                if "\\n" in public_key_pem:
                    public_key_pem = public_key_pem.replace("\\n", "\n")

                # Check for headers
                if "-----BEGIN PUBLIC KEY-----" not in public_key_pem:
                     # Remove any existing headers if they are malformed? No.
                     # If it looks like base64, wrap it.
                     if not public_key_pem.startswith("-----"):
                          public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key_pem}\n-----END PUBLIC KEY-----"

                # Ensure correct encoding
                public_key_pem = public_key_pem.encode('utf-8')

            try:
                key = RSA.import_key(public_key_pem)
            except ValueError as ve:
                print(f"    [!] RSA Import Key Failed. Key snippet: {public_key_pem[:30]!r}...")
                raise ve

            cipher = PKCS1_v1_5.new(key)

            # 准备明文
            plaintext = context.plaintext
            # JSEncrypt often encrypts JSON string
            if isinstance(plaintext, dict):
                 # Standard JS dict to json string
                 plaintext = json.dumps(plaintext, separators=(',', ':'))

            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')

            # 加密：超长明文采用分块，避免 "Plaintext is too long"
            key_size_bytes = key.size_in_bytes()
            max_chunk = key_size_bytes - 11
            if len(plaintext) > max_chunk:
                ciphertext = _rsa_encrypt_chunked(cipher, plaintext, key_size_bytes)
            else:
                ciphertext = cipher.encrypt(plaintext)

            # 编码 (JSEncrypt outputs base64 by default)
            output = base64.b64encode(ciphertext).decode('ascii')

            return HandlerResult(
                success=True,
                output=output,
                context=context,
                metadata={"algorithm": "RSA"}
            )

        except Exception as e:
            return HandlerResult(success=False, error=str(e))


# =============================================================================
# Hash & MAC
# =============================================================================


@register_operation("md5")
class MD5Operation(CryptoOperation):
    """MD5 哈希"""

    def __init__(self):
        super().__init__("md5")

    def execute(self, context: CryptoContext) -> HandlerResult:
        try:
            plaintext = context.plaintext
            if isinstance(plaintext, dict):
                plaintext = json.dumps(plaintext, separators=(',', ':'), sort_keys=True)
            if isinstance(plaintext, str):
                plaintext = plaintext.encode(context.input_encoding)

            hash_obj = hashlib.md5(plaintext)

            if context.output_encoding == "hex":
                output = hash_obj.hexdigest()
            else:
                output = base64.b64encode(hash_obj.digest()).decode('ascii')

            return HandlerResult(success=True, output=output, context=context)

        except Exception as e:
            return HandlerResult(success=False, error=str(e))


@register_operation("sha256")
class SHA256Operation(CryptoOperation):
    """SHA256 哈希"""

    def __init__(self):
        super().__init__("sha256")

    def execute(self, context: CryptoContext) -> HandlerResult:
        try:
            plaintext = context.plaintext
            if isinstance(plaintext, dict):
                plaintext = json.dumps(plaintext, separators=(',', ':'), sort_keys=True)
            if isinstance(plaintext, str):
                plaintext = plaintext.encode(context.input_encoding)

            hash_obj = hashlib.sha256(plaintext)

            if context.output_encoding == "hex":
                output = hash_obj.hexdigest()
            else:
                output = base64.b64encode(hash_obj.digest()).decode('ascii')

            return HandlerResult(success=True, output=output, context=context)

        except Exception as e:
            return HandlerResult(success=False, error=str(e))


@register_operation("hmac_sha256")
class HMACSha256Operation(CryptoOperation):
    """HMAC-SHA256 签名"""

    def __init__(self):
        super().__init__("hmac_sha256")

    def execute(self, context: CryptoContext) -> HandlerResult:
        try:
            key = context.key or context.extra_params.get("key")
            if not key:
                return HandlerResult(success=False, error="Missing key for HMAC")

            plaintext = context.plaintext
            if isinstance(plaintext, dict):
                plaintext = json.dumps(plaintext, separators=(',', ':'), sort_keys=True)
            if isinstance(plaintext, str):
                plaintext = plaintext.encode(context.input_encoding)

            # HMAC Key usually string in JS context, NOT Hex bytes
            # JS: CryptoJS.HmacSHA256("Message", "Secret Passphrase")
            if isinstance(key, str):
                key = key.encode('utf-8')
            elif isinstance(key, bytes):
                pass
            else:
                key = str(key).encode('utf-8')

            signature = hmac.new(key, plaintext, hashlib.sha256).digest()

            # Fix: Default/Force Hex for HMAC (CryptoJS default toString is Hex)
            output = signature.hex()

            return HandlerResult(success=True, output=output, context=context)

        except Exception as e:
            return HandlerResult(success=False, error=str(e))


# =============================================================================
# Encoding
# =============================================================================


@register_operation("base64_encode")
class Base64EncodeOperation(CryptoOperation):
    """Base64 编码"""

    def __init__(self):
        super().__init__("base64_encode")

    def execute(self, context: CryptoContext) -> HandlerResult:
        try:
            data = context.plaintext
            if isinstance(data, str):
                data = data.encode(context.input_encoding)

            output = base64.b64encode(data).decode('ascii')
            return HandlerResult(success=True, output=output, context=context)

        except Exception as e:
            return HandlerResult(success=False, error=str(e))


@register_operation("hex_encode")
class HexEncodeOperation(CryptoOperation):
    """Hex 编码"""

    def __init__(self):
        super().__init__("hex_encode")

    def execute(self, context: CryptoContext) -> HandlerResult:
        try:
            data = context.plaintext
            if isinstance(data, str):
                data = data.encode(context.input_encoding)

            output = data.hex()
            return HandlerResult(success=True, output=output, context=context)

        except Exception as e:
            return HandlerResult(success=False, error=str(e))


@register_operation("variable_derivation")
class VariableDerivationOperation(CryptoOperation):
    """变量衍生逻辑执行器 (用于 Key/IV 动态生成)"""

    def __init__(self):
        super().__init__("variable_derivation")

    def execute(self, context: CryptoContext) -> HandlerResult:
        try:
            target = context.extra_params.get("target") # "key" or "iv"
            derivation_rule = context.extra_params.get("derivation")
            base_payload = context.extra_params.get("base_payload", {})

            if not target or not derivation_rule:
                return HandlerResult(success=False, error="Missing target or derivation rule")

            # 如果运行时已注入 key/iv，验证阶段优先使用捕获值，避免被本地随机衍生覆盖
            if target == "key" and context.key is not None:
                context.logs.append("Derived key skipped: using injected runtime key")
                return HandlerResult(success=True, output=context.plaintext, context=context)
            if target == "iv" and context.iv is not None:
                context.logs.append("Derived iv skipped: using injected runtime iv")
                return HandlerResult(success=True, output=context.plaintext, context=context)

            # 递归计算
            resolved_value = self._evaluate(derivation_rule, base_payload)

            # 更新上下文
            if target == "key":
                context.key = resolved_value
            elif target == "iv":
                context.iv = resolved_value

            # Record log
            context.logs.append(f"Derived {target}: {str(resolved_value)[:20]}...")

            return HandlerResult(success=True, output=context.plaintext, context=context)

        except Exception as e:
            return HandlerResult(success=False, error=f"Derivation failed: {str(e)}")

    def _evaluate(self, node, payload):
        node_type = node.get("type")

        if node_type == "source":
            key_name = node.get("value")
            # 尝试从 payload 获取
            val = payload.get(key_name)
            if val is None:
                raise ValueError(f"Source variable '{key_name}' not found in payload")
            return val

        if node_type == "literal":
            return node.get("value")

        if node_type == "binary_op":
            op = node.get("op")
            left = self._evaluate(node.get("left"), payload)
            right = self._evaluate(node.get("right"), payload)

            if op == "+":
                return str(left) + str(right)
            else:
                raise ValueError(f"Unsupported binary op: {op}")

        if node_type == "op":
            op_method = node.get("op")
            input_val = self._evaluate(node.get("input"), payload)
            args_nodes = node.get("args", [])
            args = [self._evaluate(arg, payload) for arg in args_nodes]

            if op_method == "slice":
                start = int(args[0])
                end = int(args[1])
                return str(input_val)[start:end]

            if op_method == "padEnd":
                width = int(args[0])
                fillchar = str(args[1]) if len(args) > 1 else " "
                s = str(input_val)
                if len(s) >= width:
                    return s
                needed = width - len(s)
                padding = (fillchar * needed)[:needed]
                return s + padding

            if op_method == "toString":
                return str(input_val)

            if "Utf8.parse" in str(op_method) or "parse" in str(op_method):
                return str(input_val).encode('utf-8')

            raise ValueError(f"Unsupported operation: {op_method}")

        raise ValueError(f"Unknown node type: {node_type}")

