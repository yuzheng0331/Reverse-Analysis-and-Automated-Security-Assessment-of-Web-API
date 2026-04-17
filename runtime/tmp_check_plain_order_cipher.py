import base64
from Crypto.Cipher import AES

key = bytes.fromhex("4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b")
iv = bytes.fromhex("49494949494949494949494949494949")

texts = [
    '{"username":"test_user","password":"test_pass"}',
    '{"password":"test_pass","username":"test_user"}',
]

rows = []
for t in texts:
    data = t.encode("utf-8")
    rem = len(data) % 16
    if rem != 0:
        data = data + (b"\x00" * (16 - rem))
    c = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    rows.append((t, base64.b64encode(c).decode("ascii")))

out_path = r"D:\Reverse Analysis and Automated Security Assessment of Web API\runtime\tmp_check_plain_order_cipher.json"
import json
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(rows, f, ensure_ascii=False, indent=2)

