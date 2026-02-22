from gcm import aes_gcm_encrypt

def hex_to_list(hex_str: str):
    """辅助函数：将十六进制字符串转换为整数列表"""
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

def list_to_hex(l: list):
    """辅助函数：将整数列表转换为十六进制字符串"""
    return "".join(f"{b:02x}" for b in l)

def test_aes_gcm():
    # 1. 准备测试数据 (Test Vector)
    # 密钥 (128-bit)
    key = hex_to_list("feffe9928665731c6d6a8f9467308308")
    # 初始化向量 IV (96-bit 是 GCM 的标准推荐长度)
    iv = hex_to_list("cafebabefacedbaddecaf888")
    # 明文
    plaintext = hex_to_list("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
    # 附加认证数据 AAD
    aad = hex_to_list("feedfacedeadbeeffeedfacedeadbeefabaddad2")

    print("--- AES-GCM 测试开始 ---")
    
    # 2. 调用你的加密函数
    # 期望返回结果应该是 (ciphertext, tag)
    ciphertext, tag = aes_gcm_encrypt(plaintext, key, iv, aad)

    # 3. 打印结果
    print(f"明文长度: {len(plaintext)} 字节")
    print(f"密文: {list_to_hex(ciphertext)}")
    print(f"验证标签 (Tag): {list_to_hex(tag)}")

    # 4. 验证（对比标准结果）
    # 这是该测试矢量的标准输出参考：
    expected_tag = "5bc94fbc3221a5db94fae95ae7121a47"
    
    if list_to_hex(tag) == expected_tag:
        print("\n✅ 测试通过！Tag 与 NIST 标准矢量匹配。")
    else:
        print(f"\n❌ 测试失败。")
        print(f"预期 Tag: {expected_tag}")
        print(f"实际 Tag: {list_to_hex(tag)}")

if __name__ == "__main__":
    test_aes_gcm()