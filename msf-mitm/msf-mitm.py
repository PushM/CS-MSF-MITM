import Crypto.PublicKey.RSA
import Crypto.Cipher.PKCS1_v1_5
import Crypto.Cipher.PKCS1_OAEP
import Crypto.Cipher.AES
import Crypto.Util.Padding
import uuid
import binascii
from Crypto.Cipher import AES
from msfconsts import *



class BeaconKey:
    def __init__(self, aesKey, publicKey):
        self.aesKey = aesKey
        self.publicKey = publicKey

    def __str__(self):
        return f"BeaconKey(aesKey={self.aesKey}, publicKey={self.publicKey})"
    
# 读取文件到dict的代码:
def load_beacon_keys(beacon_key_file):
    try:
        dict_beacon_key = {}
        with open(beacon_key_file, 'r') as f:
            for line in f:
                ip, pubkey, aeskey = line.strip().split(',')
                dict_beacon_key[ip] = BeaconKey(aeskey, pubkey)
        return dict_beacon_key
    except FileNotFoundError:
        return {}
    


def RSADecrypt(key, data):
    oPrivateKey = Crypto.PublicKey.RSA.importKey(binascii.a2b_hex(key))
    oRSAPrivateKey = Crypto.Cipher.PKCS1_v1_5.new(oPrivateKey)
    ciphertext = data
    try:
        cleartext = oRSAPrivateKey.decrypt(ciphertext, None)
    except ValueError:
        return None
    if cleartext == b'':
        return None   
    return cleartext

"""
实现RSAEncrypt
"""
def RSAEncrypt(key, data):
    # 将十六进制的公钥转换为二进制，并导入为 RSA 公钥对象
    oPublicKey = Crypto.PublicKey.RSA.importKey(binascii.a2b_hex(key))
    oRSAPublicKey = Crypto.Cipher.PKCS1_v1_5.new(oPublicKey)

    # 加密数据
    encrypted_data = oRSAPublicKey.encrypt(data)

    return encrypted_data


def RSADecrypt_PKCS1_OAEP(key, data):
    oPrivateKey = Crypto.PublicKey.RSA.importKey(binascii.a2b_hex(key))
    oRSAPrivateKey = Crypto.Cipher.PKCS1_OAEP.new(oPrivateKey)
    ciphertext = data
    # try:
    cleartext = oRSAPrivateKey.decrypt(ciphertext)
    # except ValueError as e:
    #     print(e)
    #     return None
    if cleartext == b'':
        return None   
    return cleartext

"""
实现RSAEncrypt
"""
def RSAEncrypt_PKCS1_OAEP(key, data):
    # 将十六进制的公钥转换为二进制，并导入为 RSA 公钥对象
    oPublicKey = Crypto.PublicKey.RSA.importKey(binascii.a2b_hex(key))
    oRSAPublicKey = Crypto.Cipher.PKCS1_OAEP.new(oPublicKey)

    # 加密数据
    encrypted_data = oRSAPublicKey.encrypt(data)

    return encrypted_data

def xor(buf, key):
    return bytes([x ^ key[i % len(key)] for i, x in enumerate(buf)])





class Addon:

    def __init__(self):
        self.exporter = None
        self.beacon_key_file = "msf_beacon_keys.txt"
        self.dict_beacon_key = {}
        print(self.dict_beacon_key)

       
    from mitmproxy import http

    def request(self, flow) -> None:

        if flow.request.content != b'':
            print(f"request")
            ori_request = flow.request.content
            modify_message = self.parse_msf(ori_request, flow)
            if modify_message != b'':
                flow.request.set_content(modify_message)
           
            # print(ori_request)
        

    def response(self, flow):
        if flow.response.raw_content != b'':
            print(f"response")
            ori_response = flow.response.raw_content
            modify_message = self.parse_msf(ori_response, flow)
            print(modify_message)
            if modify_message != b'':
                # print("modify_message")
                flow.response.set_content(modify_message)
                
        
    def parse_msf(self, ori_message, flow):
        stream = ori_message
        i = 0
        modify_stream = b""
        while i < len(stream):
            xor_head = stream[i:i+32]
            xor_key = xor_head[:4]
            head = xor(xor_head, xor_key)
            session_guid = head[4:20]
            enc_flag = int.from_bytes(head[20:24], "big")
            packet_len = int.from_bytes(head[24:28], "big")
            packet_type = int.from_bytes(head[28:32], "big")

            try :
                print(f"Packet: type={packet_types[packet_type]:<4} len={packet_len:<8} enc={enc_types[enc_flag]} sess={uuid.UUID(bytes=session_guid)}")
            except Exception as e:
                print(f"Packet: type={packet_type} len={packet_len:<8} enc={enc_flag} sess={uuid.UUID(bytes=session_guid)}")
                
            tlv_data = xor(stream[i+32:i+packet_len+24], xor_key)
            if enc_flag == 1:
                aes_iv = tlv_data[:16]
                session_aes_key = self.dict_beacon_key[flow.client_conn.address[0]].aesKey
                cipher = AES.new(session_aes_key, AES.MODE_CBC, iv=aes_iv)
                tlv_data = cipher.decrypt(tlv_data[16:])

            j = 0
            while j < len(tlv_data):
                l = int.from_bytes(tlv_data[j:j+4], 'big')
                if j + l > len(tlv_data) or l == 0:
                    break
                t = int.from_bytes(tlv_data[j+4:j+8], 'big')
                v = tlv_data[j+8:j+l]
                if t == 0x20001: #COMMAND_ID
                    v = cmd_ids[int.from_bytes(v[:4], 'big')]
                elif t == 0x40034: #CHANNEL_DATA
                    with open('docs_backup.zip', 'ab') as f:
                        f.write(v)
                
                
                # if tlv_types[t] == "TLV_TYPE_RSA_PUB_KEY":
                if t == (TLV_META_TYPE_RAW     | 550):

                    # modify the pub key
                    print("TLV_TYPE_RSA_PUB_KEY modify")
                    print(stream.hex())
                    
                    # 定位到pubkey在stream中的开始位置
                    pubkey_start = j + 8
                    pubkey_end = j + l
                    # 修改pubkey
                    beaconKey = BeaconKey(None, v.hex())
                    self.dict_beacon_key[flow.client_conn.address[0]] = beaconKey
                    
                    my_pk_xor = xor(binascii.a2b_hex(my_pk), xor_key)
                    # 不能先把pubkey进行xor，因为这个xor是4个bytes，有可能pubkey的start不是4的倍数
                    modify_tlv_data = tlv_data[:pubkey_start] + binascii.a2b_hex(my_pk) + tlv_data[pubkey_end:]
                    modify_tlv_data_xor = xor(modify_tlv_data, xor_key)
                    modify_stream = stream[:i+32] + modify_tlv_data_xor

                    print(f"modify_xor_pubkey:{modify_tlv_data_xor[pubkey_start:pubkey_end].hex()}")
                    print(modify_stream.hex())


                # if tlv_types[t] == "TLV_TYPE_ENC_SYM_KEY":
                if t == (TLV_META_TYPE_RAW     | 553):
                    print("TLV_TYPE_ENC_SYM_KEY modify")
                    # 用自己的sk解密aes key
                    print(f"TLV l={l:<8} t={tlv_types[t]:<26} v={v}")
                    # my_sk_bytes = binascii.a2b_hex(my_sk)
                    aes_key = RSADecrypt(my_sk, v)
                    print(f"aes_key:{aes_key}")
                    beaconKey = self.dict_beacon_key[flow.client_conn.address[0]]
                    beaconKey.aesKey = aes_key
                    # 缓存到本地txt
                    with open(self.beacon_key_file, 'a') as f:
                            f.write(f"{flow.client_conn.address[0]},{beaconKey.publicKey},{beaconKey.aesKey}\n")

                    # 再用之前msf的pk加密
                    msf_pk = beaconKey.publicKey
                    aeskey_enc_by_msf_pubkey= RSAEncrypt(msf_pk, aes_key)

                    # 替换发送给msf server端的aes key
                    aeskey_start = j + 8
                    aeskey_end = j + l
                    modify_tlv_data = tlv_data[:aeskey_start] + aeskey_enc_by_msf_pubkey + tlv_data[aeskey_end:]
                    modify_tlv_data_xor = xor(modify_tlv_data, xor_key)
                    modify_stream = stream[:i+32] + modify_tlv_data_xor


                if len(v) > 50:
                    v = v[:50]
                if t in tlv_types:
                    print(f"TLV l={l:<8} t={tlv_types[t]:<26} v={v}")
                else:
                    print(f"TLV l={l:<8} t={t:<26} v={v}")
                j += l
            
            i += 24 + packet_len
        return modify_stream



addons = [Addon()]

