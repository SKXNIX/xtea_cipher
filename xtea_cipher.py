from pydoc import plain
import struct


def _long2bytes(n, blocksize=0):
    """long to bytes string"""
    s = b""
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffff) + s
        n = n >> 32
    # Удаление ведущих нулей
    for i in range(len(s)):
        if s[i] != b'\x00'[0]:
            break
    else:
        # происходит только тогда, когда n == 0
        s = b'\x00'
        i = 0
    s = s[i:]
    # Возвращение несколько байтов заполнения.  
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b'\x00' + s
    return s

def _bytes2long(raw):
    """bytes string to long"""
    unpack = struct.unpack
    res = 0
    for b in raw:
        if isinstance(b, int):
            b = bytes([b])
        res = (res << 8) | unpack('B', b)[0]
    return res


class XTEA:
    def __init__(self, key: int):
        # Конвертация строкового ключа в тип int
        if isinstance(key, str):
            nk = ""
            for s in list(key):
                nk += str(ord(s))
            key = int(nk)
        # Разделение ключа на 4 части по 32 бита каждая.
        self.key = [0] * 4
        for i in range(4):
            self.key[i] = key & 0xFFFFFFFF
            key >>= 32

    def _encrypt_block(self, v):
        # Шифрование одного блока из 64 бит.
        v0, v1 = v[0], v[1]
        sum = 0
        delta = 0x9E3779B9
        n = 32
        while n > 0:
            sum = (sum + delta) & 0xFFFFFFFF
            v0 = (v0 + ((v1 << 4 ^ v1 >> 5) + v1 ^ sum + self.key[sum & 3])) & 0xFFFFFFFF
            v1 = (v1 + ((v0 << 4 ^ v0 >> 5) + v0 ^ sum + self.key[(sum >> 11) & 3])) & 0xFFFFFFFF
            n -= 1
        return (v0, v1)

    def _decrypt_block(self, v):
        """Дешифрование одного блока из 64 бит."""
        v0, v1 = v[0], v[1]
        sum = 0xC6EF3720  # 0xFFFFFFFF - delta*32
        delta = 0x9E3779B9
        n = 32
        while n > 0:
            v1 = (v1 - ((v0 << 4 ^ v0 >> 5) + v0 ^ sum + self.key[(sum >> 11) & 3])) & 0xFFFFFFFF
            v0 = (v0 - ((v1 << 4 ^ v1 >> 5) + v1 ^ sum + self.key[sum & 3])) & 0xFFFFFFFF
            sum = (sum - delta) & 0xFFFFFFFF
            n -= 1
        return (v0, v1)

    def encrypt(self, plaintext: str) -> bytes:
        """Шифрование всего текста."""
        plaintext = bytes(plaintext.encode())
        if len(plaintext) % 8 != 0:
            plaintext += b'\x00' * (8 - len(plaintext) % 8)
        ciphertext = b""
        for i in range(0, len(plaintext), 8):
            block = plaintext[i:i+8]
            v0 = _bytes2long(block[:4])
            v1 = _bytes2long(block[4:])
            v0, v1 = self._encrypt_block((v0, v1))
            ciphertext += _long2bytes(v0, 4) + _long2bytes(v1, 4)
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> str:
        """Дешифрование всего текста."""
        plaintext = b""
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            v0 = _bytes2long(block[:4])
            v1 = _bytes2long(block[4:])
            v0, v1 = self._decrypt_block((v0, v1))
            plaintext += _long2bytes(v0, 4) + _long2bytes(v1, 4)
        return str(plaintext.rstrip(b'\x00'))[2:-1]


if __name__ == "__main__":
    pass