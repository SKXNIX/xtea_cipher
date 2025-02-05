# XTEA

Алгоритм шифрования данных по алгоритму XTEA

### Пример использования:
```python
key = 3019480380
xtea = XTEA(key)

plaintext = "Hello, World!"
print(f"Plaintext: {plaintext}")

encrypted = xtea.encrypt(plaintext)
print(f"Encrypted: {encrypted}")

decrypted = xtea.decrypt(encrypted)
print(f"Decrypted: {decrypted}")
```
