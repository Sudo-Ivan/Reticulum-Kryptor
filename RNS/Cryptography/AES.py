# MIT License
#
# Copyright (c) 2022 Mark Qvist / unsigned.io
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import RNS.Cryptography.Provider as cp
import RNS.vendor.platformutils as pu
import serial

if cp.PROVIDER == cp.PROVIDER_INTERNAL:
    from .aes import AES
elif cp.PROVIDER == cp.PROVIDER_PYCA:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if pu.cryptography_old_api():
        from cryptography.hazmat.backends import default_backend

class KryptorHSM:
    def __init__(self):
        self.serial = serial.Serial('/dev/ttyUSB0', 115200)
    
    def camellia_encrypt(self, plaintext, key, iv):
        command = b'CAMELLIA_ENCRYPT' + key + iv + plaintext
        self.serial.write(command)
        return self.serial.read(len(plaintext))
    
    def camellia_decrypt(self, ciphertext, key, iv):
        command = b'CAMELLIA_DECRYPT' + key + iv + ciphertext
        self.serial.write(command)
        return self.serial.read(len(ciphertext))

kryptor_hsm = KryptorHSM()

class AES_128_CBC:
    @staticmethod
    def encrypt(plaintext, key, iv):
        try:
            return kryptor_hsm.camellia_encrypt(plaintext, key, iv)
        except Exception as e:
            print(f"Hardware encryption failed: {e}. Falling back to software.")
            if cp.PROVIDER == cp.PROVIDER_INTERNAL:
                cipher = AES(key)
                return cipher.encrypt(plaintext, iv)
            elif cp.PROVIDER == cp.PROVIDER_PYCA:
                if not pu.cryptography_old_api():
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                else:
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                return encryptor.update(plaintext) + encryptor.finalize()

    @staticmethod
    def decrypt(ciphertext, key, iv):
        try:
            return kryptor_hsm.camellia_decrypt(ciphertext, key, iv)
        except Exception as e:
            print(f"Hardware decryption failed: {e}. Falling back to software.")
            if cp.PROVIDER == cp.PROVIDER_INTERNAL:
                cipher = AES(key)
                return cipher.decrypt(ciphertext, iv)
            elif cp.PROVIDER == cp.PROVIDER_PYCA:
                if not pu.cryptography_old_api():
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                else:
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                return decryptor.update(ciphertext) + decryptor.finalize()