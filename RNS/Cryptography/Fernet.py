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

import os
import time
import serial

from RNS.Cryptography import HMAC
from RNS.Cryptography import PKCS7
from RNS.Cryptography.AES import AES_128_CBC

class KryptorHSM:
    def __init__(self):
        self.serial = serial.Serial('/dev/ttyUSB0', 115200)
    
    def generate_random(self, length):
        self.serial.write(b'GENERATE_RANDOM' + length.to_bytes(2, 'big'))
        return self.serial.read(length)
    
    def camellia_encrypt(self, plaintext, key, iv):
        command = b'CAMELLIA_ENCRYPT' + key + iv + plaintext
        self.serial.write(command)
        return self.serial.read(len(plaintext))
    
    def camellia_decrypt(self, ciphertext, key, iv):
        command = b'CAMELLIA_DECRYPT' + key + iv + ciphertext
        self.serial.write(command)
        return self.serial.read(len(ciphertext))
    
    def hmac(self, key, data):
        command = b'HMAC' + key + data
        self.serial.write(command)
        return self.serial.read(32)

kryptor_hsm = KryptorHSM()

class Fernet():
    FERNET_OVERHEAD = 48

    @staticmethod
    def generate_key():
        return kryptor_hsm.generate_random(32)

    def __init__(self, key=None):
        if key is None:
            raise ValueError("Token key cannot be None")

        if len(key) != 32:
            raise ValueError("Token key must be 32 bytes, not "+str(len(key)))
            
        self._signing_key = key[:16]
        self._encryption_key = key[16:]

    def verify_hmac(self, token):
        if len(token) <= 32:
            raise ValueError("Cannot verify HMAC on token of only "+str(len(token))+" bytes")
        else:
            received_hmac = token[-32:]
            expected_hmac = kryptor_hsm.hmac(self._signing_key, token[:-32])

            return received_hmac == expected_hmac

    def encrypt(self, data=None):
        iv = kryptor_hsm.generate_random(16)

        if not isinstance(data, bytes):
            raise TypeError("Token plaintext input must be bytes")

        try:
            ciphertext = kryptor_hsm.camellia_encrypt(
                plaintext=PKCS7.pad(data),
                key=self._encryption_key,
                iv=iv,
            )
        except Exception as e:
            print(f"Hardware encryption failed: {e}. Falling back to software.")
            ciphertext = AES_128_CBC.encrypt(
                plaintext=PKCS7.pad(data),
                key=self._encryption_key,
                iv=iv,
            )

        signed_parts = iv + ciphertext

        try:
            hmac = kryptor_hsm.hmac(self._signing_key, signed_parts)
        except Exception as e:
            print(f"Hardware HMAC failed: {e}. Falling back to software.")
            hmac = HMAC.new(self._signing_key, signed_parts).digest()

        return signed_parts + hmac

    def decrypt(self, token=None):
        if not isinstance(token, bytes):
            raise TypeError("Token must be bytes")

        if not self.verify_hmac(token):
            raise ValueError("Token HMAC was invalid")

        iv = token[:16]
        ciphertext = token[16:-32]

        try:
            try:
                plaintext = PKCS7.unpad(
                    kryptor_hsm.camellia_decrypt(
                        ciphertext,
                        self._encryption_key,
                        iv,
                    )
                )
            except Exception as e:
                print(f"Hardware decryption failed: {e}. Falling back to software.")
                plaintext = PKCS7.unpad(
                    AES_128_CBC.decrypt(
                        ciphertext,
                        self._encryption_key,
                        iv,
                    )
                )

            return plaintext

        except Exception as e:
            raise ValueError("Could not decrypt token")