from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64, os


nonce_b64 = "NQqNQ5CbIb8GqWiY"
ciphertext_b64 = "o2kt"
tag_b64 = "na5CAC64azqJMFcnDJSGeg=="

nonce = base64.b64decode(nonce_b64)
ciphertext = base64.b64decode(ciphertext_b64)
tag = base64.b64decode(tag_b64)

fake_key = os.urandom(32)  # random AES key

decryptor = Cipher(algorithms.AES(fake_key), modes.GCM(nonce, tag)).decryptor()

plaintext = decryptor.update(ciphertext) + decryptor.finalize()
