from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import FileResponse
import base64
import os
import hashlib
import subprocess
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

app = FastAPI()

# Temporary Key Storage (Replace with a DB for production)
KEY_STORE = {}

# 📌 Models
class KeyGenerationRequest(BaseModel):
    key_type: str  # AES, RSA
    key_size: int  # AES: 256, RSA: 2048

class EncryptionRequest(BaseModel):
    key_id: str
    plaintext: str
    algorithm: str  # AES or RSA

class DecryptionRequest(BaseModel):
    key_id: str
    ciphertext: str
    algorithm: str

class HashGenerationRequest(BaseModel):
    data: str
    algorithm: str  # SHA-256 or SHA-512

class HashVerificationRequest(BaseModel):
    data: str
    hash_value: str
    algorithm: str

# 📌 Root and Favicon
@app.get("/")
def read_root():
    return {"message": "Welcome to the Crypto API. Visit /docs for Swagger UI."}

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse("path/to/favicon.ico")  # Optional, replace if needed

# 📌 Internal Key Generation
@app.post("/generate-key")
def generate_key(request: KeyGenerationRequest):
    key_id = str(len(KEY_STORE) + 1)

    if request.key_type.upper() == "AES":
        key = get_random_bytes(request.key_size // 8)
        key_value = base64.b64encode(key).decode()

    elif request.key_type.upper() == "RSA":
        key = RSA.generate(request.key_size)
        key_value = base64.b64encode(key.export_key(format='PEM')).decode()

    else:
        raise HTTPException(status_code=400, detail="Unsupported key type.")

    KEY_STORE[key_id] = key
    return {"key_id": key_id, "key_value": key_value}

# 📌 OpenSSL Key Generation
@app.post("/generate-openssl-key")
def generate_openssl_key():
    key_id = str(len(KEY_STORE) + 1)
    key_dir = f"openssl_keys/key_{key_id}"
    os.makedirs(key_dir, exist_ok=True)

    private_key_path = os.path.join(key_dir, "private.pem")
    public_key_path = os.path.join(key_dir, "public.pem")

    subprocess.run(["openssl", "genrsa", "-out", private_key_path, "2048"], check=True)
    subprocess.run(["openssl", "rsa", "-in", private_key_path, "-pubout", "-out", public_key_path], check=True)

    with open(private_key_path, "rb") as f:
        private_key = base64.b64encode(f.read()).decode()
    with open(public_key_path, "rb") as f:
        public_key = base64.b64encode(f.read()).decode()

    KEY_STORE[key_id] = {
        "type": "OpenSSL",
        "private_path": private_key_path,
        "public_path": public_key_path
    }

    return {"key_id": key_id, "private_key": private_key, "public_key": public_key}

# 📌 Internal Encryption
@app.post("/encrypt")
def encrypt(request: EncryptionRequest):
    if request.key_id not in KEY_STORE:
        raise HTTPException(status_code=404, detail="Key not found.")

    key = KEY_STORE[request.key_id]

    if request.algorithm.upper() == "AES":
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = request.plaintext.encode() + b" " * (16 - len(request.plaintext) % 16)
        ciphertext = iv + cipher.encrypt(padded)

    elif request.algorithm.upper() == "RSA":
        public_key = key.publickey()
        ciphertext = public_key.encrypt(
            request.plaintext.encode(),
            None
        )[0]

    else:
        raise HTTPException(status_code=400, detail="Unsupported algorithm.")

    return {"ciphertext": base64.b64encode(ciphertext).decode()}

# 📌 Internal Decryption
@app.post("/decrypt")
def decrypt(request: DecryptionRequest):
    if request.key_id not in KEY_STORE:
        raise HTTPException(status_code=404, detail="Key not found.")

    key = KEY_STORE[request.key_id]
    ciphertext = base64.b64decode(request.ciphertext)

    if request.algorithm.upper() == "AES":
        iv, ct = ciphertext[:16], ciphertext[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ct).rstrip(b" ").decode()

    elif request.algorithm.upper() == "RSA":
        plaintext = key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

    else:
        raise HTTPException(status_code=400, detail="Unsupported algorithm.")

    return {"plaintext": plaintext}

# 📌 OpenSSL RSA Encryption
@app.post("/openssl/encrypt")
def openssl_encrypt(request: EncryptionRequest):
    if request.key_id not in KEY_STORE or KEY_STORE[request.key_id]["type"] != "OpenSSL":
        raise HTTPException(status_code=404, detail="OpenSSL RSA key not found.")

    public_key_path = KEY_STORE[request.key_id]["public_path"]
    key_dir = f"openssl_keys/key_{request.key_id}"
    plain_path = os.path.join(key_dir, "plaintext.txt")
    cipher_path = os.path.join(key_dir, "ciphertext.bin")

    with open(plain_path, "w") as f:
        f.write(request.plaintext)

    subprocess.run([
        "openssl", "rsautl",
        "-encrypt",
        "-pubin",
        "-inkey", public_key_path,
        "-in", plain_path,
        "-out", cipher_path
    ], check=True)

    with open(cipher_path, "rb") as f:
        ciphertext = base64.b64encode(f.read()).decode()

    return {"ciphertext": ciphertext}

# 📌 OpenSSL RSA Decryption
@app.post("/openssl/decrypt")
def openssl_decrypt(request: DecryptionRequest):
    if request.key_id not in KEY_STORE or KEY_STORE[request.key_id]["type"] != "OpenSSL":
        raise HTTPException(status_code=404, detail="OpenSSL RSA key not found.")

    private_key_path = KEY_STORE[request.key_id]["private_path"]
    key_dir = f"openssl_keys/key_{request.key_id}"
    cipher_path = os.path.join(key_dir, "ciphertext.bin")
    decrypted_path = os.path.join(key_dir, "decrypted.txt")

    with open(cipher_path, "wb") as f:
        f.write(base64.b64decode(request.ciphertext))

    subprocess.run([
        "openssl", "rsautl",
        "-decrypt",
        "-inkey", private_key_path,
        "-in", cipher_path,
        "-out", decrypted_path
    ], check=True)

    with open(decrypted_path, "r") as f:
        plaintext = f.read()

    return {"plaintext": plaintext}

# 📌 Hashing
@app.post("/generate-hash")
def generate_hash(request: HashGenerationRequest):
    if request.algorithm.upper() == "SHA-256":
        digest = hashlib.sha256(request.data.encode()).digest()
    elif request.algorithm.upper() == "SHA-512":
        digest = hashlib.sha512(request.data.encode()).digest()
    else:
        raise HTTPException(status_code=400, detail="Unsupported algorithm.")

    return {"hash_value": base64.b64encode(digest).decode(), "algorithm": request.algorithm}

@app.post("/verify-hash")
def verify_hash(request: HashVerificationRequest):
    if request.algorithm.upper() == "SHA-256":
        expected = hashlib.sha256(request.data.encode()).digest()
    elif request.algorithm.upper() == "SHA-512":
        expected = hashlib.sha512(request.data.encode()).digest()
    else:
        raise HTTPException(status_code=400, detail="Unsupported algorithm.")

    is_valid = base64.b64encode(expected).decode() == request.hash_value
    return {"is_valid": is_valid, "message": "Hash matches the data." if is_valid else "Hash does not match."}

# 📌 Run
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
