import time, requests

BASE     = "http://127.0.0.1:5000"
EMAIL    = "ayahadri8@gmail.com"   # same user
PASSWORD = "12345678"
ENC_FILE = "testdata.bin.enc"

def get_jwt():
    r = requests.post(f"{BASE}/login",
                      json={"email":EMAIL, "password":PASSWORD})
    r.raise_for_status()
    return r.json()["token"]

def benchmark_decrypt(token):
    headers = {"x-access-token": token}
    data    = {"password": PASSWORD}
    with open(ENC_FILE, "rb") as f:
        start = time.time()
        r = requests.post(f"{BASE}/decrypt",
                          headers=headers,
                          files={"file": f},
                          data=data)
        r.raise_for_status()
        elapsed = time.time() - start
        dec_name = r.json()["decrypted"]
    print(f"Decrypt → {dec_name} took {elapsed:.2f}s")

def main():
    token = get_jwt()
    print("🔑 Token OK, running decryption…")
    benchmark_decrypt(token)

if __name__=="__main__":
    main()
