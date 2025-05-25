import time, requests

BASE       = "http://127.0.0.1:5000"
EMAIL      = "ayahadri8@gmail.com"   # ← your test user
PASSWORD   = "12345678"              # ← that user’s password
RAW_FILE   = "testdata.bin"
ENC_FILE   = RAW_FILE + ".enc"

def get_jwt():
    r = requests.post(f"{BASE}/login",
                      json={"email":EMAIL, "password":PASSWORD})
    r.raise_for_status()
    return r.json()["token"]

def benchmark_encrypt(token):
    headers = {"x-access-token": token}
    data    = {"password": PASSWORD}
    with open(RAW_FILE, "rb") as f:
        start = time.time()
        r = requests.post(f"{BASE}/encrypt",
                          headers=headers,
                          files={"file": f},
                          data=data)
        r.raise_for_status()
        elapsed = time.time() - start
        enc_name = r.json()["encrypted"]
    print(f"Encrypt → {enc_name} took {elapsed:.2f}s")

    # **Download** the .enc blob into cwd
    dl = requests.get(f"{BASE}/uploads/{enc_name}", headers=headers)
    dl.raise_for_status()
    with open(ENC_FILE, "wb") as out:
        out.write(dl.content)
    print(f"Saved encrypted file as ./{ENC_FILE}")

def main():
    token = get_jwt()
    print("🔑 Token OK, running encryption…")
    benchmark_encrypt(token)

if __name__=="__main__":
    main()
