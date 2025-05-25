# perf_test_badpw.py
import requests

BASE     = "http://127.0.0.1:5000"
EMAIL    = "ayahadri8@gmail.com"   # your test user
PASSWORD = "12345678"              # correct password
BAD_PW   = "wrong-password"
ENC_FILE = "testdata.bin.enc"

def get_jwt():
    r = requests.post(f"{BASE}/login",
                      json={"email": EMAIL, "password": PASSWORD})
    r.raise_for_status()
    return r.json()["token"]

def test_wrong_password(token):
    headers = {"x-access-token": token}
    # Attempt decrypt with an incorrect password
    with open(ENC_FILE, "rb") as f:
        r = requests.post(f"{BASE}/decrypt",
                          headers=headers,
                          files={"file": f},
                          data={"password": BAD_PW})
    if r.status_code == 400:
        print("✅ Wrong-password correctly rejected:", r.json().get("message"))
    else:
        print("❌ Unexpected response:", r.status_code, r.text)

def main():
    token = get_jwt()
    print("🔑 Token OK, testing bad-password…")
    test_wrong_password(token)

if __name__ == "__main__":
    main()
