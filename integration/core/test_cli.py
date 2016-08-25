import requests
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


URL = 'http://localhost:8181'
CREATE_URL = URL + "/v1-secrets/secrets/create"
REWRAP_URL = URL + "/v1-secrets/secrets/rewrap"

secret_data = {
        "clearText": "hello",
        "backend": "none"
        }

insecure_private_key = '''-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAlqXgL8UtupeafCFVQwckREfGN+KM3M+tiY0CLsd847w3B3MI
rwurSDvBRZMvriYz7LCQIrrXTri8XZC0LNvRdkkHr9HWNPwA1eB8DLRORPIp0H4I
9XwLHP76qaKJY2Af2vL8Oq0paSiSwtCaN983JNwyDXmgGKYv0K+6byUv6AVtiQS8
8kOylCnrSKkui7nzcFuoLR/RwuLCxoK9jmAGBNJCG/16u9eFnaElJ1kCcnS0XsdJ
Biy60lWgnMLwlGel0vGZXjTOdAF1xMHZAHSq2Y0k82brNvxLNQSdnV1TjU70rSYO
Li/hoNep978UR76Fv2ZdBY8Ft06N09N4JNanWwIDAQABAoIBAFDlEdWVFFE2R4aQ
f7BWjWr8/7vSs8F+47kRNzLXfIDt+L7PTsJwibFoJQivWNMzQH7A8SU1H5juKngz
1AyinX/fB3mqPFSHXgt7WCGaUM1FHJ8Qjs8DpRQU95VP6maqn3B7OmZnxezqFKT4
T1fhTUNF2rrRrN6Pnu1476vvVCJKtPJcAqG4IIE01jrvZ/jD1wiZ+s3fpJN0Q/j3
FEkWP0B+KPAbE9viEK+aKX0eO2Jkq7xZYgslQRV1TrCooQ5U2+/xBypGrggHloK/
5/apjteJxwljyZMBRFXoX3Yl6Y2y/TXg2fYTTKo323IVLx/080REYjOXcGujp5Sy
cXJ7SsECgYEAxrzXmfO9E718bjilUBT1t2fy2gch+tubDsQeMwXD57sIgSE4Sr7k
xkaHW6FfgA0rtj94CkMW00509ny7HkyaFNkwrkrC/0R/gUIo0E31fgxTM2cO3urI
QXFw1lmFVsE9/uppgF5L9ktSe8TJz7fMp8iHV+1N7FDyuoNSoFp6/bcCgYEAwg3f
Hni3I5JgRI6MX5j1HquUt76PqI7CYeqRmqcHBSg6d5u1Y0P2Fulh4gdYIX8QrGi2
5viSaTZQt9DVATF4pKs2XMPZc9QooudYTSUhRDAnRfdYFa0E56rtL2L/RXTbZj7S
jYdmMrMBvB9mY+RbLTeWK7yG53IzaidJVp6tY30CgYBo8zbkPRwffZRlXJKoTLlK
BqHv0451PF2RGa5dAXFoQZQHJTTl/BMyRfKbSAf3xnzL/I521OEL68XGmS3znT5N
PjkAAckiJtkyuG53OoQm8XlKjuUCgXgJX0/YUmQg4WHM6ZuXR7TTtwkzBUQR5p00
Cai3nUDmSAU2y7zpo36J1wKBgEZtVGGxu/27/RZEieuUDroP2YyKK4coMKHqyOdQ
4Tpc7ENGjqE1JBYSo4St161oeTupUWAoLLLklIzxzKx/MOLKhJNMPRpNkGX3AlQV
OqqNs2MwLpbHUXVm0mgVTMH/dDT6bd4RmuShlOqalsWANhsGBolfBbLv/nrzQSmf
sxvdAoGALwb3fP9ir2Fs3vHn4fCpiuNoCovWExbhH+UtQ/kDYuXsjt1Th7cxuLPF
FNH/hPpMSf5p6Gl4Ipl12s5U6FVYQlmuVlFgV8iUEKsSkMWdrvvx5X38RlgqQqvU
+7k/Qphbh1dQWKCpMXmeMxRWTtgaftz18zvou6k0CyCSNco6JZ4=
-----END RSA PRIVATE KEY-----'''

insecure_public_key = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlqXgL8UtupeafCFVQwck
REfGN+KM3M+tiY0CLsd847w3B3MIrwurSDvBRZMvriYz7LCQIrrXTri8XZC0LNvR
dkkHr9HWNPwA1eB8DLRORPIp0H4I9XwLHP76qaKJY2Af2vL8Oq0paSiSwtCaN983
JNwyDXmgGKYv0K+6byUv6AVtiQS88kOylCnrSKkui7nzcFuoLR/RwuLCxoK9jmAG
BNJCG/16u9eFnaElJ1kCcnS0XsdJBiy60lWgnMLwlGel0vGZXjTOdAF1xMHZAHSq
2Y0k82brNvxLNQSdnV1TjU70rSYOLi/hoNep978UR76Fv2ZdBY8Ft06N09N4JNan
WwIDAQAB
-----END PUBLIC KEY-----'''


def get_expected_encrypted_value(p_key, value):
    key = RSA.importKey(p_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(value)


def get_decrypted_value(p_key, val):
    key = RSA.importKey(p_key)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    return cipher.decrypt(val)


def python_post_response(url, json):
    secret = requests.post(url, json=json)
    assert secret.status_code == requests.codes.ok
    return secret.json()


def test_secrets_create_api_none_backend():
    json_secret = python_post_response(CREATE_URL, secret_data)
    expected_encoded = base64.b64encode(secret_data["clearText"])

    assert expected_encoded == json_secret["cipherText"]
    assert "" == json_secret["clearText"]


def test_secrets_rewrap_api_none_backend():
    json_secret = python_post_response(CREATE_URL, secret_data)
    json_secret["rewrapKey"] = insecure_public_key

    json_rewrapped_secret = python_post_response(REWRAP_URL, json_secret)
    print("{}\n".format(json_rewrapped_secret))

    assert "" == json_rewrapped_secret["clearText"]
    assert "" == json_rewrapped_secret["cipherText"]

    print(base64.b64decode(json_rewrapped_secret["rewrapText"]) + '\n')
    plain_text = get_decrypted_value(insecure_private_key,
                                     base64.b64decode(
                                         json_rewrapped_secret["rewrapText"]))

    assert secret_data["clearText"] == plain_text
