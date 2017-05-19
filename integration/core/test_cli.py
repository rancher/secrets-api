import requests
import base64
import pytest
import hashlib
import hvac

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


URL = 'http://localhost:8181'
ALT_URL = 'http://localhost:18181'

VAULT_STORAGE_URL = 'http://127.0.0.1:18200'

CREATE_URL = URL + "/v1-secrets/secrets/create"
REWRAP_URL = URL + "/v1-secrets/secrets/rewrap"


def get_create_url(url=URL):
    return url + "/v1-secrets/secrets/create"


def get_delete_url(url=URL):
    return url + "/v1-secrets/secrets/purge"


def get_rewrap_url(url=URL):
    return url + "/v1-secrets/secrets/rewrap"


secret_data = {
        "type": "secret",
        "name": "secret1",
        "clearText": "hello",
        "backend": "none"
        }

secret_b64_data = {
        "type": "secret",
        "name": "secret1",
        "clearText": "aGVsbG8=",
        "backend": "none"
        }


secrets_bulk_data = {
        "data": [
          {
             "type": "secret",
             "name": "secret1",
             "clearText": "hello",
             "backend": "none"
          },
          {
             "type": "secret",
             "name": "secret2",
             "clearText": "world",
             "backend": "none"
          },
          {
             "type": "secret",
             "name": "secret3",
             "clearText": "!",
             "backend": "none"
          }
        ]
      }


@pytest.fixture
def bulk_secret(scope="function"):
    return secrets_bulk_data


@pytest.fixture(scope="function")
def single_secret():
    return secret_data


@pytest.fixture(scope="function")
def single_b64_secret():
    return secret_b64_data


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


def _post(url, json):
    secret = requests.post(url, json=json, timeout=10.0)

    try:
        print(secret.status_code)
        print(secret.json())
        assert "tempKey" not in secret.json().keys()
        return secret
    except ValueError:
        if secret.status_code == 200:
            return secret

    assert False


def python_post_response(url, json):
    secret = _post(url, json)
    assert secret.status_code == requests.codes.ok
    assert secret.status_code != 400
    dict = {}

    try:
        dict = secret.json()
    except ValueError:
        dict = {}

    return dict


def verify_python_bad_post_response(url, json):
    secret = _post(url, json)
    resp = secret.json()
    assert secret.status_code == 400
    assert resp["type"] == "error"


def md5_hex_digest(data):
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()


def test_secrets_create_api_none_backend(single_b64_secret):
    json_secret = python_post_response(CREATE_URL, single_b64_secret)
    expected_encoded = single_b64_secret["clearText"]

    assert expected_encoded == base64.b64decode(json_secret["cipherText"])
    assert "clearText" not in json_secret.keys()
    assert md5_hex_digest(expected_encoded) == \
        json_secret["signature"]


def test_secrets_create_bulk_api_none_backend(bulk_secret):
    '''
    This test validates that the plain text was base64 encoded
    and then re-encoded. Proving that the end result would need
    to be base64 decoded
    '''
    bulk_url = CREATE_URL + "?action=bulk"
    json_secrets = python_post_response(bulk_url, bulk_secret)

    i = 0
    for secret in json_secrets["data"]:
        expected_encoded = base64.b64encode(
                secrets_bulk_data["data"][i]["clearText"])
        assert expected_encoded == base64.b64decode(secret["cipherText"])
        assert "clearText" not in secret.keys()
        i += 1


def test_secrets_bulk_rewrap_api_none_backend(bulk_secret):
    bulk_url = CREATE_URL + "?action=bulk"
    bulk_rewrap_url = REWRAP_URL + "?action=bulk"

    json_secret = python_post_response(bulk_url, bulk_secret)
    json_secret["rewrapKey"] = insecure_public_key

    rewrap_secret = python_post_response(bulk_rewrap_url, json_secret)

    assert len(rewrap_secret["data"]) == len(bulk_secret["data"])


def test_secrets_rewrap_api_none_backend_invalid_signatures(single_secret):
    json_secret = python_post_response(CREATE_URL, single_secret)

    json_secret["rewrapKey"] = insecure_public_key
    json_secret["signature"] = md5_hex_digest("bad signature")

    verify_python_bad_post_response(REWRAP_URL, json_secret)


def test_secrets_api_vault_backend_avoids_collisions(single_secret):
    single_secret["backend"] = "vault"
    single_secret["keyName"] = "rancher"
    json_secret1 = python_post_response(CREATE_URL, single_secret)
    json_secret2 = python_post_response(CREATE_URL, single_secret)

    assert json_secret1["cipherText"] != json_secret2["cipherText"]
    assert json_secret1["signature"] != json_secret2["signature"]


def test_secrets_local_key_backend_same_text_avoids_collisions(single_secret):
    single_secret["backend"] = "localkey"
    single_secret["keyName"] = "test_key"
    print(single_secret["clearText"])
    json_secret1 = python_post_response(CREATE_URL, single_secret)
    json_secret2 = python_post_response(CREATE_URL, single_secret)

    assert json_secret1["cipherText"] != json_secret2["cipherText"]
    assert json_secret1["signature"] != json_secret2["signature"]


def test_vault_backend_with_storage_dir(single_secret):
    single_secret["backend"] = "vault"

    # Test that one has paths and the other doesn't
    json_secret_alt = python_post_response(
        get_create_url(ALT_URL), single_secret)
    json_secret = python_post_response(CREATE_URL, single_secret)

    client = hvac.Client(url=VAULT_STORAGE_URL, token="testing")
    secret_cipher_text = client.read(json_secret_alt["cipherText"])

    # Asserts the storage path
    assert "v1-secrets" in json_secret_alt["cipherText"]
    assert "v1-secrets" not in json_secret["cipherText"]

    # Asserts it is stored in Vault
    assert len(secret_cipher_text["data"]["cipherText"]) > 0

    # Test the delete
    python_post_response(get_delete_url(ALT_URL), json_secret_alt)

    secret_from_vault = client.read(json_secret_alt["cipherText"])
    assert secret_from_vault is None
