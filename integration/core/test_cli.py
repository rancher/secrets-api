import requests
import base64

URL = 'http://localhost:8181'
CREATE_URL = URL + "/v1-secrets/secrets/create"

secret_data = {
        "clearText": "hello",
        "backend": "none"
        }


def test_secrets_create_api_none_backend():
    secret = requests.post(CREATE_URL, json=secret_data)
    expected_encoded = base64.b64encode(secret_data["clearText"])
    json_secret = secret.json()

    assert secret.status_code == requests.codes.ok
    assert expected_encoded == json_secret["cipherText"]
    assert "" == json_secret["clearText"]
