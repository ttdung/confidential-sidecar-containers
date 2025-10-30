from flask import Flask, jsonify, request
import requests
import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
app = Flask(__name__)


# In a real application, this data would come from a database
items = {
    1: {"id": 1, "name": "Laptop", "description": "Powerful computing device"},
    2: {"id": 2, "name": "Mouse", "description": "Wireless optical mouse"},
    3: {"id": 3, "name": "Keyboard", "description": "Mechanical gaming keyboard"},
}

private_key_global = None  # global variable

@app.route("/items/<int:item_id>", methods=["GET"])
def get_item(item_id):
    item = items.get(item_id)
    if not item:
        return jsonify({"error": "Item not found"}), 404
    return jsonify(item)

@app.route('/attest/maa', methods=['POST'])
def attest_maa():

    data = request.get_json()
    maa_endpoint = data['maa_endpoint']
    runtime_data = data['runtime_data']

    response = requests.post("http://localhost:8080/attest/maa",
                             json={"maa_endpoint": maa_endpoint, "runtime_data": runtime_data})

    # return the result as a JSON object
    return jsonify({'result': response.text})

@app.route('/attest', methods=['POST'])
def attest():
    # retrieve the two numbers from the request
    data = request.get_json()
    runtime_data = data['runtime_data']

    response = requests.post("http://localhost:8080/attest/raw",
                             json={"runtime_data": runtime_data})

    # return the result as a JSON object
    return jsonify({'result': response.text})


@app.route('/key/release', methods=['POST'])
def key_release():
    global private_key_global

    data = request.get_json()
    maa_endpoint = data['maa_endpoint']
    akv_endpoint = data['akv_endpoint']
    kid = data['kid']

    response = requests.post("http://localhost:8080/key/release",
                             json={"maa_endpoint": maa_endpoint, "akv_endpoint": akv_endpoint, "kid": kid})

    outer_json = json.loads(response.text)
    key_json = json.loads(outer_json['key'])

    def b64url_to_int(b64url_str):  
        padding = '=' * (-len(b64url_str) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(b64url_str + padding), 'big')

    n  = b64url_to_int(key_json['n'])
    e  = b64url_to_int(key_json['e'])
    d  = b64url_to_int(key_json['d'])
    p  = b64url_to_int(key_json['p'])
    q  = b64url_to_int(key_json['q'])
    dp = b64url_to_int(key_json['dp'])
    dq = b64url_to_int(key_json['dq'])
    qi = b64url_to_int(key_json['qi'])
    
    private_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dp,
        dmq1=dq,
        iqmp=qi,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n)
    )

    private_key_global = private_numbers.private_key()

    # ========== 3️⃣ Extract public key ==========
    public_key = private_key_global.public_key()

    # print("🔑 Public Key PEM:\n", pub_pem.decode())
    """Return RSA public key in PEM format (or JWK if you prefer)."""
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({"public_key_pem": pub_pem.decode()})

@app.route("/decrypt_key", methods=["POST"])
def decrypt_key():
    global private_key_global
    if private_key_global is None:
        return jsonify({"error": "No private key available. Call /key/release first."}), 400

    try:
        data = request.get_json()
        if not data or "encrypted_key_b64" not in data:
            return jsonify({"error": "Missing 'encrypted_key_b64'"}), 400

        # Get the encrypted key (base64 string) and decode it
        encrypted_key_b64 = data["encrypted_key_b64"]
        encrypted_key = base64.b64decode(encrypted_key_b64)

        # Decrypt using RSA private key with OAEP + SHA256
        symmetric_key = private_key_global.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Return base64 or hex for readability (raw binary otherwise)
        return jsonify({
            "symmetric_key_b64": base64.b64encode(symmetric_key).decode()
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)