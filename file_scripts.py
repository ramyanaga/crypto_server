import json

# json_data = {}
# with open("public_key_bytes", "rb") as f:
#     public_key_bytes = f.read()

# json_data["public_key"] = public_key_bytes.decode('cp437')
# json_data["vector"] = [1.0, 2.0, 3.0, 4.0, 5.0]

# with open("encrypt_request_data", "w") as f:
#     f.write(json.dumps(json_data))

# json_data = {}
# with open("encrypt_result_temp", "r") as f:
#     file_data = json.loads(f.read())
#     json_data["encrypted_vals"] = file_data["encrypted_vals"]

# with open("add_request_data", "w") as f:
#     f.write(json.dumps(json_data))

json_data = {}
with open("keys_temp", "r") as f:
    file_data = json.loads(f.read())
    json_data["secret_key"] = file_data["secret_key_bytes"]

with open("add_result_json", "r") as f:
    file_data = json.loads(f.read())
    json_data["encrypted_val"] = file_data["encrypted_sum"]

with open("decrypt_request_data", "w") as f:
    f.write(json.dumps(json_data))

