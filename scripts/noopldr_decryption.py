import sys, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# pip install pycryptodome


def format_byte(sha256_hash_16_bytes):
    byte_array = bytearray()
    for byte in sha256_hash_16_bytes:
        byte_array.extend(byte.to_bytes(1, "big"))

    # Convert the bytearray to a hexadecimal string
    result = "".join(format(byte, "02X") for byte in byte_array)
    return result


def create_sha384(machine_id, registry_key):
    sha384 = hashlib.sha384((machine_id + registry_key).encode("ascii"))
    sha384_hash_full = sha384.digest()
    sha384_hash = sha384_hash_full[:32]
    sha384_hash_16 = sha384_hash_full[32:]
    return sha384_hash, sha384_hash_16


def decrypt(payload, sha384_hash, sha384_hash_16):
    cipher = AES.new(sha384_hash, AES.MODE_CBC, sha384_hash_16)
    decrypted_data = unpad(cipher.decrypt(payload), AES.block_size)
    return decrypted_data


def main():
    try:
        payload = open(sys.argv[1], "rb").read()
        encrypted_filename = sys.argv[1]
        registry_key = sys.argv[2]
        machine_id = sys.argv[3]

    except:
        print(
            "\n-------------------------------------HOW TO"
            " USE-------------------------------------------------------"
        )
        print(
            "Useage: extract-shellcode.py <payload-file> <Registry key>"
            " <Machine_Id>"
        )
        print("Where payload-file is the contents of \{xxxx\} inside")
        print("\tHKCU\\Software\\License\\{xxx}")
        print("\tHKLM\\Software\\License\\{xxx}")
        print("\tHKLM\\COM3\\{xxx}")
        print("Where Registry key (XXX) is the name of the key inside \{XXX\}")
        print(
            "For MachineId, look in"
            " \n\tHKLM\\Software\\Microsoft\\SQMClient\\MachineId"
        )
        print(
            "--------------------------------------------------------------------------------------------------------\n"
        )
        exit()

    # Create sha384 hash based on HKLM\\Software\\Microsoft\\SQMClient\\MachineId keyVALUE and keyNAME under HKCU\\Software\\License\\{xxx}
    sha384_hash, sha384_hash_16 = create_sha384(machine_id, registry_key)

    # first 32 bytes of payload is sha256 hash
    # sha384_hash is the key, and sha384_hash_16 is the IV for AES CBC

    decrypted_filename = (
        encrypted_filename.replace(".encrypted", "") + ".decrypted"
    )
    try:
        decrypted_payload = decrypt(payload[32:], sha384_hash, sha384_hash_16)
        open(decrypted_filename, "wb").write(decrypted_payload[10:])
        open("prologue.bin", "wb").write(decrypted_payload[:10])
        print(f"Successfully wrote to {decrypted_filename}!")
    except:
        try:
            sha384_hash, sha384_hash_16 = create_sha384(
                machine_id, encrypted_filename
            )
            decrypted_payload = decrypt(
                payload[32:], sha384_hash, sha384_hash_16
            )
            open(decrypted_filename, "wb").write(decrypted_payload[10:])
            open("prologue.bin", "wb").write(decrypted_payload[:10])
            print(f"Successfully wrote to {decrypted_filename}!")
        except:
            print("Failed to decrypt")
            print("")


if __name__ == "__main__":
    main()
