from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

#data = b'This is the first message that I have encrypted using PyCryptodome!!'
data = get_random_bytes(4194304)


def to_hex(byte_string):
    return ":".join("{:02x}".format(c) for c in byte_string)


def main():
    key = get_random_bytes(16)
    nonce = get_random_bytes(16)

    print("=================")
    print("Encrypting with AES")
    print("Key: ", to_hex(key))
    print("Nonce: ", to_hex(nonce))

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print("MAC: ", to_hex(tag))
    #print("Cleartext: ", to_hex(data))
    #print("Ciphertext: ", to_hex(ciphertext))

    file_out = open("encrypted.bin", "wb")
    [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
    file_out.close()

    file_in = open("encrypted.bin", "rb")
    decrypt_nonce, decrypt_tag, decrypt_ciphertext = [
        file_in.read(x) for x in (16, 16, -1)]
    file_in.close()

    print("=================")
    print("Decrypting with AES")
    print("Key: ", to_hex(key))
    print("Nonce: ", to_hex(decrypt_nonce))
    print("MAC: ", to_hex(decrypt_tag))
    print("=================")
    #print("Ciphertext: ", to_hex(decrypt_ciphertext))

    decipher = AES.new(key, AES.MODE_EAX, decrypt_nonce)
    cleartext = decipher.decrypt_and_verify(decrypt_ciphertext, decrypt_tag)

    if cleartext == data:
        print("Decryption successful")
    else:
        print("Decryption failed")

    return


if __name__ == "__main__":
    main()
