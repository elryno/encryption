import Cryptodome.Cipher.AES as AES
import Cryptodome.Cipher.DES as DES
import Cryptodome.Cipher.DES3 as DES3
import Cryptodome.Cipher.CAST as CAST
import Cryptodome.Util.strxor as XOR
import Cryptodome.Random as Random
import itertools

#data = b'This is the first message that I have encrypted using PyCryptodome!!'
data = Random.get_random_bytes(4194304)


def to_hex(byte_string):
    return ":".join("{:02x}".format(c) for c in byte_string)


def chunker(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return ((bytes(bytearray(x))) for x in itertools.zip_longest(fillvalue=fillvalue, *args))


def run_AES256():
    key = Random.get_random_bytes(32)
    nonce = Random.get_random_bytes(16)

    print("=================")
    print("Encrypting with AES-256")
    print("Key: ", to_hex(key))
    print("Nonce: ", to_hex(nonce))

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print("MAC: ", to_hex(tag))
    #print("Cleartext: ", to_hex(data))
    #print("Ciphertext: ", to_hex(ciphertext))

    file_out = open("aes256.bin", "wb")
    [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
    file_out.close()

    file_in = open("aes256.bin", "rb")
    decrypt_nonce, decrypt_tag, decrypt_ciphertext = [
        file_in.read(x) for x in (16, 16, -1)]
    file_in.close()

    print("=================")
    print("Decrypting with AES-256")
    print("Key: ", to_hex(key))
    print("Nonce: ", to_hex(decrypt_nonce))
    print("MAC: ", to_hex(decrypt_tag))
    #print("Ciphertext: ", to_hex(decrypt_ciphertext))

    decipher = AES.new(key, AES.MODE_EAX, decrypt_nonce)
    cleartext = decipher.decrypt_and_verify(decrypt_ciphertext, decrypt_tag)

    #print("Cleartext: ", to_hex(cleartext))
    print("=================")
    if cleartext == data:
        print("Decryption successful\n")
    else:
        print("Decryption failed\n")

    return


def run_DES():
    key = Random.get_random_bytes(8)
    nonce = Random.get_random_bytes(16)

    print("=================")
    print("Encrypting with DES")
    print("Key: ", to_hex(key))
    print("Nonce: ", to_hex(nonce))

    cipher = DES.new(key, DES.MODE_EAX, nonce)

    ciphertext = cipher.encrypt(data)

    #print("Cleartext: ", to_hex(data))
    #print("Ciphertext: ", to_hex(ciphertext))

    file_out = open("des.bin", "wb")
    [file_out.write(x) for x in (cipher.nonce, ciphertext)]
    file_out.close()

    file_in = open("des.bin", "rb")
    decrypt_nonce, decrypt_ciphertext = [
        file_in.read(x) for x in (16, -1)]
    file_in.close()

    print("=================")
    print("Decrypting with DES")
    print("Key: ", to_hex(key))
    print("Nonce: ", to_hex(decrypt_nonce))
    #print("Ciphertext: ", to_hex(decrypt_ciphertext))

    decipher = DES.new(key, DES.MODE_EAX, decrypt_nonce)
    cleartext = decipher.decrypt(decrypt_ciphertext)

    #print("Cleartext: ", to_hex(cleartext))
    print("=================")

    if cleartext == data:
        print("Decryption successful\n")
    else:
        print("Decryption failed\n")

    return


def run_3DES():
    while True:
        try:
            key = DES3.adjust_key_parity(Random.get_random_bytes(24))
            break
        except ValueError:
            pass

    nonce = Random.get_random_bytes(16)

    print("=================")
    print("Encrypting with 3DES")
    print("Key: ", to_hex(key))
    print("Nonce: ", to_hex(nonce))

    cipher = DES3.new(key, DES3.MODE_EAX, nonce)

    ciphertext = cipher.encrypt(data)

    #print("Cleartext: ", to_hex(data))
    #print("Ciphertext: ", to_hex(ciphertext))

    file_out = open("des3.bin", "wb")
    [file_out.write(x) for x in (cipher.nonce, ciphertext)]
    file_out.close()

    file_in = open("des3.bin", "rb")
    decrypt_nonce, decrypt_ciphertext = [
        file_in.read(x) for x in (16, -1)]
    file_in.close()

    print("=================")
    print("Decrypting with 3DES")
    print("Key: ", to_hex(key))
    print("Nonce: ", to_hex(decrypt_nonce))
    #print("Ciphertext: ", to_hex(decrypt_ciphertext))

    decipher = DES3.new(key, DES3.MODE_EAX, decrypt_nonce)
    cleartext = decipher.decrypt(decrypt_ciphertext)

    #print("Cleartext: ", to_hex(cleartext))
    print("=================")

    if cleartext == data:
        print("Decryption successful\n")
    else:
        print("Decryption failed\n")

    return


def run_CAST128():
    key = Random.get_random_bytes(16)
    nonce = Random.get_random_bytes(16)

    print("=================")
    print("Encrypting with CAST-128")
    print("Key: ", to_hex(key))
    print("Nonce: ", to_hex(nonce))

    cipher = CAST.new(key, CAST.MODE_EAX, nonce)

    ciphertext = cipher.encrypt(data)

    #print("Cleartext: ", to_hex(data))
    #print("Ciphertext: ", to_hex(ciphertext))

    file_out = open("cast.bin", "wb")
    [file_out.write(x) for x in (cipher.nonce, ciphertext)]
    file_out.close()

    file_in = open("cast.bin", "rb")
    decrypt_nonce, decrypt_ciphertext = [
        file_in.read(x) for x in (16, -1)]
    file_in.close()

    print("=================")
    print("Decrypting with CAST-128")
    print("Key: ", to_hex(key))
    print("Nonce: ", to_hex(decrypt_nonce))
    #print("Ciphertext: ", to_hex(decrypt_ciphertext))

    decipher = CAST.new(key, CAST.MODE_EAX, decrypt_nonce)
    cleartext = decipher.decrypt(decrypt_ciphertext)

    #print("Cleartext: ", to_hex(cleartext))
    print("=================")

    if cleartext == data:
        print("Decryption successful\n")
    else:
        print("Decryption failed\n")

    return


def run_XOR():
    key = Random.get_random_bytes(16)
    textlen = len(data)

    print("=================")
    print("Encrypting with XOR")
    print("Key: ", to_hex(key))

    ciphertext = b"".join(XOR.strxor(bytes(bytearray(c)), bytes(bytearray(k)))
                          for (c, k) in zip(chunker(data, len(key), fillvalue=ord(b'0')), itertools.cycle(chunker(key, len(key)))))

    #print("Text length: ", textlen)
    #print("Cleartext: ", to_hex(data))
    #print("Ciphertext: ", to_hex(ciphertext))

    file_out = open("xor.bin", "wb")
    [file_out.write(x) for x in (textlen.to_bytes(16, 'big'), ciphertext)]
    file_out.close()

    file_in = open("xor.bin", "rb")
    decrypt_len = int.from_bytes(file_in.read(16), 'big')
    decrypt_ciphertext = file_in.read()
    file_in.close()

    print("=================")
    print("Decrypting with XOR")
    print("Key: ", to_hex(key))
    #print("Ciphertext: ", to_hex(decrypt_ciphertext))

    cleartext = b"".join(XOR.strxor(bytes(bytearray(c)), bytes(bytearray(k)))
                         for (c, k) in zip(chunker(decrypt_ciphertext, len(key), fillvalue=ord(b'0')), itertools.cycle(chunker(key, len(key)))))[:decrypt_len]

    #print("Text length: ", decrypt_len)
    #print("Cleartext: ", to_hex(cleartext[:decrypt_len]))
    print("=================")

    if cleartext == data:
        print("Decryption successful\n")
    else:
        print("Decryption failed\n")

    return


def main():
    run_AES256()
    run_DES()
    run_3DES()
    run_CAST128()
    run_XOR()


if __name__ == "__main__":
    main()
