#!/usr/bin/python3

import argparse

import Cryptodome.Cipher.DES3 as DES3
import Cryptodome.Random as Random

#data = b'This is the first message that I have encrypted using PyCryptodome!!'
data = Random.get_random_bytes(16777216)
while True:
    try:
        key = DES3.adjust_key_parity(Random.get_random_bytes(24))
        break
    except ValueError:
        pass
nonce = Random.get_random_bytes(16)


def run_3DES(num):
    for i in list(range(num)):
        cipher = DES3.new(key, DES3.MODE_EAX, nonce)
        ciphertext = cipher.encrypt(data)
    return


def main():
    num = 1

    parser = argparse.ArgumentParser()

    parser.add_argument("--num", "-n", help="set number of reps for encryption")

    args = parser.parse_args()

    if args.num:
        num = int(args.num)

    run_3DES(num)


if __name__ == "__main__":
    main()
