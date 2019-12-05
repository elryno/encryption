#!/usr/bin/python3

import argparse

import Cryptodome.Cipher.DES as DES
import Cryptodome.Random as Random

#data = b'This is the first message that I have encrypted using PyCryptodome!!'
data = Random.get_random_bytes(16777216)
key = Random.get_random_bytes(8)
nonce = Random.get_random_bytes(16)


def run_DES(num):
    for i in list(range(num)):
        cipher = DES.new(key, DES.MODE_EAX, nonce)
        ciphertext = cipher.encrypt(data)
    return


def main():
    num = 1

    parser = argparse.ArgumentParser()

    parser.add_argument("--num", "-n", help="set number of reps for encryption")

    args = parser.parse_args()

    if args.num:
        num = int(args.num)

    run_DES(num)


if __name__ == "__main__":
    main()
