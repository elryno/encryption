#!/usr/bin/python3

import argparse

import Cryptodome.Cipher.AES as AES
import Cryptodome.Random as Random

data = Random.get_random_bytes(67108864)
key = Random.get_random_bytes(32)
nonce = Random.get_random_bytes(16)


def run_AES256(num):
    for i in list(range(num)):
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
    return


def main():
    num = 1

    parser = argparse.ArgumentParser()

    parser.add_argument("--num", "-n", help="set number of reps for encryption")

    args = parser.parse_args()

    if args.num:
        num = int(args.num)

    run_AES256(num)
    return


if __name__ == "__main__":
    main()
