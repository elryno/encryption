#!/usr/bin/python3

import argparse

import Cryptodome.Random as Random

import Crypto.Cipher.XOR as XOR

#data = b'This is the first message that I have encrypted using PyCryptodome!!'
data = Random.get_random_bytes(16777216)
key = Random.get_random_bytes(16)


def run_XOR(num):
    for i in list(range(num)):
        cipher = XOR.new(key)
        ciphertext = cipher.encrypt(data)
    return


def main():
    num = 1

    parser = argparse.ArgumentParser()

    parser.add_argument("--num", "-n", help="set number of reps for encryption")

    args = parser.parse_args()

    if args.num:
        num = int(args.num)

    run_XOR(num)
    return


if __name__ == "__main__":
    main()
