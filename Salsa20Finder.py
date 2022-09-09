"""
@author: Luis Loaysa 2022

Sodinokibi decryptor. Finds Salsa20 keys in memory and decrypts
files encrypted by Sodinokibi
"""

import re
import os
from Crypto.Cipher import Salsa20


def reading_file(name_file):
    """Reading dump file to extract Salsa20 keys"""
    chunk_sz = 131072
    count = 0
    read_ahead = []
    storing_keys = []
    try:
        print('[+] Finding Salsa20 keys loaded in memory...', '\n')
        with open(name_file, 'rb') as f:
            while True:
                count += 1
                dump = f.read(chunk_sz)
                chunk = dump.hex()
                expand = re.findall(r'65787061.{128}', chunk)
                if expand:
                    storing_keys.append(expand)

                if count % 2 != 0:
                    read_ahead.insert(0, dump[-500:])
                if count % 2 == 0:
                    read_ahead.insert(0, dump[:500])

                gap_bytes = [b''.join(read_ahead[0:2])]  # Join hex bytes to avoid breaks from cutting bytes
                for gap in gap_bytes:
                    gap_hex = gap.hex()
                    expand = re.findall(r'65787061.{128}', gap_hex)
                    if expand:
                        storing_keys.append(expand)

                if len(read_ahead) == 20:  # Prevents list getting too big
                    read_ahead = []
                if not dump:
                    break
    except IOError:
        print('[-] Error opening the file')
        exit()

    return storing_keys


def extracting_key(lists):
    """Matching and verifying keys found in memory"""
    checked = []
    expand = [item for sublist in lists for item in sublist]  # Unpacking lists
    for key in expand:
        if key[40:48] == '6e642033' and key[120:128] == '7465206b':
            #  If second and fourth words exist in their location continue
            checked.append(key)

    return checked


def main():
    number_keys_found = 0
    name_file = input("[+] Enter the name of the memory dump and its extension: ")
    key = reading_file(name_file)
    filtered_keys = extracting_key(key)
    storing_keys = {}

    for key in filtered_keys:
        number_keys_found += 1
        print('[*] 32 byte Salsa20 Key -', key[8:40] + key[88:120])
        print('[*] Nonce -', key[48:64])
        storing_keys.update({key[8:40] + key[88:120]: key[48:64]})

    print('[+] Total number of keys found:', number_keys_found)
    print("[+] That's all we could find!", '\n')

    with open("KeysFound.txt", "w") as file_keys:
        for key, value in storing_keys.items():
            file_keys.write("Key:" + key + " ")
            file_keys.write("Nonce:" + value)
            file_keys.write('\n')


if __name__ == '__main__':
    main()
