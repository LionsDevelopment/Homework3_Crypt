import os
import sys
import subprocess

from rsa import encrypt, decrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes



def pad_data(data: bytes, block_size: int) -> bytes:
    return pad(data, block_size)

def unpad_data(padded_data: bytes, block_size: int) -> bytes:
    return unpad(padded_data, block_size)

def read_file(file_path: str) -> str:
    with open(file_path, 'r', encoding='latin-1') as file:
        return file.read()

def create_key_dictionary(filename: str) -> dict:
    key_dict = {}
    try:
        with open(filename, 'r') as key_file:
            for line in key_file:
                line.strip()
                if line:
                    elements = line.split(',', 1)
                    if len(elements) == 2:
                        key_type = elements[0].strip
                        key_value = elements[1].strip
                        key_dict[key_type] = key_value
                else:
                    print("No elements could be found...")
    except:
        print("Filename \"{filename}\" was not found...")
    return key_dict
    

def AES_ENCRYPT(plaintext: str, key: bytes, initial_vector: bytes) -> bytes:
    encoded_plaintext = plaintext.encode("latin-1")
    padded_plaintext = pad_data(encoded_plaintext, AES.block_size)
    
    AES_CIPHER = AES.new(key, AES.MODE_CBC, initial_vector)

    ciphertext = AES_CIPHER.encrypt(padded_plaintext)
    return ciphertext

def AES_DECRYPT(ciphertext: bytes, key: bytes, initial_vector: bytes) -> str:
    # encoded_ciphertext = ciphertext.encode('utf-8')

    AES_CIPHER = AES.new(key, AES.MODE_CBC, initial_vector)
    decoded_ciphertext = AES_CIPHER.decrypt(ciphertext)
    unpadded_ciphertext = unpad_data(decoded_ciphertext, AES.block_size)
    plaintext = unpadded_ciphertext.decode("latin-1")
    return plaintext

def RSA_ENCRYPT(plaintext: str, public_key: int) -> str:
    pass

def RSA_DECRYPT(ciphertext: str, public_key: int) -> str:
    pass


def main():
    print("Which Method?")
    key_length = int(input("Enter Key Length: "))
    key = get_random_bytes(key_length // 8)
    initial_vector = get_random_bytes(AES.block_size)


    plaintext1 = input("Enter the plaintext:")
    ciphertext1 = AES_ENCRYPT(plaintext1, key, initial_vector) 

    print(ciphertext1)
    print(AES_DECRYPT(ciphertext1, key, initial_vector))

    #subprocess.run(["./my_script.sh"]) 


if __name__ == "__main__":
    main()



