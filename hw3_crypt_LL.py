#Luke Lyons - 100079115
#Cryptography Homework 3

import os
import time
import rsa

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

#File names
CTEXT_FILE = "text_files/ctext.txt"
AES_KEY_IV_FILE = "text_files/key_iv.txt"
RSA_PUB_FILE = "text_files/rsa_public_key.txt"
BOB_PRIV_FILE = "text_files/bob_private_key.txt"

#Padding and unpadding methods for AES
def pad_data(data: bytes, block_size: int) -> bytes:
    return pad(data, block_size)

def unpad_data(padded_data: bytes, block_size: int) -> bytes:
    return unpad(padded_data, block_size)

#Checks for existing AES key and initial vector, if empty creates new key and iv and saves to file
def create_AES_key_dict(filename: str) -> dict:
    aes_key_dict = {}
    try:
        with open(filename, 'rb') as aes_key_file:
            lines = aes_key_file.readlines()
            if lines:
                key = lines[0].strip()
                iv = lines[1].strip()

                aes_key_dict['key'] = key
                aes_key_dict['iv'] = iv
            else:
                print("AES key file is empty...")
                key_length = int(input("Enter Key Length(bits):"))
                print("Generating new key and initial vector...")

                key = get_random_bytes(key_length // 8)
                initial_vector = get_random_bytes(AES.block_size)
                
                aes_key_dict['key'] = key
                aes_key_dict['iv'] = initial_vector

                with open(filename, 'wb') as aes_key_file:
                    aes_key_file.write(key + b'\n')
                    aes_key_file.write(initial_vector)
    except:
        print("Filename ", "\"", filename, "\" was not found...")
    return aes_key_dict
    
#Checks for existing RSA keypair, if empty creates new keypair and saves to files
def create_RSA_keypair(public_key_file: str, private_key_file: str) -> tuple:
    rsa_keypair = ()
    try:
        with open(public_key_file, 'rb') as public_f, open(private_key_file, 'rb') as private_f:
            public_data = public_f.read()
            private_data = private_f.read()

            if public_data and private_data:
                public_key = rsa.PublicKey.load_pkcs1(public_data)
                private_key = rsa.PrivateKey.load_pkcs1(private_data)
                rsa_keypair =  (public_key, private_key)
            else:
                print("RSA public or private key files are empty...")

                key_length = int(input("Enter Key Length(bits): "))
                print("Generating new keypair...")
                public_key, private_key = rsa.newkeys(key_length)
                rsa_keypair = (public_key, private_key)

                with open(public_key_file, 'wb') as public_f, open(private_key_file, 'wb') as private_f:
                    public_f.write(public_key.save_pkcs1())
                    private_f.write(private_key.save_pkcs1())
    except FileNotFoundError:
        print("Filename ", "\"", public_key_file, "\" or \"",  private_key_file, "\" was not found...")

    return rsa_keypair

#AES encrypt and decrypt method abstracted with encoding
def AES_ENCRYPT(plaintext: str, key: bytes, initial_vector: bytes) -> bytes:
    AES_CIPHER = AES.new(key, AES.MODE_CBC, initial_vector)

    encoded_plaintext = plaintext.encode("latin-1")
    padded_plaintext = pad_data(encoded_plaintext, AES.block_size)
    ciphertext = AES_CIPHER.encrypt(padded_plaintext)
    return ciphertext.hex()

def AES_DECRYPT(ciphertext: str, key: bytes, initial_vector: bytes) -> str:
    AES_CIPHER = AES.new(key, AES.MODE_CBC, initial_vector)
    ciphertext = bytes.fromhex(ciphertext)

    decoded_ciphertext = AES_CIPHER.decrypt(ciphertext)
    unpadded_ciphertext = unpad_data(decoded_ciphertext, AES.block_size)
    plaintext = unpadded_ciphertext.decode("latin-1")
    return plaintext

#RSA encrypt and decrypt method abstracted with encoding
def RSA_ENCRYPT(plaintext: str, public_key: int) -> bytes:
    encoded_plaintext = plaintext.encode('latin-1')
    return rsa.encrypt(encoded_plaintext, public_key).hex()

def RSA_DECRYPT(ciphertext: str, private_key: int) -> str:
    ciphertext = bytes.fromhex(ciphertext)
    encoded_ciphertext = rsa.decrypt(ciphertext, private_key)
    return encoded_ciphertext.decode('latin-1')

#Basic AES encrypt and decrypt mode
def AES_Mode(key: bytes, initial_vector: bytes):
    print("\nAES Mode Selected")

    choice = int(input("Choose Method: \nEncrypt(0) \nDecrypt(1) \nChoice:"))
    match choice:
        case 0:
            plaintext = input("Enter the plaintext:")
            ciphertext = AES_ENCRYPT(plaintext, key, initial_vector) 
            print("Ciphertext: ", ciphertext, "\n")
        case 1:
            ciphertext = input("Enter the ciphertext:")
            plaintext = AES_DECRYPT(ciphertext, key, initial_vector)
            print("Plaintext: ", plaintext, "\n")

#Basic RSA encrypt and decrypt mode
def RSA_Mode(public_key: bytes, private_key: bytes):
    print("\nRSA Mode Selected")

    choice = int(input("Choose Method: \nEncrypt(0) \nDecrypt(1) \nChoice:"))
    match choice:
        case 0:
            plaintext = input("Enter the plaintext:")
            ciphertext = RSA_ENCRYPT(plaintext, public_key) 
            print("Ciphertext: ", ciphertext, "\n")
        case 1:
            ciphertext = input("Enter the ciphertext:")
            plaintext = RSA_DECRYPT(ciphertext, private_key)
            print("Plaintext: ", plaintext, "\n")

#Bob and Alice message system with AES 128-bit key using CBC
def Bob_Alice_AES(key: bytes, initial_vector: bytes):
    print("\nAlice and Bob AES 128 bit key CBC")
    
    person = input("Are you Alice or Bob? (A/B): ").strip().upper()
    if person not in ['A', 'B']:
        print("Invalid input. Please enter 'A' for Alice or 'B' for Bob.")
        return
    
    #Alice encryption section & write to ctext file
    if person == 'A':
        print("Alice encrypts and sends to Bob")
        message = input("Enter the plaintext message(18 bytes): ")
        if len(message) != 18:
            print("Warning: message length is", len(message), " bytes")
        ciphertext = AES_ENCRYPT(message, key, initial_vector)

        with open(CTEXT_FILE, "w", encoding='latin-1') as f:
            f.write(ciphertext)
        print("Ciphertext(hex) \"", ciphertext, " written to \"", CTEXT_FILE, "\"")
    #Bob decryption section from ctext file
    elif person == 'B':
        print("Bob reads and decrypts the message from Alice")
        with open(CTEXT_FILE, "r", encoding='latin-1') as f:
            ciphertext = f.read()
        try:
            plaintext = AES_DECRYPT(ciphertext, key, initial_vector)
            print("Plaintext: ", plaintext, "\n")
        except Exception as e:
            print("Decryption failed:", e)
 
#Bob and Alice message system with RSA 2048-bit key
def Bob_Alice_RSA(public_key: bytes, private_key: bytes):
    print("\nAlice and Bob RSA 2048 bit")

    #Check if user is Alice or Bob
    person = input("Are you Alice or Bob? (A/B): ").strip().upper()
    if person not in ['A', 'B']:
        print("Invalid input. Please enter 'A' for Alice or 'B' for Bob.")
        return
    
    #Alice encryption section & write to ctext file
    if person == 'A':
        print("Alice encrypts and sends to Bob")
        message = input("Enter the plaintext message(18 bytes): ")
        if len(message) != 18:
            print("Warning: message length is", len(message), " bytes")

        ciphertext = RSA_ENCRYPT(message, public_key)
        with open(CTEXT_FILE, "w", encoding="latin-1") as f:
            f.write(ciphertext)
        print("Ciphertext(hex) \"", ciphertext, " written to \"", CTEXT_FILE, "\"")
    #Bob decryption section from ctext file
    elif person == 'B':
        print("Bob reads and decrypts the message from Alice")
        with open(CTEXT_FILE, "r", encoding='latin-1') as f:
            ciphertext = f.read()
        try:
            plaintext = RSA_DECRYPT(ciphertext, private_key)
            print("Plaintext: ", plaintext, "\n")
        except Exception as e:
            print("RSA decryption failed:", e)

#AES perfmance test with 128-bit, 192-bit, and 256-bit keys
def AES_performance():
    print("\nAES Performance Test Selected")
    key_sizes = [128, 192, 256]

    #Grab 7-byte message from command line
    message = input("Put test message(7-bytes):")
    for key_size in key_sizes:
        print("\nUsing AES with key size:", key_size)
        print("Generating new key and initial vector...")
        key = get_random_bytes(key_size // 8)
        initial_vector = get_random_bytes(AES.block_size)
        encryption_times = []
        decryption_times = []

        #Encryption time test
        print("Running encryption test...")
        for i in range(100):
            start_time = time.perf_counter()
            ciphertext = AES_ENCRYPT(message, key, initial_vector)
            end_time = time.perf_counter()
            encryption_times.append((end_time - start_time) * 1_000_000)

        avg_encryption_time = sum(encryption_times) / 100
        print("\tAverage encryption time for", key_size, "bit key over 100 runs: ", avg_encryption_time, "ms")

        #Decryption time test
        print("Running decryption test...")
        for i in range(100):
            start_time = time.perf_counter()
            plaintext = AES_DECRYPT(ciphertext, key, initial_vector)
            end_time = time.perf_counter()
            decryption_times.append((end_time - start_time) * 1_000_000)

        avg_decryption_time = sum(decryption_times) / 100
        print("\tAverage decryption time for", key_size, "bit key over 100 runs: ", avg_decryption_time, "ms")
    

#RSA perfmance test with 1024-bit, 2048-bit, and 4096-bit keys
def RSA_performance():
    print("\nRSA Performance Test Selected")
    key_sizes = [1024, 2048, 4096]
    
    #Grab 7-byte message from command line
    message = input("Put test message(7-bytes):")
    for key_size in key_sizes:
        print("\nUsing RSA with key size:", key_size)
        print("Generating new keypair...")
        keypair = rsa.newkeys(key_size)
        public_key = keypair[0]
        private_key = keypair[1]
        encryption_times = []
        decryption_times = []

        #Encryption time test
        print("Running encryption test...")
        for i in range(100):
            start_time = time.perf_counter()
            ciphertext = RSA_ENCRYPT(message, public_key)
            end_time = time.perf_counter()
            encryption_times.append((end_time - start_time) * 1_000_000) 

        avg_encryption_time = sum(encryption_times) / 100
        print("\tAverage encryption time for", key_size, "bit key over 100 runs: ", avg_encryption_time, "ms")

        #Decryption time test
        print("Running decryption test...")
        for i in range(100):
            start_time = time.perf_counter()
            plaintext = RSA_DECRYPT(ciphertext, private_key)
            end_time = time.perf_counter()
            decryption_times.append((end_time - start_time) * 1_000_000)

        avg_decryption_time = sum(decryption_times) / 100
        print("\tAverage decryption time for", key_size, "bit key over 100 runs: ", avg_decryption_time, "ms")

def main():
    print("||AES/RSA Cryptography Assignment||")
    
    #Generating key and initial_vector in bytes
    aes_key_dict = create_AES_key_dict(AES_KEY_IV_FILE)
    #Generating key pair for RSA
    rsa_keypair = create_RSA_keypair(RSA_PUB_FILE, BOB_PRIV_FILE)

    #Main mode selection loop
    while(1):
        mode = int(input("\nPlease choose a mode " +
                            "\nRun AES(0) \nRun RSA(1) " +
                            "\nRun Bob and Alice AES(2) " +
                            "\nRun Bob and Alice RSA(3) "
                            "\nRun AES Performance(4) \nRun RSA Performance(5)" +
                            "\nExit(6)" +
                            "\nChoice:")) 
        match mode:
            case 0:
                AES_Mode(aes_key_dict.get("key"), aes_key_dict.get("iv"))
            case 1:
                RSA_Mode(rsa_keypair[0], rsa_keypair[1])
                pass
            case 2:
                Bob_Alice_AES(aes_key_dict.get("key"), aes_key_dict.get("iv"))
            case 3:
                Bob_Alice_RSA(rsa_keypair[0], rsa_keypair[1])
            case 4:
                AES_performance()
                pass
            case 5:
                RSA_performance()
                pass
            case 6:
                exit()

if __name__ == "__main__":
    main()