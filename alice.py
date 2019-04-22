# Author: John Young
# Date:   4/18/20
# Course: CS 4480, University of Utah, School of Computing
# Copyright: CS 4480 and John Young - This work may not be copied for use in Academic Coursework.
#
# I, John Young, certify that I wrote this code from scratch and did not copy it in part or whole from
# another source.  Any references used in the completion of the assignment are cited in my written work.
#
# File Contents
#
#    This file is mimics a client named Alice accessing a server named Bob.
#    Alice follows the following steps in collaboration with Bob to simulate
#    authentication, Encryption and Decryption methods.
#    1) Alice will establish a connection to Bob and send the plain text message: "Hello"
#    2) Bob will respond with his encrypted DIGEST (see above).
#       This digest will be encrypted with the certificate agencies' private key.
#    3) Alice decodes the DIGEST and confirms that the name is really "bob" and then stores Bob's public key.
#    4) Alice then will create a two part message to send back to Bob.

import os
import argparse
import socket
import re
import sys
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as _padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Verbose global flag
verbose = False
certificate_public: bytes = []
bobs_public_key_data: bytes = []
symmetric_key: bytes = []


def main():
    """
    Main program
    """
    global verbose
    global certificate_public
    global bobs_public_key_data
    global symmetric_key

    # Instantiate the argument parser
    parser = argparse.ArgumentParser(description='Listens on the given port for communications from alice')
    parser.add_argument('host', type=str,  metavar='host', default='localhost',
                        help='the host address at which alice contact bob on')
    parser.add_argument('-port', '-p', type=int, metavar='port', default=65432,
                        help='the port at which alice will contact bob on')
    parser.add_argument('-file', type=str, metavar='file',
                        help='certificate agency private key')
    parser.add_argument('-message', type=str, metavar='message',
                        help='the message alice wants to send to bob')
    parser.add_argument('certificate_public', type=str, metavar='certificate_public',
                        help='certificate agency private key')
    parser.add_argument('-verbose', '-v', action='store_true',
                        help='prints more messages to console for debugging.')
    args = parser.parse_args()

    verbose = args.verbose
    printv(args)

    print("--------------------------------------")

    # Read files
    with open(args.certificate_public, "rb") as key_file:
        certificate_public = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    # Generate a 256-bit symmetric key
    symmetric_key = os.urandom(32)

    # Open the socket.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 1. Alice will establish a connection to Bob and send the plain text message: "Hello"
    print("1) Attempting to open connection to Bob at " + str(args.host) + " on port " + str(args.port))
    # Connect to server a host and port.
    s.connect((args.host, args.port))

    try:
        # 2. Bob will respond with his encrypted DIGEST (see above). This digest will be encrypted with the
        # certificate agencies' private key.
        print("2) Connected. Sending \"Hello\"")
        bobs_encrypted_digest: dict = json.loads(send_to_bob(s, 'Hello'))

        # 3. Alice decodes the DIGEST and confirms that the name is really "bob" and then stores Bob's public key.
        print("3) Received:")
        print("\t" + json.dumps(bobs_encrypted_digest, indent=4, sort_keys=True).replace('\n', '\n\t'))
        bob: bool = digest_confirmation(bobs_encrypted_digest)

        if not bob:
            raise ValueError("Message is not from Bob!")

        # 4. Alice then will create a two part message to send back to Bob.
        if args.message:
            message_bytes = str_to_bytes(args.message)
            encrypted_message: str = json.dumps(encrypt_message(message_bytes), indent=4, sort_keys=True)
            print("4) Sending the encoded message:")
            print("\t" + str(encrypted_message).replace('\n', '\n\t'))
            send_to_bob(s, encrypted_message, False)

        # 4. Alice then will create a two part message to send back to Bob.
        if args.file:
            file_name: bytes = str_to_bytes(args.file)
            file_data_bytes: bytes = None
            with open(file_name, 'rb') as file:
                file_data_bytes: bytes = file.read()
            if not file_data_bytes:
                raise ValueError("File could not be read!")
            encrypted_file: str = json.dumps(encrypt_file(file_name, file_data_bytes), indent=4, sort_keys=True)
            print("4) Sending the encoded file:")
            print("\t" + str(encrypted_file).replace('\n', '\n\t'))
            send_to_bob(s, encrypted_file, False)

    except Exception as e:
        print(e)
    finally:
        s.close()
        print("5) Communication Over")

    print("--------------------------------------")


def send_to_bob(s: socket, message: str, wait_for_reply: bool=True):
    """
    Sends the encoded message to the server
    :param s: the socket connecting to Bob
    :param message: message as a string
    :param wait_for_reply: boolean indicating if alice should expect a reply from Bob.
    :return: Returns the message in bytes from the server if successful
    """
    s.sendall(pack_message(message))
    if wait_for_reply:
        return receive_from_bob(s)
    else:
        return ''


def receive_from_bob(connection):
    """
    Handles the connection accepted by the client
    :param connection: Socket connection
    :return: Message in bytes received from the connection
    """
    bytes_read: int = 0
    message: bytes = bytes()
    content_length: int = sys.maxsize
    header_size: int = 0
    # Wait for bytes
    while True:
        printv("Waiting for message from Bob...")
        data = connection.recv(1024)
        if content_length == sys.maxsize:
            content_length_with_body = re.split("\r\n", bytes_to_str(data))
            header = content_length_with_body[0]

            if header:
                header_size = len(header) + 2
                content_length = int(header)

        bytes_read += len(data)
        printv("Received:" + str(data))
        message += data

        if bytes_read - header_size == content_length:
            break

    printv("Message from Bob: " + str(message))
    return message[header_size:]


def digest_confirmation(bobs_digest: dict):
    """
    Parses Bob's digest and confirms message is from Bob and stores Bob's private key.
    :return: True if bob is confirmed otherwise false.
    """
    global bobs_public_key_data

    if 'name' not in bobs_digest or \
            'pub_key' not in bobs_digest or \
            'signature' not in bobs_digest or \
            alpha_str_to_bytes(bobs_digest['name']) != b'bob':
        return False

    message: bytes = alpha_str_to_bytes(bobs_digest['pub_key'])
    signature: bytes = alpha_str_to_bytes(bobs_digest['signature'])

    try:
        certificate_public.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        print(e)
        return False

    bobs_public_key_data = alpha_str_to_bytes(bobs_digest['pub_key'])
    return True


def encrypt_message(message: bytes):
    """
    For a simple message, the following JSON generated:
    {
        message: "ENCRYPTED MESSAGE USING ALICE'S SYMMETRIC KEY",
        verify:  "HASH OF THE MESSAGE ENCRYPTED WITH ALICE'S SYMMETRIC KEY",
        key:     "SYMMETRIC KEY ENCRYPTED WITH BOB'S PUBLIC KEY"
    }
    :param message: Message in bytes to encrypt and hash using the symmetric key
    :return: A dictionary ready that is ready for JSON formatting as described in description above
    """
    # Hashing the message
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    hashed_message: bytes = digest.finalize()

    # Generate a random 128-bit IV
    iv: bytes = os.urandom(16)

    # verify - Encrypt hashed message
    encrypted_hash_message: bytes = symmetric_encrypt(symmetric_key, iv, hashed_message)

    # message - Encrypt message
    encrypted_message: bytes = symmetric_encrypt(symmetric_key, iv, message)

    # Convert bob's public key from bytes to a pem
    bobs_public_key = load_pem_public_key(bobs_public_key_data, backend=default_backend())

    # key - Encrypt the symmetric key using bobs public key
    encrypted_sym_key_iv = bobs_public_key.encrypt(
        pack_key(symmetric_key, iv),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "message": bytes_to_alpha_str(encrypted_message),
        "verify": bytes_to_alpha_str(encrypted_hash_message),
        "key": bytes_to_alpha_str(encrypted_sym_key_iv)
    }


def encrypt_file(file_name: bytes, file_contents: bytes):
    """
    For a file, the following JSON generated:
    {
        file_name: "ENCRYPTED FILE NAME USING ALICE'S SYMMETRIC KEY",
        contents:  "ENCRYPTED FILE CONTENTS USING SYMMETRIC KEY",
        verify:    "SHA 256 HASH OF THE FILE ENCRYPTED WITH THE SYMMETRIC KEY",
        key:       "SYMMETRIC KEY, ITSELF ENCRYPTED WITH BOB's PUBLIC KEY"
     }
    :param file_name: File name in bytes to encrypt and hash using the symmetric key
    :param file_contents: File contents in bytes to encrypt and hash using the symmetric key
    :return: A dictionary ready that is ready for JSON formatting as described in description above
    """
    # Hashing the file_contents
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(file_contents)
    hashed_file: bytes = digest.finalize()

    # Generate a random 128-bit IV
    iv: bytes = os.urandom(16)

    # verify - Encrypt hashed file contents
    encrypted_hash_file: bytes = symmetric_encrypt(symmetric_key, iv, hashed_file)

    # contents - Encrypt file contents
    encrypted_file: bytes = symmetric_encrypt(symmetric_key, iv, file_contents)

    # file_name - Encrypt file name
    encrypted_file_name: bytes = symmetric_encrypt(symmetric_key, iv, file_name)

    # Convert bob's public key from bytes to a pem
    bobs_public_key = load_pem_public_key(bobs_public_key_data, backend=default_backend())

    # key - Encrypt the symmetric key using bobs public key
    encrypted_sym_key_iv = bobs_public_key.encrypt(
        pack_key(symmetric_key, iv),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "file_name": bytes_to_alpha_str(encrypted_file_name),
        "contents": bytes_to_alpha_str(encrypted_file),
        "verify": bytes_to_alpha_str(encrypted_hash_file),
        "key": bytes_to_alpha_str(encrypted_sym_key_iv)
    }


def symmetric_encrypt(key: bytes, iv: bytes, plain_bytes: bytes):
    """
    Encrypts a plain text message using a symmetric key
    :param key: The symmetric key
    :param: iv: Initialization vector
    :param plain_bytes: The message to encrypt
    :return: A tuple containing hte key and  A byte array containing the IV appended onto the symmetric key
    """
    # Make AES-CBC Cipher object with the symmetric given key and IV
    enc: bytes = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()

    # Generate cipher text from the plaintext
    ciphered_text: bytes = enc.update(pad_bytes(plain_bytes)) + enc.finalize()

    return ciphered_text


def symmetric_decrypt(key_iv, ciphered_text):
    """
    Decrypts a ciphered text message using a symmetric key and IV
    :param key_iv: A byte array containing the IV appended onto the symmetric key
    :param ciphered_text: The ciphered text to decrypt
    :return: The decrypted message in bytes
    """
    global symmetric_key
    symmetric_key, iv = unpack_key(key_iv)

    # Make AES-CBC decipher object with the symmetric given key and IV
    dec = Cipher(
        algorithms.AES(symmetric_key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return unpad_bytes(dec.update(ciphered_text) + dec.finalize())


def pack_message(message: str):
    """
    Message to pack and send to server by adding content length to be beginning.
    :param message byte array to pack with content length header
    :return: message with content length in bytes added to top of content all as bytes
    """
    message = str(len(message)) + '\r\n' + message
    return str_to_bytes(message)


def pack_key(key: bytes, iv: bytes):
    """
    Packs the key and iv into one byte array
    :param key: The symmetric key
    :param iv: Initialization vector
    :return: A byte array with the the initialization vector appended on the key
    """
    return key + iv


def unpack_key(key_iv: bytes):
    """
    Unpacks the key and iv into a tuple
    :param key_iv:
    :return: Tuple containing the Key and IV
    """
    key, iv = key_iv[0:32], key_iv[32:48]
    return key, iv


def bytes_to_alpha_str(byte_array: bytes):
    """
    converts bytes to string
    :param byte_array: bytes to convert
    :return: the alpha numeric string version of byte_array
    """
    return bytes_to_str(base64.b64encode(byte_array))


def alpha_str_to_bytes(string: str):
    """
    converts string to bytes
    :param string: string to convert
    :return: the byte version of the alpha numeric string
    """
    return base64.b64decode(str_to_bytes(string))


def bytes_to_str(byte_array: bytes):
    """
    converts bytes to string
    :param byte_array: bytes to convert
    :return: the string version of bytes
    """
    return byte_array.decode()


def str_to_bytes(string: str):
    """
    converts string to bytes
    :param string: string to convert
    :return: the byte version of string
    """
    return string.encode()


def pad_bytes(unpadded_bytes: bytes):
    """
    Pads a string to be a multiple of 16 bytes
    :param unpadded_bytes: The bytes to pad
    :return: The padded bytes
    """
    padder = _padding.PKCS7(128).padder()
    padded_bytes = padder.update(unpadded_bytes)
    padded_bytes += padder.finalize()
    return padded_bytes


def unpad_bytes(padded_bytes: bytes):
    """
    Unpads a string to be a multiple of 16 bytes
    :param padded_bytes: The padded bytes to unpad
    :return: The unpadded bytes as a bytes
    """
    unpadder = _padding.PKCS7(128).unpadder()
    unpadded_bytes = unpadder.update(padded_bytes)
    unpadded_bytes += unpadder.finalize()
    return unpadded_bytes


def printv(message):
    """
    Prints message only when in verbose mode
    :param message: Prints message in verbose mode
    """
    if verbose:
        print(message)


if __name__ == '__main__':
    main()