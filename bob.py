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
#    This file is mimics a server named Bob accessed by a client named Alice.
#    Bob follows the following steps in collaboration with Alice to simulate
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

# Verbose global flag
verbose: bool = False
private_key: bytes = []
public_key: bytes = []
certificate_private: bytes = []
symmetric_key: bytes = []


def main():
    """
    Main program
    """
    global verbose
    global private_key
    global public_key
    global certificate_private

    # The address at which Bob will listen for Alice on
    host = '127.0.0.1'

    # Instantiate the argument parser
    parser = argparse.ArgumentParser(description='Listens on the given port for communications from Alice')
    parser.add_argument('-port', '-p', type=int, default=65432, metavar='port',
                        help='the port at which Bob will listen for Alice on')
    parser.add_argument('private_key', type=str, metavar='private_key',
                        help='Bob\'s private key')
    parser.add_argument('public_key', type=str, metavar='public_key',
                        help='Bob\'s or Alice\'s public key to encrypt with')
    parser.add_argument('certificate_private', type=str, metavar='certificate_private',
                        help='certificate agency private key')
    parser.add_argument('-verbose', '-v', action='store_true',
                        help='prints more messages to console for debugging.')

    args = parser.parse_args()

    verbose = args.verbose
    printv(args)

    # Read files
    with open(args.private_key, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    with open(args.public_key, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    with open(args.certificate_private, "rb") as key_file:
        certificate_private = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Open the socket.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #  Bind the socket to a host and port.
    s.bind((host, args.port))

    # Listen for connection (with no backlog connection queue)
    s.listen(1)

    while True:
        print("--------------------------------------")
        # Wait for a connection to accept from the outside world.
        print("1) Waiting For Connection on " + str(host) + " port " + str(args.port))
        (alice_connection, alice_address) = s.accept()
        print("2) Connected from ", end="")
        print(alice_connection)
        handle_alice_connection(alice_connection)


def handle_alice_connection(connection):
    """
    Handles the client connection accepted by the Bob
    :param connection: Connection to Alice from the socket
    """
    message_from_alice:bytes = bytes()
    try:
        # 1. Alice will establish a connection to Bob and send the plain text message: "Hello"
        message_from_alice = receive_from_alice(connection)
        printv('Alice Connected - ' + bytes_to_str(message_from_alice))

        # 2. Bob will respond with his encrypted DIGEST (see above). This digest will be encrypted with the
        # the certificate agencies' private key.
        bobs_digest: json = json.dumps(generate_digest(), indent=4, sort_keys=True)
        print("2) Sending Digest Information:")
        print("\t" + str(bobs_digest).replace('\n', '\n\t'))
        connection.send(pack_message(bobs_digest))

        # 3. Alice decodes the DIGEST and confirms that the name is really "bob" and then stores Bob's public key.
        # 4. Alice then will create a two part message to send back to Bob.
        print("3) Awaiting private communication")
        message_from_alice: dict = json.loads(receive_from_alice(connection))
        print("4) Received message from Alice:")
        print("\t" + json.dumps(message_from_alice, indent=4, sort_keys=True).replace('\n', '\n\t'))
        if 'message' in message_from_alice:
            verified: bool = decrypt_and_verify_message(message_from_alice)
        elif 'file_name' in message_from_alice:
            verified: bool = decrypt_and_verify_file(message_from_alice)
        else:
            raise ValueError("WARNING: Cannot Verify File or Message!")

        if not verified:
            raise ValueError("WARNING: Cannot Verify Message!")

    except Exception as e:
        print(e)
    finally:
        connection.close()

    return message_from_alice


def decrypt_and_verify_message(message: dict):
    """
    For a simple message, the following JSON generated:
    {
        message: "ENCRYPTED MESSAGE USING ALICE'S SYMMETRIC KEY",
        verify:  "HASH OF THE MESSAGE ENCRYPTED WITH ALICE'S SYMMETRIC KEY",
        key:     "SYMMETRIC KEY ENCRYPTED WITH BOB'S PUBLIC KEY"
    }
    :param message: Encrypted message using Alice's symmetric key
    :return: A dictionary ready that is ready for JSON formatting.
    """
    # Parse information out of dictionary
    if 'message' not in message or \
            'verify' not in message or \
            'key' not in message:
        return False

    encrypted_message: bytes =  alpha_str_to_bytes(message['message'])
    encrypted_hash_message: bytes = alpha_str_to_bytes(message['verify'])
    encrypted_sym_key_iv: bytes = alpha_str_to_bytes(message['key'])

    # Pull Alice's symmetric key and decrypt it with Bob's private key
    symmetric_key_iv: bytes = private_key.decrypt(
        encrypted_sym_key_iv,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Use Alice's symmetric key to decode the message
    message: bytes = symmetric_decrypt(symmetric_key_iv, encrypted_message)
    print("5) Secret Message Decoded:")
    print("\t" + bytes_to_str(message))

    # Use Alice's symmetric key to decode the hashed message
    bob_hashed_message: bytes = symmetric_decrypt(symmetric_key_iv, encrypted_hash_message)

    # Rehash Alice's message
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    alice_hashed_message: bytes = digest.finalize()
    # and compare it to Alice's hashed message
    if bob_hashed_message == alice_hashed_message:
        print("6) Message Hash Checks Out!")
        printv('Alice Sent Text Message - \"' + bytes_to_str(message) + '\"')
        return True
    else:
        return False


def decrypt_and_verify_file(message: dict):
    """
    For a simple message, the following JSON generated:
    {
        message: "ENCRYPTED MESSAGE USING ALICE'S SYMMETRIC KEY",
        verify:  "HASH OF THE MESSAGE ENCRYPTED WITH ALICE'S SYMMETRIC KEY",
        key:     "SYMMETRIC KEY ENCRYPTED WITH BOB'S PUBLIC KEY"
    }
    :param message: Encrypted message using Alice's symmetric key
    :return: A dictionary ready that is ready for JSON formatting.
    """
    # Parse information out of dictionary
    if 'file_name' not in message or \
            'contents' not in message or \
            'verify' not in message or \
            'key' not in message:
        return False

    encrypted_file_name: bytes =  alpha_str_to_bytes(message['file_name'])
    encrypted_file: bytes =  alpha_str_to_bytes(message['contents'])
    encrypted_hash_file: bytes = alpha_str_to_bytes(message['verify'])
    encrypted_sym_key_iv: bytes = alpha_str_to_bytes(message['key'])

    # Pull Alice's symmetric key and decrypt it with Bob's private key
    symmetric_key_iv: bytes = private_key.decrypt(
        encrypted_sym_key_iv,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Use Alice's symmetric key to decode the file name
    file_name: bytes = symmetric_decrypt(symmetric_key_iv, encrypted_file_name)

    # Use Alice's symmetric key to decode the file contents
    file_contents: bytes = symmetric_decrypt(symmetric_key_iv, encrypted_file)
    print("5) Secret Message Decoded:")
    print("\t" + bytes_to_str(file_contents))

    # Use Alice's symmetric key to decode the hashed file contents
    bob_hashed_file_contents: bytes = symmetric_decrypt(symmetric_key_iv, encrypted_hash_file)
    # Rehash Alice's message
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(file_contents)
    alice_hashed_message: bytes = digest.finalize()
    # and compare it to Alice's hashed message
    if bob_hashed_file_contents == alice_hashed_message:
        print("6) Message Hash Checks Out!")
        printv('Alice Sent a File - ' + bytes_to_str(file_name))
        # Save file
        with open(file_name, 'wb') as file:
            file.write(file_contents)
            printv('File Saved.')

        return True

    # Couldn't verify file
    return False


def receive_from_alice(connection):
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
        # Waiting for message from Alice...
        data = connection.recv(1024)
        if content_length == sys.maxsize:
            content_length_with_body = re.split("\r\n", bytes_to_str(data))
            header = content_length_with_body[0]

            if header:
                header_size = len(header) + 2
                content_length = int(header)

        bytes_read += len(data)
        message += data

        if bytes_read - header_size == content_length:
            break

    return message[header_size:]


def generate_digest():
    """
    Generates Bob's digest from the CA private key.
    :return: dictionary of digest
    """
    public_pem = public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    signed_pub: bytes = certificate_private.sign(
        public_pem,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return {
        'name': bytes_to_alpha_str(b'bob'),
        'pub_key': bytes_to_alpha_str(public_pem),  # BOBS PUBLIC KEY GOES HERE
        'signature': bytes_to_alpha_str(signed_pub)  # BOBS PUBLIC KEY SIGNED WITH CERT AGENCY PRIVATE KEY
    }


def symmetric_encrypt(key: bytes, plaintext: str):
    """
    Encrypts a plain text message using a symmetric key
    :param key: The symmetric key
    :param plaintext: The message to encrypt
    :return: A byte array containing the IV appended onto the symmetric key
    """
    # Generate a random 128-bit IV
    iv: bytes = os.urandom(16)

    # Make AES-CBC Cipher object with the symmetric given key and IV
    encryptor: bytes = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()

    # Generate cipher text from the plaintext
    ciphered_text: bytes = encryptor.update(plaintext) + encryptor.finalize()

    return pack_key(ciphered_text, iv)


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
    decryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return unpad_bytes(decryptor.update(ciphered_text) + decryptor.finalize())


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