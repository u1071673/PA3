import os
import argparse
import socket
import re
import sys
import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Verbose global flag
verbose = False
certificate_public: bytes = []
bobs_public_key: bytes = []
symmetric_key: bytes = []


def main():
    """
    Main program
    """
    global verbose
    global certificate_public
    global bobs_public_key
    global symmetric_key

    # Instantiate the parser
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
    pprintv(args)

    # Read files
    with open(args.certificate_public, "rb") as key_file:
        certificate_public = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Generate a 256-bit symmetric key
    symmetric_key = os.urandom(32)

    # Open the socket.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect to server a host and port.
    s.connect((args.host, args.port))

    try:
        # 1. Alice will establish a connection to Bob and send the plain text message: "Hello"
        # 2. Bob will respond with his encrypted DIGEST (see above). This digest will be encrypted with the
        # certificate agencies' private key.
        bobs_encrypted_digest: dict = json.loads(send_to_bob(s, 'Hello'))

        # 3. Alice decodes the DIGEST and confirms that the name is really "bob" and then stores Bob's public key.
        is_bob: bool = digest_confirmation(bobs_encrypted_digest)

        if not is_bob:
            raise ValueError("Message is not from Bob!")

        # 4. Alice then will create a two part message to send back to Bob.
        if args.message:
            message: str = args.message
            format_message(message, )
            reply_from_bob = send_to_bob(s, message)

        if args.file:
            file = open(args.file, "rb")
            file_data_bytes: bytes = file.read()
            file.close()
            reply_from_bob = send_to_bob(s, file_data_bytes)

    except Exception as e:
        print(e)
    finally:
        s.close()


def send_to_bob(s: socket, message: str):
    """
    Sends the encoded message to the server
    :param s: the socket connecting to Bob
    :param message: message as a string
    :return: Returns the message in bytes from the server if successful
    """
    s.sendall(pack_message(message))
    return receive_from_bob(s)


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
        pprintv("Waiting for message from Bob...")
        data = connection.recv(1024)
        content_length_with_body = re.split("\r\n", bytes_to_str(data))
        header = content_length_with_body[0]

        if header:
            header_size = len(header) + 2
            content_length = int(header)

        bytes_read += len(data)
        pprintv("Received:" + str(data))
        message += data

        if bytes_read - header_size == content_length:
            break

    pprintv("Message from Bob: " + str(message))
    return message[header_size:]


def digest_confirmation(bobs_digest: dict):
    """
    Parses Bob's digest and confirms message is from Bob and stores Bob's private key.
    :return: True if bob is confirmed otherwise false.
    """
    global bobs_public_key

    if 'name' not in bobs_digest or \
            'pub_key' not in bobs_digest or \
            'signature' not in bobs_digest or \
            bobs_digest['name'] != 'bob':
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

    bobs_public_key = alpha_str_to_bytes(bobs_digest['pub_key'])
    return True


def format_message(message: str, verify: str, key: str):
    """
    For a simple message, the following JSON generated:
    {
        message: "ENCRYPTED MESSAGE USING ALICE'S SYMMETRIC KEY",
        verify:  "HASH OF THE MESSAGE ENCRYPTED WITH ALICE'S SYMMETRIC KEY",
        key:     "SYMMETRIC KEY ENCRYPTED WITH BOB's PUBLIC KEY"
    }
    :param message: Encrypted message using Alice's symmetric key
    :param verify: Hash of the message encrypted with Alice's symmetric key
    :param key: Symmetric key encrypted with Bob's public key
    :return: A string of the message formated in JSON as shown in the description.
    """
    msg_dict: dict = {
        "message": message,
        "verify": verify,
        "key": key
    }
    return json.dumps(msg_dict)


def format_file(file_name: str, contents: str, verify: str, key: str):
    """
    For a file, the following JSON generated:
    {
        file_name: "ENCRYPTED FILE NAME USING ALICE'S SYMMETRIC KEY",
        contents:  "ENCRYPTED FILE CONTENTS USING SYMMETRIC KEY",
        verify:    "SHA 256 HASH OF THE FILE ENCRYPTED WITH THE SYMMETRIC KEY",
        key:       "SYMMETRIC KEY, ITSELF ENCRYPTED WITH BOB's PUBLIC KEY"
     }
    :param file_name: Encrypted file name using Alice's symmetric key
    :param contents: Encrypted file contents using symmetric key
    :param verify: SHA 256 hash of the file encrypted with the symmetric key
    :param key: Symmetric key, itself encrypted with Bob's public key.
    :return:
    """
    msg_dict = {
        "file_name": file_name,
        "contents": verify,
        "verify": contents,
        "key": key
    }
    return json.dumps(msg_dict)


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
    :return: The decrypted message
    """
    key, iv = unpack_key(key_iv)

    # Make AES-CBC decipher object with the symmetric given key and IV
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphered_text) + decryptor.finalize()


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


def pprintv(message):
    """
    Prints message only when in verbose mode
    :param message: Prints message in verbose mode
    """
    if verbose:
        print(message)


if __name__ == '__main__':
    main()