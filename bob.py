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
verbose: bool = False
private_key: bytes = []
public_key: bytes = []
certificate_private: bytes = []


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
    # Instantiate the parser
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
    pprintv(args)

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

    another = "a"
    while True:
        pprintv("Bob is ready to accept " + another + " connection, at " + str(host) +
                " and port " + str(args.port) + "...")
        # Wait for a connection to accept from the outside world.
        (alice_connection, alice_address) = s.accept()
        pprintv("Bob accepted " + another + " connection from " + str(alice_address) + ".")
        print('Alice Connected - ', end='')
        handle_alice_connection(alice_connection)
        another = "another"


def handle_alice_connection(connection):
    """
    Handles the client connection accepted by the Bob
    :param connection: Connection to Alice from the socket
    """
    message_from_alice:bytes = bytes()
    try:
        pprintv("Bob is waiting for a message from the Alice...")
        # 1. Alice will establish a connection to Bob and send the plain text message: "Hello"
        message_from_alice = receive_from_alice(connection)
        print(bytes_to_str(message_from_alice))

        # 2. Bob will respond with his encrypted DIGEST (see above). This digest will be encrypted with the
        # certificate agencies' private key.
        bobs_digest: json = json.dumps(generate_digest())
        connection.send(pack_message(bobs_digest))

        message_from_alice = receive_from_alice(connection)
        print('Alice Sent Text Message - ', end='')
        pprint(bytes_to_str(message_from_alice))
        # 3. Alice decodes the DIGEST and confirms that the name is really "bob" and then stores Bob's public key.
        # 4. Alice then will create a two part message to send back to Bob.
    except Exception as e:
        print(e)
    finally:
        connection.close()

    return message_from_alice


def send_to_alice(s: socket, message_in_bytes: bytes =[]):
    """
    Sends the encoded message to the server
    :param host: Host name of the server to connect to
    :param message_in_bytes: message in bytes to send to the server
    :param port: Port of the server to connect to
    :return: Returns the message in bytes from the server if successful
    """
    s.sendall(pack_message(message_in_bytes))
    return receive_from_alice(s)


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
        pprintv("Waiting for message from Alice...")
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

    pprintv("Message from Alice: " + str(message))
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
        'name': 'bob',
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