from lib.single_command_buffer import SingleCommandBuffer
from lib.cert_funcs import sign_csr_with_ecc_ca, import_certificate, import_ecc_key, get_csr_cn
from lib.hash_measurement import create_hash

from dotenv import load_dotenv

import logging
import socket
import ssl
import os
import time


load_dotenv()

CA_KEY_PATH = os.environ.get("CA_KEY_PATH", "")
CA_CERT_PATH = os.environ.get("CA_CERT_PATH", "")
SSL_KEY_PATH = os.environ.get("SSL_KEY_PATH", "")
SSL_CERT_PATH = os.environ.get("SSL_CERT_PATH", "")
TARGET_VALUE_PATH = os.environ.get("TARGET_VALUE_PATH", "")

CA_KEY = import_ecc_key(
    CA_KEY_PATH
)
CA_CERT = import_certificate(
    CA_CERT_PATH
)
SSL_KEY = import_ecc_key(
    SSL_KEY_PATH
)
SSL_CERT = import_certificate(
    SSL_CERT_PATH
)


enrolled = []


def sign_csr(csr: bytes) -> bytes:
    return sign_csr_with_ecc_ca(
        csr,
        CA_KEY,
        CA_CERT
    )


with open(TARGET_VALUE_PATH, "rb") as f:
    VERIFIED_HASH = create_hash(f.read())


def handle_client(client: socket.socket | ssl.SSLSocket, remote_id: str | None):
    print("ID:", remote_id)
    buf = SingleCommandBuffer()

    while True:
        try:
            if not (rcv := client.recv(128)):
                print("Client disconnected.")
                break
            buf.update(rcv)
            #print(f"'{rcv.decode()}'")

            while (cmd := buf.get_next_command()):
                cmd = [c.decode() for c in cmd]
                print(cmd)
                if cmd[0] == "ENROLL":
                    print("Client wants to enroll...")
                    try:
                        raw_csr = "\n".join([l for l in cmd[1:] if len(l) > 0]).encode()
                        common_name = get_csr_cn(raw_csr)
                        if common_name in enrolled:
                            print("Already enrolled.")
                            resp = b"ERR\nALREADY_ENROLLED\n\n"
                        else:
                            signed = sign_csr(raw_csr)
                            enrolled.append(common_name)
                            resp = b"SUCC\n" + signed + b"\n\n"
                            print("Success.")
                        client.send(resp)
                    except:
                        print("Error.")
                        client.send(b"ERR\n\n")
                elif cmd[0] == "TEST":
                    if remote_id != None:
                        print(f"Test command from '{remote_id}'.")
                        client.send(b"SUCC\n0\n\n")
                    else:
                        print("Unauthorized test command!")
                        client.send(b"ERR\nNO_AUTH\n\n")
                elif cmd[0] == "ATTEST":
                    if remote_id != None:
                        print(f"Attestation request from '{remote_id}': {cmd[1]}")
                        if cmd[1] == VERIFIED_HASH:
                            client.send(b"SUCC\n\n")
                        else:
                            client.send(b"ERR\nINV\n\n")
                    else:
                        print("Unauthorized Attest command!")
                        client.send(b"ERR\nNO_AUTH\n\n")
                else:
                    print("Invalid command from client.")
                    try:
                        client.send(b"ERR\nINV_CMD\n\n")
                        print("Sent msg?")
                    except Exception as e:
                        print("E INV CMD:", e)
                        pass
        except Exception as e:
            print("E GEN:", e)
            pass


def main():
    logging.basicConfig(level=logging.DEBUG)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.set_ciphers('ALL')

    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE+AESGCM:!aNULL:!MD5:!DSS')

    context.load_cert_chain(
        certfile=SSL_CERT_PATH,
        keyfile=SSL_KEY_PATH
    )
    context.load_verify_locations(
        cafile=CA_CERT_PATH
    )
    context.verify_mode = ssl.CERT_OPTIONAL

    sock.bind(("0.0.0.0", 5432))
    sock.listen()

    print("Listening...")

    while True:
        client, _ = sock.accept()
        try:
            wrapped_client = context.wrap_socket(
                client,
                server_side=True
            )

            client_cert = wrapped_client.getpeercert()
            if client_cert:
                subject = dict(x[0] for x in client_cert["subject"])
                common_name = subject.get("commonName")
                remote_id = common_name or None
            else:
                print("Client didn't use Certificate")
                remote_id = None

            handle_client(wrapped_client, remote_id)
        except ssl.SSLError as e:
            print("SSL Error:")
            print(e)
            #import traceback
            #traceback.print_exc()
        except Exception as e:
            print("General error accepting client")
        finally:
            try:
                wrapped_client.shutdown(socket.SHUT_RDWR)
            except:
                pass
            client.close()


if __name__ == "__main__":
    main()
