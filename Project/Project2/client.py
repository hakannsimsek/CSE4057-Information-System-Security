import socket
import time
import errno
import sys
import threading
from utils import *
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 1234
RSA_PRIVATE_KEY = ""
RSA_PUBLIC_KEY = ""
PM_PARTNER_RSA_PUBLIC_KEY = ""
PM_PARTNER_AES_KEY = ""
PM_PARTNER_IV = ""
SERVER_RSA_PUBLIC = ""
IS_PM = False
AES_CIPHER_ENC = ""
AES_CIPHER_DEC = ""
# function to send general message
def send_message(client_socket, username):
    global IS_PM
    global PM_PARTNER_RSA_PUBLIC_KEY
    mac_header="".encode("utf-8")
    mac_field="".encode("utf-8")
    while True:
        message = input(f"{username} > ")
        message_type = "CHAT"
        if message:
            # user want to pm someone
            if message.split(" ")[0] == "@PM":
                message_type = "PMREQ"
            # user want to leave program
            elif message == "LOGOUT":
                message_type = "LOGOUT"
            # user want to exit pm
            elif IS_PM:
                if message == "EXIT PM":
                    message_type = "PMEXIT"
                    IS_PM = False
                else:
                    message_type = "PM"
            # if user trying to accept or reject pm request ignore this thread
            elif message == "Y" or message == "y" or message == "N" or message == "n":
                continue

            if message_type == "PM":
                mac_field = get_hashed_message(message).encode("utf-8")
                mac_header =  f"{len(mac_field):< {HEADER_LENGTH}}".encode("utf-8")
                message = AES_CIPHER_ENC.encrypt(pad(message.encode("utf-8"), AES.block_size))

                #AES_CIPHER = AES.new(PM_PARTNER_AES_KEY, AES.MODE_CBC, PM_PARTNER_IV)
            else:
                message = message.encode("utf-8")
            username_header = f"{len(username):< {HEADER_LENGTH}}".encode("utf-8")
            message_header = f"{len(message) :< {HEADER_LENGTH}}".encode("utf-8")
            message_type_header = f"{len(message_type) :< {HEADER_LENGTH}}".encode("utf-8")

            # send message to server
            client_socket.send(
                username_header + message_type_header + message_header + username.encode("utf-8") + message_type.encode(
                    "utf-8") + message + mac_header + mac_field)


# function for responding specific message type other than sending normal message
def send_simple_message(username, type, message,cipher_info=None):

    username_header = f"{len(username):< {HEADER_LENGTH}}".encode("utf-8")
    message_header = f"{len(message) :< {HEADER_LENGTH}}".encode("utf-8")
    message_type_header = f"{len(type) :< {HEADER_LENGTH}}".encode("utf-8")
    if cipher_info:
        cipher_info_header = f"{len(cipher_info) :< {HEADER_LENGTH}}".encode("utf-8")
        client_socket.send(
            username_header + message_type_header + message_header + username.encode("utf-8") + type.encode(
                "utf-8") + message+cipher_info_header+cipher_info)
        return

    client_socket.send(
        username_header + message_type_header + message_header + username.encode("utf-8") + type.encode(
            "utf-8") + message)


# function that receiving messages from server
def receive_messaege(client_socket, my_username):
    global IS_PM,PM_PARTNER_RSA_PUBLIC_KEY,AES_CIPHER_ENC,PM_PARTNER_IV,PM_PARTNER_AES_KEY,AES_CIPHER_DEC
    mac_field = ""
    while True:
        try:
            while True:
                # get message from server if server is up
                username_header = client_socket.recv(HEADER_LENGTH)
                if not len(username_header):
                    print("connection closed by the server")
                    sys.exit()

                # parse message
                username_length = int(username_header.decode("utf-8").strip())
                message_type_header = client_socket.recv(HEADER_LENGTH)
                message_type_length = int(message_type_header.decode("utf-8").strip())
                message_header = client_socket.recv(HEADER_LENGTH)
                message_length = int(message_header.decode("utf-8").strip())

                username = client_socket.recv(username_length).decode("utf-8")
                message_type = client_socket.recv(message_type_length).decode("utf-8")
                if message_type=="PM":
                    message = client_socket.recv(message_length)
                    mac_header = client_socket.recv(HEADER_LENGTH)
                    mac_field = client_socket.recv(int(mac_header.decode('utf-8'))).decode("utf-8")
                else:
                    message = client_socket.recv(message_length).decode("utf-8")
                ## classify message types and take action accordingly

                # handle login respond message type
                if message_type == "LOGINRES":
                    server_rsa_header = client_socket.recv(HEADER_LENGTH)
                    server_rsa_header_lenght = int(server_rsa_header.decode("utf-8").strip())
                    server_rsa_public_key = client_socket.recv(server_rsa_header_lenght)
                    return message, server_rsa_public_key
                # handle pm request message type
                elif message_type == "PMREQ":
                    respond_ = input(f"{message} > ")

                    if respond_ == "Y" or respond_ == "y":
                        pm_requester_rsa_header = client_socket.recv(HEADER_LENGTH)
                        pm_requester_rsa_header_length = int(pm_requester_rsa_header.decode("utf-8").strip())
                        pm_requester_signed_public = client_socket.recv(pm_requester_rsa_header_length)

                        PM_PARTNER_RSA_PUBLIC_KEY = RSA.importKey(pm_requester_signed_public)
                        aes_key = get_random_bytes(16)
                        iv = get_random_bytes(16)
                        PM_PARTNER_IV = iv
                        PM_PARTNER_AES_KEY = aes_key
                        AES_CIPHER_ENC = AES.new(aes_key, AES.MODE_CBC, iv)
                        AES_CIPHER_DEC = AES.new(aes_key, AES.MODE_CBC, iv)
                        aes_plus_iv = aes_key + iv
                        #encrypted_aes_plus_iv = PKCS1_OAEP.new(RSA_PRIVATE_KEY).encrypt(aes_plus_iv)
                        send_simple_message(my_username, "PMRES", "ACCEPT".encode("utf-8"),aes_plus_iv)
                        global IS_PM
                        IS_PM = True
                    else:
                        send_simple_message(my_username, "PMRES", "REJECT".encode("utf-8"))
                # handle pm respond message type
                elif message_type == "PMRES":

                    if " accept " in message:
                        pm_requester_rsa_header = client_socket.recv(HEADER_LENGTH)
                        pm_requester_rsa_header_length = int(pm_requester_rsa_header.decode("utf-8").strip())
                        pm_requester_signed_public = client_socket.recv(pm_requester_rsa_header_length)

                        PM_PARTNER_RSA_PUBLIC_KEY = RSA.importKey(pm_requester_signed_public)

                        pm_requester_ae_and_iv_header = client_socket.recv(HEADER_LENGTH)
                        pm_requester_ae_and_iv_header_length = int(pm_requester_ae_and_iv_header.decode("utf-8").strip())
                        pm_requester_ae_and_iv = client_socket.recv(pm_requester_ae_and_iv_header_length)
                        #aes_iv_decrypt = PKCS1_OAEP.new(PM_PARTNER_RSA_PUBLIC_KEY).decrypt(pm_requester_ae_and_iv)
                        aes_key,iv = pm_requester_ae_and_iv[0:16],pm_requester_ae_and_iv[16:]
                        PM_PARTNER_IV = iv
                        PM_PARTNER_AES_KEY = aes_key
                        AES_CIPHER_ENC = AES.new(aes_key, AES.MODE_CBC, iv)
                        AES_CIPHER_DEC = AES.new(aes_key, AES.MODE_CBC, iv)
                        IS_PM = True

                    print(message)
                # handle private message type
                elif message_type == "PM":
                    actual_message = unpad(AES_CIPHER_DEC.decrypt(message), AES.block_size).decode('utf-8')
                    if find_if_actual_message_match_with_hashed_one(actual_message,mac_field):
                        print(f"{username} > {actual_message}")
                    else:
                        print("Message authentication code does not match with code hackers here!")

                # handle user want to exit private chat
                elif message_type == "PMEXIT":
                    print(f"Your partner {username} left pm!")
                    IS_PM = False
                # handle logout
                elif message_type == "CLOSE":
                    print("Connection closed success!")
                    sys.exit()
                # public chat message
                else:
                    print(f"{username} > {message}")

        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.WSAEWOULDBLOCK:
                print("Reading error", str(e))
                sys.exit()
            continue

        except Exception as e:
            print("General error", str(e))
            sys.exit()
            pass


# udp connection for checking periodically whether user online or not
def udp_check(sec, udp_socket, username):
    while True:
        udp_socket.sendto(str(time.time()).encode("utf-8") + str("|" + username).encode("utf-8"), (IP, 12345))
        time.sleep(sec)


if __name__ == '__main__':
    # keep looping until user succesfully login
    while True:
        my_username = input("Username: ")
        my_password = input("Password: ")

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        client_socket.connect((socket.gethostname(), PORT))
        client_socket.setblocking(False)

        RSA_PRIVATE_KEY, RSA_PUBLIC_KEY = get_private_and_public_rsa_keys()

        username = my_username.encode("utf-8")
        password = my_password.encode("utf-8")
        rsa_public = RSA_PUBLIC_KEY.exportKey()

        username_header = f"{len(username):< {HEADER_LENGTH}}".encode("utf-8")
        password_header = f"{len(password):< {HEADER_LENGTH}}".encode("utf-8")
        rsa_public_header = f"{len(rsa_public):< {HEADER_LENGTH}}".encode("utf-8")

        # send user information for login
        client_socket.send(username_header + password_header + rsa_public_header + username + password + rsa_public)

        # receive server respond for login request
        login_respond, SERVER_RSA_PUBLIC = receive_messaege(client_socket, my_username)

        if login_respond == "Login success!":
            print("Login success!")
            break
        else:
            print(login_respond)

    # after user successfully logged in create udp socket and connect to server's udp socket for user online check
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_check_thread = threading.Thread(target=udp_check, args=([6, udp_socket, my_username]))
    udp_check_thread.start()

    # create tcp connection with server for chatting
    connect_thread = threading.Thread(target=send_message, args=([client_socket, my_username]))
    send_thread = threading.Thread(target=receive_messaege, args=([client_socket, my_username]))
    connect_thread.start()
    send_thread.start()
    connect_thread.join()
    send_thread.join()
