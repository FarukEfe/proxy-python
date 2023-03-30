# socket.recv() is a synchronous(blocking) call that receives a certain amount of the data (in bytes) that is sent by the client
# Other methods like socket.gethostbyname, socket.inet_aton, etc. get certain parts of that data that is called in the function
# SOCK_STREAM is the method for TCP where packages are sent in order
# AF_INET is the method for IPv4 which is the IP protocol version 4
# threading.Thread puts each client on a different thread so that the server can individually respond to each client

import socket
import threading
import select

IP_ADRESS = ""
PORT = 3000
SOCKS_VERSION = 5

class Proxy:

    def __init__(self):
        self.username = "username"
        self.password = "password"

    def handle_client(self, connection):
        # greeting header
        # read and unpack 2 bytes from a client
        version, nmethods = connection.recv(2)

        # get available methods [0, 1, 2]
        # These are methods of authentication
        methods = self.get_available_methods(nmethods, connection)

        # accept only USERNAME/PASSWORD authentication
        if 2 not in set(methods):
            connection.close()
            return
        
        connection.sendall(bytes([SOCKS_VERSION, 2]))

        if not self.verify_credentials(connection):
            return
        
        #request (version=5)
        version, cmd, _, address_type = connection.recv(4)

        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)
        
        #convert bytes to unsigned short array
        port = int.from_bytes(connection.recv(2), 'big', signed=False)

        try:
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                print("* Connected to {}, {}".format(address, port))
            else:
                connection.close()
            
            addr = int.from_bytes(socket.inet_aton(bind_address[0]), "big", signed=False)
            port = bind_address[1]

            reply = b''.join([
                SOCKS_VERSION.to_bytes(1,'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(2, 'big')
            ])
        except Exception as e:
            # Return connection refused error
            reply = self.generate_failed_reply(address_type, 5)
        
        connection.sendall(reply)

        #establish data exchange
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(connection, remote)
        
        connection.close()

    def exchange_loop(self, client, remote):
        while True:
            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break
                
            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break

    def verify_credentials(self, connection):
        version = ord(connection.recv(1)) # should be 1

        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode("utf-8")

        password_len = ord(connection.recv(1))
        password = connection.recv(password_len).decode("utf-8")

        if username == self.username and password == self.password:
            #success, status = 0
            response = bytes([version, 0])
            connection.sendall(response)
            return True
        
        #success, status != 0
        response = bytes([version, 0xFF])
        connection.sendall(response)
        connection.close()
        return False

    def get_available_methods(self, nmethods, connection):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods
    
    def run(self, host, port):
        # SOCK_STREAM runs on TCP protocol and AF_INET runs on IP family 4 (for correct identificationa of IP Adresses)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen()

        # Testing
        print("* Socks5 proxy server is running on {}:{}".format(host,port))

        while True:
            conn, addr = s.accept()
            print("* new connection from {}".format(addr))
            # After listening for connection, retrieve client data and handle each client in a different thread
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()

if __name__ == "__main__":
    proxy = Proxy()
    proxy.run(IP_ADRESS, PORT)