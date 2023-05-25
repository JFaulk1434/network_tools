import socketserver
import importlib
import threading


class TelnetRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"Connected to the network scanner server.\n")
        while True:
            self.request.sendall(b"Enter command: ")
            data = self.request.recv(1024).strip()
            if not data:
                break

            command = data.decode("utf-8")

            try:
                module_name, *args = command.split()
                module = importlib.import_module(f"commands.{module_name}")
                response = module.run(*args)
                self.request.sendall(response.encode("utf-8"))
            except ImportError:
                self.request.sendall(b"Invalid command.\n")


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    server = socketserver.ThreadingTCPServer((HOST, PORT), TelnetRequestHandler)
    print(f"Server running on {HOST}:{PORT}")
    server.serve_forever()
