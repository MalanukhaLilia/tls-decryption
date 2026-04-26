import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/hello':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write("Hello from Malanukha Liliia КР-31".encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

server = HTTPServer(('127.0.0.1', 8443), Handler)


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_2


context.set_ciphers('AES256-SHA256:AES256-SHA:AES128-SHA256:AES128-SHA')

context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

server.socket = context.wrap_socket(server.socket, server_side=True)
print("The server is running on https://127.0.0.1:8443")
server.serve_forever()