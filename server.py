from http.server import HTTPServer, BaseHTTPRequestHandler

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Hello from your custom Python server!")

server = HTTPServer(('localhost', 8000), SimpleHTTPRequestHandler)
print("Server running on http://localhost:8000...")
server.serve_forever()
