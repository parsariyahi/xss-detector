import http.server
import socketserver
from urllib.parse import urlparse, parse_qs

class DOMHrefXSSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        
        html = '''<html>
<head><title>Redirect Service</title></head>
<body>
    <h1>URL Redirector</h1>
    <p>Loading redirect URL...</p>
    <script>
        const params = new URLSearchParams(window.location.search);
        const redirectUrl = params.get('url');
        if (redirectUrl) {
            // Vulnerable: direct assignment to location.href
            window.location.href = redirectUrl;
        }
    </script>
</body>
</html>'''
        
        self.wfile.write(html.encode())

if __name__ == '__main__':
    PORT = 8082
    with socketserver.TCPServer(("", PORT), DOMHrefXSSHandler) as httpd:
        print(f"DOM XSS (location.href) Lab running on http://localhost:{PORT}")
        print("Test with: http://localhost:8082/redirect?url=javascript:alert(document.domain)")
        httpd.serve_forever()
