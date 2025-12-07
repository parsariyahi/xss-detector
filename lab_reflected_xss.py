import http.server
import socketserver
from urllib.parse import urlparse, parse_qs

class ReflectedXSSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        search_term = query.get('q', [''])[0]
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        
        html = f'''<html>
<head><title>Search Results</title></head>
<body>
    <h1>Search Results</h1>
    <form method="GET">
        <input type="text" name="q" value="{search_term}">
        <button type="submit">Search</button>
    </form>
    <p>You searched for: {search_term}</p>
</body>
</html>'''
        
        self.wfile.write(html.encode())

if __name__ == '__main__':
    PORT = 8081
    with socketserver.TCPServer(("", PORT), ReflectedXSSHandler) as httpd:
        print(f"Reflected XSS Lab running on http://localhost:{PORT}")
        print("Test with: http://localhost:8081/search?q=<script>alert(1)</script>")
        httpd.serve_forever()
