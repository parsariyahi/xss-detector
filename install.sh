#!/bin/bash


echo "========================================"
echo "XSS Scanner Setup"
echo "========================================"


python3 --version
if [ $? -ne 0 ]; then
    echo "Error: Python 3 is required"
    exit 1
fi


read -p "Create virtual environment? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    python3 -m venv venv
    source venv/bin/activate
    echo "Virtual environment activated"
fi


echo "Installing Python dependencies..."
pip install -r requirements.txt


echo "Installing Playwright Chromium browser..."
playwright install chromium

echo "========================================"
echo "Setup completed!"
echo "========================================"
echo ""
echo "You can now run the scanner with:"
echo "  python xss_scanner.py https://example.com"
echo ""
echo "For more information, see README.md"
