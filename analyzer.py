import re
import requests
from dataclasses import dataclass, asdict
from datetime import datetime
import urllib3
from typing import List, Dict, Any, Optional, Tuple
import re
import bisect


def _clip(s: Optional[str], n: int) -> Optional[str]:
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class AnalysisResult:
    """Structure for analysis results"""
    url: str
    api_keys: List[Dict[str, Any]]
    credentials: List[Dict[str, Any]]
    emails: List[Dict[str, Any]]
    interesting_comments: List[Dict[str, Any]]
    xss_vulnerabilities: List[Dict[str, Any]]
    xss_functions: List[Dict[str, Any]]
    api_endpoints: List[Dict[str, Any]]
    parameters: List[Dict[str, Any]]
    paths_directories: List[Dict[str, Any]]
    errors: List[str]
    file_size: int
    analysis_timestamp: str


class JavaScriptAnalyzer:
    """Enhanced analyzer with reduced false positives"""
    
    def __init__(self):
        # Improved API key patterns - more specific to reduce false positives
        self.api_key_patterns = [
                # -------------------------
                # AWS
                # -------------------------
                (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', True),
                (r'ASIA[0-9A-Z]{16}', 'AWS Temporary Access Key', True),
                (r'(?i)aws(.{0,20})?(secret|private).{0,20}?["\']([A-Za-z0-9/+=]{40})["\']', 'AWS Secret Key', True),

                # -------------------------
                # Google / GCP
                # -------------------------
                (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key', True),
                (r'(?i)google(.{0,20})?api(.{0,20})?key["\']?\s*[:=]\s*["\'](AIza[0-9A-Za-z\-_]{35})', 'Google API Key', True),

                # -------------------------
                # GitHub
                # -------------------------
                (r'ghp_[A-Za-z0-9]{36}', 'GitHub PAT', True),
                (r'github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}', 'GitHub Fine-grained Token', True),
                (r'gho_[A-Za-z0-9]{36}', 'GitHub OAuth Token', True),

                # -------------------------
                # GitLab
                # -------------------------
                (r'glpat-[A-Za-z0-9\-_]{20,}', 'GitLab Access Token', True),

                # -------------------------
                # Stripe
                # -------------------------
                (r'sk_live_[A-Za-z0-9]{24,}', 'Stripe Live Secret Key', True),
                (r'sk_test_[A-Za-z0-9]{24,}', 'Stripe Test Secret Key', True),
                (r'pk_live_[A-Za-z0-9]{24,}', 'Stripe Live Publishable Key', True),
                (r'pk_test_[A-Za-z0-9]{24,}', 'Stripe Test Publishable Key', True),

                # -------------------------
                # PayPal
                # -------------------------
                (r'access_token\$production\$[A-Za-z0-9]{22}\$[A-Za-z0-9]{86}', 'PayPal Access Token', True),

                # -------------------------
                # Slack
                # -------------------------
                (r'xox[baprs]-[0-9A-Za-z\-]{10,48}', 'Slack Token', True),

                # -------------------------
                # Firebase
                # -------------------------
                (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', 'Firebase Cloud Messaging Token', True),
                (r'(?i)firebase(.{0,20})?(api|server)?(.{0,20})?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{32,})', 'Firebase API Key', False),

                # -------------------------
                # JWT
                # -------------------------
                (r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b', 'JWT Token', False),

                # -------------------------
                # OAuth / Bearer tokens
                # -------------------------
                (r'Bearer\s+[A-Za-z0-9\-_\.=]{30,}', 'Bearer Token', False),

                # -------------------------
                # Private keys
                # -------------------------
                (r'-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----', 'Private Key', True),

                # -------------------------
                # High-entropy generic secrets
                # -------------------------
                (r'(?i)(api|access|secret|private|token|auth)[_-]?(key|token|secret)?\s*[:=]\s*["\']([A-Za-z0-9_\-\/+=]{32,})["\']', 'Generic Secret', False),

                # -------------------------
                # Hex secrets (often used in crypto, sessions)
                # -------------------------
                (r'\b[a-f0-9]{32}\b', 'MD5-like Secret', False),
                (r'\b[a-f0-9]{40}\b', 'SHA1-like Secret', False),
                (r'\b[a-f0-9]{64}\b', 'SHA256-like Secret', False),

                # -------------------------
                # Base64 secrets
                # -------------------------
                (r'\b[A-Za-z0-9+/]{40,}={0,2}\b', 'Base64 Encoded Secret', False),
            ]

        
        # Credentials - more specific
        self.credential_patterns = [
            # Passwords - avoid common false positives like "password: false"
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']', 'Password', False),
            (r'(?i)(db[_-]?password|database[_-]?password)\s*[:=]\s*["\']([^"\']{6,})["\']', 'Database Password', False),
            (r'(?i)(username|user[_-]?name|login)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Username', False),
        ]
        
        # Email patterns - more accurate
        self.email_patterns = [
            (r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', 'Email Address', True),
        ]
        
        # Comments
        self.comment_patterns = [
            (r'//\s*(TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING|TEMP)', 'Interesting Comment', True),
            (r'/\*[\s\S]{0,500}?(TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING)[\s\S]{0,500}?\*/', 'Interesting Comment (Multi-line)', True),
            (r'//\s*(password|secret|key|token|admin|backdoor|debug|test|hardcoded)', 'Suspicious Comment', False),
        ]
        
        # XSS patterns - improved
        self.xss_patterns = [
            (r'\.innerHTML\s*=\s*([^;]+)', 'innerHTML Assignment', 'high'),
            (r'\.outerHTML\s*=\s*([^;]+)', 'outerHTML Assignment', 'high'),
            (r'document\.write\s*\(([^)]+)\)', 'document.write()', 'high'),
            (r'document\.writeln\s*\(([^)]+)\)', 'document.writeln()', 'high'),
            (r'eval\s*\([^)]*(\$|location|window\.|document\.|user|input|param|query|search)', 'eval() with User Input', 'critical'),
            (r'dangerouslySetInnerHTML\s*=\s*\{[^}]*\}', 'React dangerouslySetInnerHTML', 'high'),
            (r'\$\([^)]+\)\.html\s*\(([^)]+)\)', 'jQuery .html()', 'medium'),
            (r'\$\([^)]+\)\.append\s*\(([^)]+)\)', 'jQuery .append()', 'medium'),
            (r'location\.(href|hash|search)\s*=\s*([^;]+)', 'Location Manipulation', 'medium'),
            (r'innerHTML\s*[+\=]\s*["\']', 'innerHTML Concatenation', 'high'),
        ]
        
        # XSS function patterns - functions that might lead to XSS
        self.xss_function_patterns = [
            (r'function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*\.(innerHTML|outerHTML|write)', 'Function with innerHTML/write', 'high'),
            (r'function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*eval\s*\(', 'Function with eval()', 'critical'),
            (r'(\w+)\s*[:=]\s*function\s*\([^)]*\)\s*\{[^}]*\.(innerHTML|outerHTML)', 'Arrow function with DOM manipulation', 'high'),
            (r'\.(onclick|onerror|onload|onmouseover)\s*=\s*function', 'Event handler assignment', 'medium'),
        ]
        
        # API patterns
        self.api_patterns = [
            # --------------------
            # fetch()
            # --------------------
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'fetch()'),
            (r'fetch\s*\(\s*`([^`]+)`', 'fetch() template'),
            (r'fetch\s*\(\s*([a-zA-Z_$][\w$]*)', 'fetch() variable'),

            # --------------------
            # XMLHttpRequest
            # --------------------
            (r'\.open\s*\(\s*["\'](GET|POST|PUT|DELETE|PATCH|OPTIONS)["\']\s*,\s*["\']([^"\']+)["\']', 'XMLHttpRequest'),
            (r'\.open\s*\(\s*["\'](GET|POST|PUT|DELETE|PATCH|OPTIONS)["\']\s*,\s*([a-zA-Z_$][\w$]*)', 'XMLHttpRequest variable'),

            # --------------------
            # Axios
            # --------------------
            (r'axios\.(get|post|put|delete|patch|options)\s*\(\s*["\']([^"\']+)["\']', 'axios'),
            (r'axios\.(get|post|put|delete|patch|options)\s*\(\s*`([^`]+)`', 'axios template'),
            (r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'axios config'),
            (r'axios\s*\(\s*\{[^}]*url\s*:\s*`([^`]+)`', 'axios config template'),

            # --------------------
            # jQuery AJAX
            # --------------------
            (r'\$\.(ajax|get|post|getJSON)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'jQuery AJAX'),
            (r'\$\.(ajax|get|post|getJSON)\s*\(\s*\{[^}]*url\s*:\s*`([^`]+)`', 'jQuery AJAX template'),
            (r'\$\.(get|post|getJSON)\s*\(\s*["\']([^"\']+)["\']', 'jQuery AJAX short'),

            # --------------------
            # Superagent
            # --------------------
            (r'superagent\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'superagent'),

            # --------------------
            # GraphQL
            # --------------------
            (r'["\'](/graphql[^"\']*)["\']', 'GraphQL Endpoint'),
            (r'graphqlEndpoint\s*[:=]\s*["\']([^"\']+)["\']', 'GraphQL Endpoint Var'),

            # --------------------
            # WebSocket
            # --------------------
            (r'new\s+WebSocket\s*\(\s*["\'](ws[s]?:\/\/[^"\']+)["\']', 'WebSocket URL'),

            # --------------------
            # EventSource (SSE)
            # --------------------
            (r'new\s+EventSource\s*\(\s*["\']([^"\']+)["\']', 'EventSource URL'),

            # --------------------
            # Absolute URLs
            # --------------------
            (r'["\'](https?:\/\/[^"\']+)["\']', 'Absolute URL'),

            # --------------------
            # API paths (relative)
            # --------------------
            (r'["\'](/api/[^"\']+)["\']', 'API Path'),
            (r'["\'](/v\d+/[^"\']+)["\']', 'Versioned API Path'),
            (r'["\'](/internal/[^"\']+)["\']', 'Internal API Path'),
            (r'["\'](/admin/[^"\']+)["\']', 'Admin Path'),

            # --------------------
            # Base URLs / config
            # --------------------
            (r'baseURL\s*[:=]\s*["\']([^"\']+)["\']', 'Base URL'),
            (r'api[_-]?url\s*[:=]\s*["\']([^"\']+)["\']', 'API URL Variable'),
            (r'endpoint\s*[:=]\s*["\']([^"\']+)["\']', 'Endpoint Variable'),

            # --------------------
            # Environment-based URLs
            # --------------------
            (r'process\.env\.[A-Z0-9_]+', 'Environment URL'),
        ]

        
        # Parameter patterns - comprehensive detection of ALL parameters
        self.parameter_patterns = [
            # URL query parameters - ALL parameters (not just sensitive ones)
            # Pattern: ?param=value or &param=value
            (r'["\']([^"\']*[?&](\w+)\s*=\s*[^"\'&\s]+)["\']', 'URL Query Parameter'),
            (r'[?&](\w+)\s*=\s*([^&\s"\']+)', 'Query Parameter'),
            
            # Multiple parameters in URL: ?param1=value1&param2=value2
            (r'["\']([^"\']*[?&][\w\-]+\s*=\s*[^"\'&\s]+(?:\s*&\s*[\w\-]+\s*=\s*[^"\'&\s]+)+)["\']', 'URL with Multiple Parameters'),
            
            # URL patterns with any parameters
            (r'["\']([^"\']+[?&][^"\']+)["\']', 'URL with Query Parameters'),
            
            # Function parameters - ALL function definitions
            (r'function\s+(\w+)\s*\(([^)]+)\)', 'Function Parameters'),
            (r'function\s*\(([^)]+)\)', 'Anonymous Function Parameters'),
            (r'(\w+)\s*[:=]\s*function\s*\(([^)]+)\)', 'Function Expression Parameters'),
            (r'\(([^)]+)\)\s*=>', 'Arrow Function Parameters'),
            (r'const\s+\w+\s*=\s*\(([^)]+)\)\s*=>', 'Arrow Function (const)'),
            (r'let\s+\w+\s*=\s*\(([^)]+)\)\s*=>', 'Arrow Function (let)'),
            (r'var\s+\w+\s*=\s*\(([^)]+)\)\s*=>', 'Arrow Function (var)'),
            
            # Method parameters
            (r'\.(\w+)\s*\(([^)]+)\)', 'Method Call Parameters'),
            
            # URLSearchParams - extract all parameters
            (r'URLSearchParams\s*\([^)]*\)', 'URL Parameters Object'),
            (r'new\s+URLSearchParams\s*\(([^)]+)\)', 'URLSearchParams Constructor'),
            (r'\.get\s*\(["\']([^"\']+)["\']', 'URLSearchParams.get()'),
            (r'\.getAll\s*\(["\']([^"\']+)["\']', 'URLSearchParams.getAll()'),
            (r'\.has\s*\(["\']([^"\']+)["\']', 'URLSearchParams.has()'),
            
            # Request parameters - ALL HTTP methods
            (r'\.(get|post|put|delete|patch|head|options)\s*\([^,]+,\s*\{([^}]+)\}', 'Request Parameters'),
            (r'\.(get|post|put|delete|patch)\s*\([^,]+,\s*([^,)]+)\)', 'Request Parameters (short)'),
            (r'fetch\s*\([^,]+,\s*\{([^}]+)\}', 'Fetch Request Parameters'),
            (r'axios\s*\(\s*\{([^}]+)\}', 'Axios Request Parameters'),
            
            # URL constructor with parameters
            (r'new\s+URL\s*\([^,]+,\s*["\']([^"\']+)["\']', 'URL Constructor with Parameters'),
            
            # Location/search patterns - ALL location parameters
            (r'location\.(search|href)\s*[=:]\s*["\']([^"\']*[?&][^"\']+)["\']', 'Location with Parameters'),
            (r'window\.location\.(search|href)\s*[=:]\s*["\']([^"\']*[?&][^"\']+)["\']', 'Window Location with Parameters'),
            (r'document\.location\.(search|href)\s*[=:]\s*["\']([^"\']*[?&][^"\']+)["\']', 'Document Location with Parameters'),
            
            # Template literals with parameters
            (r'`([^`]*[?&]\w+\s*=\s*[^`&]+)`', 'Template Literal with Parameters'),
            
            # Object/JSON parameters
            (r'\{([^}]*:\s*[^,}]+(?:,\s*[^}]*:\s*[^,}]+)*)\}', 'Object Parameters'),
            
            # Destructuring parameters
            (r'const\s+\{([^}]+)\}\s*=', 'Destructuring Parameters (const)'),
            (r'let\s+\{([^}]+)\}\s*=', 'Destructuring Parameters (let)'),
            (r'var\s+\{([^}]+)\}\s*=', 'Destructuring Parameters (var)'),
            (r'function\s+\w+\s*\(\{([^}]+)\}\)', 'Function with Destructuring'),
            
            # Array destructuring
            (r'const\s+\[([^\]]+)\]\s*=', 'Array Destructuring (const)'),
            (r'let\s+\[([^\]]+)\]\s*=', 'Array Destructuring (let)'),
            
            # Event handler parameters
            (r'\.(on\w+)\s*=\s*function\s*\(([^)]+)\)', 'Event Handler Parameters'),
            (r'\.addEventListener\s*\(["\']([^"\']+)["\'],\s*function\s*\(([^)]+)\)', 'EventListener Parameters'),
            (r'\.addEventListener\s*\(["\']([^"\']+)["\'],\s*\(([^)]+)\)\s*=>', 'EventListener Arrow Parameters'),
            
            # Callback parameters
            (r'\.(then|catch|finally)\s*\(([^)]+)\)', 'Promise Callback Parameters'),
            (r'\.(map|filter|reduce|forEach|find)\s*\(([^)]+)\)', 'Array Method Parameters'),
        ]
        
        # Path and directory patterns
        self.path_patterns = [
            (r'["\'](/[a-zA-Z0-9_\-/]+)["\']', 'Path'),
            (r'["\'](\.\.?/[a-zA-Z0-9_\-/]+)["\']', 'Relative Path'),
            (r'path\s*[:=]\s*["\']([^"\']+)["\']', 'Path Variable'),
            (r'dir\s*[:=]\s*["\']([^"\']+)["\']', 'Directory Variable'),
            (r'["\']([a-zA-Z0-9_\-/]+\.(js|json|html|css|png|jpg|svg))["\']', 'File Path'),
        ]
    
    def fetch_js_file(self, url: str) -> Optional[str]:
        """
        Fetch JavaScript file from URL
        
        NOTE: This runs on the SERVER, not in the browser.
        The server downloads the JavaScript file for analysis.
        """
        try:
            # Fix 0.0.0.0 to localhost for local connections
            if '0.0.0.0' in url:
                url = url.replace('0.0.0.0', 'localhost')
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/javascript, text/javascript, */*',
            }
            
            # Increased timeout for large files
            response = requests.get(url, headers=headers, timeout=60, verify=False, stream=True, allow_redirects=True)
            response.raise_for_status()
            
            # Check content type - some servers return wrong content type
            content_type = response.headers.get('Content-Type', '').lower()
            
            # Check content length
            content_length = response.headers.get('Content-Length')
            if content_length:
                try:
                    size_mb = int(content_length) / (1024 * 1024)
                    if size_mb > 10:  # Limit to 10MB
                        return None
                except (ValueError, TypeError):
                    pass
            
            # Read content in chunks for large files
            content = ""
            max_size = 10 * 1024 * 1024  # 10MB limit
            try:
                # Try to decode as text
                response.encoding = response.apparent_encoding or 'utf-8'
                for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
                    if chunk:
                        if isinstance(chunk, bytes):
                            chunk = chunk.decode('utf-8', errors='ignore')
                        content += chunk
                        if len(content) > max_size:
                            # Truncate if too large
                            content = content[:max_size]
                            break
            except UnicodeDecodeError:
                # Fallback: decode as bytes then decode to string
                content = response.content.decode('utf-8', errors='ignore')
                if len(content) > max_size:
                    content = content[:max_size]
            
            return content if content else None
        except requests.exceptions.Timeout as e:
            return None
        except requests.exceptions.ConnectionError as e:
            return None
        except requests.exceptions.RequestException as e:
            return None
        except Exception as e:
            return None
    
    def is_false_positive(self, match: str, pattern_type: str) -> bool:
        """Filter out common false positives"""
        match_lower = match.lower()
        
        # Common false positives
        false_positives = [
            'example.com', 'example.org', 'localhost', '127.0.0.1',
            'test', 'demo', 'sample', 'placeholder', 'your_api_key',
            'your_secret', 'api_key_here', 'secret_here', 'password: false',
            'password: true', 'password: null', 'password: undefined',
            'api_key: null', 'api_key: undefined', 'api_key: false',
        ]
        
        for fp in false_positives:
            if fp in match_lower:
                return True
        
        # Filter out JWT tokens that are too short or look like base64 encoded data structures
        if pattern_type == 'JWT Token':
            parts = match.split('.')
            if len(parts) < 3:
                return True
            if len(match) < 50:  # Too short to be a real JWT
                return True
        
        return False
    
    def find_patterns(self, content: str, patterns: list, context_lines: int = 5) -> list:
        findings = []
        if not content:
            return findings

        lines = content.split('\n')
        is_minified = (len(lines) == 1 and len(content) > 10000)

        if is_minified:
            context_lines = 0

        seen = set()

        for pattern_info in patterns:
            try:
                pattern = pattern_info[0]
                label = pattern_info[1]
                is_strict = False
                severity = None

                if len(pattern_info) >= 3 and isinstance(pattern_info[2], bool):
                    is_strict = pattern_info[2]
                if len(pattern_info) >= 4 and isinstance(pattern_info[3], str):
                    severity = pattern_info[3]
                if len(pattern_info) == 3 and isinstance(pattern_info[2], str):
                    severity = pattern_info[2]

                for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                    try:
                        full_match = match.group(0)

                        # Prefer captured secret value if exists
                        extracted = full_match
                        if match.lastindex:
                            for i in range(match.lastindex, 0, -1):
                                g = match.group(i)
                                if g and isinstance(g, str):
                                    extracted = g
                                    break

                        extracted = extracted.strip(' "\'')

                        # False positive filtering
                        if not is_strict and self.is_false_positive(full_match, label):
                            continue

                        start_pos = match.start()
                        line_num = content[:start_pos].count('\n') + 1

                        # Line content
                        line_text = lines[line_num - 1] if line_num <= len(lines) else ""
                        if len(line_text) > 500:
                            line_text = line_text[:220] + "..." + line_text[-220:]

                        # Context handling
                        if is_minified:
                            cs = max(0, start_pos - 250)
                            ce = min(len(content), match.end() + 250)
                            context = content[cs:ce]
                            ctx_start = line_num
                            ctx_end = line_num
                        else:
                            start_line = max(0, line_num - context_lines - 1)
                            end_line = min(len(lines), line_num + context_lines)
                            context = '\n'.join(lines[start_line:end_line])
                            ctx_start = start_line + 1
                            ctx_end = end_line

                        if len(context) > 1200:
                            mid = len(context) // 2
                            context = context[mid - 400: mid + 400]

                        match_preview = full_match[:220]

                        dedup_key = (label, line_num, match_preview)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        finding = {
                            "type": str(label),
                            "match": match_preview,
                            "extracted": extracted[:220],
                            "line": line_num,
                            "line_content": line_text.strip(),
                            "context": context,
                            "context_start_line": ctx_start,
                            "context_end_line": ctx_end,
                            "strict": is_strict,
                        }

                        if severity:
                            finding["severity"] = severity

                        findings.append(finding)

                    except Exception:
                        continue

            except Exception:
                continue

        return findings
    
    def extract_api_endpoints(self, content: str) -> List[Dict[str, Any]]:
        """Extract API endpoints"""
        endpoints = []
        lines = content.split('\n')
        
        for pattern, method in self.api_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count('\n') + 1
                
                url_path = match.group(1) if match.lastindex >= 1 else match.group(0)
                if len(match.groups()) > 1:
                    url_path = match.group(2) if match.lastindex >= 2 else match.group(1)
                
                # Filter out common false positives
                if any(fp in url_path.lower() for fp in ['example.com', 'localhost', 'placeholder']):
                    continue
                
                endpoint = {
                    'method': method,
                    'path': url_path[:200],
                    'line': line_num,
                    'full_match': match.group(0)[:150],
                    'line_content': lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
                
                endpoints.append(endpoint)
        
        # Remove duplicates
        seen = set()
        unique_endpoints = []
        for ep in endpoints:
            key = (ep['path'], ep['line'])
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)
        
        return unique_endpoints
    
    def _build_line_index(self, content: str):
            # positions of each '\n' for fast line lookup
            nl = [i for i, ch in enumerate(content) if ch == "\n"]
            lines = content.splitlines()
            return nl, lines

    def _pos_to_line(self, nl_positions: List[int], pos: int) -> int:
        # 1-based line number
        return bisect.bisect_left(nl_positions, pos) + 1

    def _parse_query_params(self, param_part: str) -> List[Tuple[str, str]]:
        # param_part may include leading ? or & and may contain multiple params
        # Example: "?a=1&b=2" or "a=1&b=2"
        out = []
        if not param_part:
            return out

        # remove leading ?, & safely
        param_part = param_part.lstrip("?&").strip()
        if not param_part:
            return out

        # split multiple params
        for chunk in param_part.split("&"):
            if not chunk or "=" not in chunk:
                continue
            k, v = chunk.split("=", 1)
            k = k.strip().lstrip("?&")
            v = v.strip()
            if k:
                out.append((k, v))
        return out

    def _snippet_context(self, content: str, start_pos: int, full_match_len: int, radius: int = 200) -> str:
        a = max(0, start_pos - radius)
        b = min(len(content), start_pos + full_match_len + radius)
        return content[a:b]

    def extract_parameters(self, content: str) -> List[Dict[str, Any]]:
        """Extract parameters from JavaScript including URL query parameters (smooth + safer)."""
        params: List[Dict[str, Any]] = []
        if not content:
            return params

        # Hard limits to prevent "stuck" on huge bundles
        MAX_TOTAL_FINDINGS = 100 #3000
        MAX_MATCHES_PER_PATTERN = 50 #1200
        MAX_CONTENT_FOR_FULL_SCAN = 2_500_000  # ~2.5MB, adjust as you want

        # Quick minified detection without heavy splitting
        is_probably_minified = ("\n" not in content and len(content) > 10000)

        # Build line index only when helpful
        if is_probably_minified or len(content) > MAX_CONTENT_FOR_FULL_SCAN:
            nl_positions = []
            lines = [content]  # keep minimal, line_num will be 1
        else:
            nl_positions, lines = self._build_line_index(content)

        # Compile patterns once
        compiled = []
        for item in self.parameter_patterns:
            if len(item) == 2:
                pattern, label = item
                kind = None
            else:
                pattern, label, kind = item[0], item[1], item[2]
            try:
                compiled.append((re.compile(pattern, re.MULTILINE | re.IGNORECASE), label, kind))
            except Exception:
                continue

        for cre, label, kind in compiled:
            match_count = 0

            for match in cre.finditer(content):
                match_count += 1
                if match_count > MAX_MATCHES_PER_PATTERN:
                    break
                if len(params) >= MAX_TOTAL_FINDINGS:
                    break

                try:
                    pairs = None  # important: reset per match

                    start_pos = match.start()
                    line_num = 1 if not nl_positions else self._pos_to_line(nl_positions, start_pos)

                    full_match = match.group(0) or ""
                    line_content = lines[line_num - 1].strip() if 1 <= line_num <= len(lines) else ""

                    if len(line_content) > 500:
                        line_content = line_content[:200] + "..." + line_content[-200:]

                    param_name = None
                    param_value = None
                    param_text = full_match

                    g1 = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                    g2 = match.group(2) if match.lastindex and match.lastindex >= 2 else None
                    payload = g1 or g2 or full_match

                    text_has_query_markers = ("?" in full_match) or ("&" in full_match)
                    payload_has_query_markers = isinstance(payload, str) and (
                        payload.startswith("?") or payload.startswith("&") or "&" in payload
                    )

                    mode = kind
                    if mode is None:
                        if text_has_query_markers or payload_has_query_markers:
                            mode = "query"
                        elif "(" in full_match and ")" in full_match:
                            mode = "func"
                        elif "{" in full_match:
                            mode = "object"
                        else:
                            mode = "generic"

                    if mode == "query":
                        pairs = self._parse_query_params(payload if isinstance(payload, str) else full_match)
                        if pairs:
                            for k, v in pairs:
                                ptext = f"{k}={_clip(v, 50)}"
                                params.append({
                                    "type": label,
                                    "parameter": _clip(ptext, 200),
                                    "param_name": _clip(k, 100),
                                    "param_value": _clip(v, 100),
                                    "line": line_num,
                                    "start_pos": start_pos,
                                    "full_match": _clip(full_match, 400),
                                    "line_content": line_content,
                                    "context": "",
                                    "context_start_line": None,
                                    "context_end_line": None,
                                })
                        else:
                            param_text = _clip(str(payload), 200)

                    elif mode == "func":
                        params_blob = g2 or g1 or payload or ""
                        if not isinstance(params_blob, str):
                            params_blob = str(params_blob)

                        first = params_blob.split(",", 1)[0].strip()
                        if "=" in first:
                            param_name = first.split("=", 1)[0].strip()
                            param_value = first.split("=", 1)[1].strip()
                        elif ":" in first:
                            param_name = first.split(":", 1)[0].strip()
                        else:
                            param_name = first or None

                        param_text = params_blob.strip() or full_match

                    elif mode == "object":
                        blob = g1 or payload or ""
                        if not isinstance(blob, str):
                            blob = str(blob)
                        blob = blob.strip()

                        first = blob.split(",", 1)[0].strip()
                        if ":" in first:
                            param_name = first.split(":", 1)[0].strip()
                        else:
                            param_name = first or None

                        param_text = blob or full_match

                    else:
                        blob = g1 or g2 or payload or ""
                        if not isinstance(blob, str):
                            blob = str(blob)
                        blob = blob.strip()

                        if "=" in blob:
                            param_name = blob.split("=", 1)[0].strip()
                            param_value = blob.split("=", 1)[1].strip()
                        elif ":" in blob:
                            param_name = blob.split(":", 1)[0].strip()
                        else:
                            param_name = (blob.split(",", 1)[0].strip() if blob else None)

                        param_text = blob or full_match

                    # Context
                    is_minified_like = is_probably_minified or (len(lines) <= 3) or (len(line_content) > 300)
                    if is_minified_like:
                        context = self._snippet_context(content, start_pos, len(full_match), radius=250)
                        context_start_line = None
                        context_end_line = None
                    else:
                        start_line = max(0, line_num - 6)
                        end_line = min(len(lines), line_num + 5)
                        context = "\n".join(lines[start_line:end_line])

                        if len(context) > 1000:
                            context = self._snippet_context(content, start_pos, len(full_match), radius=250)
                            context_start_line = None
                            context_end_line = None
                        else:
                            context_start_line = start_line + 1
                            context_end_line = end_line

                    # Fill context for query pairs already appended
                    if mode == "query" and pairs:
                        for i in range(len(pairs)):
                            params[-1 - i]["context"] = context
                            params[-1 - i]["context_start_line"] = context_start_line
                            params[-1 - i]["context_end_line"] = context_end_line
                        continue

                    params.append({
                        "type": label,
                        "parameter": _clip(param_text, 200),
                        "param_name": _clip(param_name, 100),
                        "param_value": _clip(param_value, 100),
                        "line": line_num,
                        "start_pos": start_pos,
                        "full_match": _clip(full_match, 400),
                        "line_content": line_content,
                        "context": context,
                        "context_start_line": context_start_line,
                        "context_end_line": context_end_line,
                    })

                except Exception:
                    continue

            if len(params) >= MAX_TOTAL_FINDINGS:
                break

        # De-dup
        seen = set()
        unique_params = []
        for p in params:
            key = (p.get("line"), p.get("start_pos"), p.get("full_match"), p.get("param_name"), p.get("parameter"))
            if key not in seen:
                seen.add(key)
                p.pop("start_pos", None)
                unique_params.append(p)

        return unique_params

    def extract_paths(self, content: str) -> List[Dict[str, Any]]:
        """Extract paths and directories"""
        paths = []
        lines = content.split('\n')
        
        for pattern, label in self.path_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count('\n') + 1
                
                path_text = match.group(1) if match.lastindex >= 1 else match.group(0)
                
                # Filter out common false positives
                if any(fp in path_text.lower() for fp in ['http://', 'https://', 'www.', 'example.com']):
                    continue
                
                path = {
                    'type': label,
                    'path': path_text[:200],
                    'line': line_num,
                    'full_match': match.group(0)[:150],
                    'line_content': lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
                
                paths.append(path)
        
        # Remove duplicates
        seen = set()
        unique_paths = []
        for path in paths:
            key = (path['path'], path['line'])
            if key not in seen:
                seen.add(key)
                unique_paths.append(path)
        
        return unique_paths
    
    def analyze(self, url: str) -> AnalysisResult:
        """
        Analyze JavaScript file for security issues
        
        ALL ANALYSIS HAPPENS SERVER-SIDE:
        - Fetches JavaScript file from URL (server-side HTTP request)
        - Runs regex patterns to find sensitive data
        - Extracts API endpoints, parameters, paths
        - Detects XSS vulnerabilities
        - Returns structured results
        
        No processing happens in the browser - only results are sent back.
        """
        errors = []
        
        try:
            # Try to fetch the file
            original_url = url
            # Fix 0.0.0.0 to localhost
            if '0.0.0.0' in url:
                url = url.replace('0.0.0.0', 'localhost')
            
            content = self.fetch_js_file(url)
            print(f"\x1b[1;94m[>] Fetching URL: {url}, Content fetched: {'Yes' if content else 'No'}")
            if content is None:
                # Try with 127.0.0.1 if localhost failed
                if 'localhost' in url:
                    url_alt = url.replace('localhost', '127.0.0.1')
                    content = self.fetch_js_file(url_alt)
                    if content:
                        url = url_alt
                
                if content is None:
                    error_msg = f"Failed to fetch {original_url}. "
                    if '0.0.0.0' in original_url:
                        error_msg += "Note: 0.0.0.0 is not a valid address to connect to. Please use 'localhost' or '127.0.0.1' instead. "
                    error_msg += "The file may be too large, inaccessible, or the server timed out."
                    errors.append(error_msg)
                    return AnalysisResult(
                    url=url,
                    api_keys=[],
                    credentials=[],
                    emails=[],
                    interesting_comments=[],
                    xss_vulnerabilities=[],
                    xss_functions=[],
                    api_endpoints=[],
                    parameters=[],
                    paths_directories=[],
                    errors=errors,
                    file_size=0,
                    analysis_timestamp=datetime.now().isoformat()
                )
        except Exception as e:
            errors.append(f"Error fetching {url}: {str(e)}")
            return AnalysisResult(
                url=url,
                api_keys=[],
                credentials=[],
                emails=[],
                interesting_comments=[],
                xss_vulnerabilities=[],
                xss_functions=[],
                api_endpoints=[],
                parameters=[],
                paths_directories=[],
                errors=errors,
                file_size=0,
                analysis_timestamp=datetime.now().isoformat()
            )
        
        file_size = len(content)
        print(f"\x1b[1;93m[>] Analyzing content of size: {file_size} bytes")
        
        # Run all analyses with error handling
        try:
            api_keys = self.find_patterns(content, self.api_key_patterns)
            print(f"\x1b[1;92m[>] Found {len(api_keys)} API keys")
        except Exception as e:
            errors.append(f"Error analyzing API keys: {str(e)}")
            api_keys = []
        
        try:
            credentials = self.find_patterns(content, self.credential_patterns)
            print(f"\x1b[1;92m[>] Found {len(credentials)} credentials")
        except Exception as e:
            errors.append(f"Error analyzing credentials: {str(e)}")
            credentials = []
        
        try:
            emails = self.find_patterns(content, self.email_patterns)
            print(f"\x1b[1;92m[>] Found {len(emails)} email addresses")
        except Exception as e:
            errors.append(f"Error analyzing emails: {str(e)}")
            emails = []
        
        try:
            comments = self.find_patterns(content, self.comment_patterns)
            print(f"\x1b[1;92m[>] Found {len(comments)} interesting comments")
        except Exception as e:
            errors.append(f"Error analyzing comments: {str(e)}")
            comments = []
        
        try:
            xss_vulns = self.find_patterns(content, self.xss_patterns)
            print(f"\x1b[1;92m[>] Found {len(xss_vulns)} XSS vulnerabilities")
        except Exception as e:
            errors.append(f"Error analyzing XSS vulnerabilities: {str(e)}")
            xss_vulns = []
        
        try:
            xss_funcs = self.find_patterns(content, self.xss_function_patterns)
            print(f"\x1b[1;92m[>] Found {len(xss_funcs)} XSS-related functions")
        except Exception as e:
            errors.append(f"Error analyzing XSS functions: {str(e)}")
            xss_funcs = []
        
        try:
            api_endpoints = self.extract_api_endpoints(content)
            print(f"\x1b[1;92m[>] Found {len(api_endpoints)} API endpoints")
        except Exception as e:
            errors.append(f"Error extracting API endpoints: {str(e)}")
            api_endpoints = []
  
        try:  
            parameters = self.extract_parameters(content)
            print(f"\x1b[1;92m[>] Found {len(parameters)} parameters")
        except Exception as e:
            errors.append(f"Error extracting parameters: {str(e)}")
            parameters = []
       # parameters = []
        try:
            
            paths = self.extract_paths(content)
            print(f"\x1b[1;92m[>] Found {len(paths)} paths and directories\x1b[0m")
        except Exception as e:
            errors.append(f"Error extracting paths: {str(e)}")
            paths = []
        
        # return AnalysisResult(
        #     url=url,
        #     api_keys=api_keys,
        #     credentials=credentials,
        #     emails=emails,
        #     interesting_comments=comments,
        #     xss_vulnerabilities=xss_vulns,
        #     xss_functions=xss_funcs,
        #     api_endpoints=api_endpoints,
        #     parameters=parameters,
        #     paths_directories=paths,
        #     errors=errors,
        #     file_size=file_size,
        #     analysis_timestamp=datetime.now().isoformat()
        # )
        return AnalysisResult(
            url=url,
            api_keys=api_keys,
            credentials=credentials,
            emails=emails,
            interesting_comments=comments,
            xss_vulnerabilities=xss_vulns,
            xss_functions=xss_funcs,
            api_endpoints=api_endpoints,
            parameters=parameters,
            paths_directories=paths,
            errors=errors,
            file_size=file_size,
            analysis_timestamp=datetime.now().isoformat()
        )


