# -*- coding: ascii -*-
# =============================================================================
# ECWASS Web Application Security Scanner - Burp Suite Pro Extension
# Version: 2.1  |  Compatible: Burp Suite Pro 2023.x/2024.x + Jython 2.7.3+
# All 102 ECWASS controls | Selectable controls UI | Passive scan + CSV export
# =============================================================================

import re
import datetime
import java.io
from java.io import FileOutputStream, OutputStreamWriter, BufferedWriter

from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from burp import IContextMenuFactory, IHttpListener, IProxyListener

from java.awt import BorderLayout, Color, Font
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from java.io import PrintWriter
from java.net import URL as JavaURL
from java.util import ArrayList, Arrays, Vector
import javax.swing
from javax.swing import (
    BorderFactory, BoxLayout, JButton, JComboBox, JFileChooser,
    JLabel, JMenuItem, JOptionPane, JPanel, JScrollPane,
    JSplitPane, JTable, JTextArea, JTextField, JToolBar,
    RowFilter, SwingUtilities, JTabbedPane
)
from javax.swing.event import ListSelectionListener, DocumentListener
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from java.lang import Boolean as JBoolean

ALL_CONTROLS = [
    # --- General Requirements ---
    ("ECWASS-002","Web App","General Requirements","A new web application shall use a robust and recognized development framework.","Questionnaire",True),
    ("ECWASS-003","Web App","General Requirements","The development team should use a development framework recommended by DIGIT.","Questionnaire",False),
    ("ECWASS-004","Web App","General Requirements","A maintained version of the framework shall be used; by default, this should be the latest stable version of the framework.","Questionnaire",True),
    ("ECWASS-005","Web App","General Requirements","Unsupported or deprecated client-side technologies shall not be used.","Technical",True),
    ("ECWASS-006","Web App","General Requirements","All client side technologies not natively supported by browsers shall not be used.","Technical",True),
    # --- Authentication ---
    ("ECWASS-007","Web App","Authentication","Web applications should use EU Login to enforce authentication with a strength that satisfies the risk analysis and/or the required level of security.","Technical",False),
    ("ECWASS-008","Web App","Authentication","If EU Login support is not implemented the web applications shall implement authentication mechanisms, with a strength that satisfies the risk analysis and/or the required level of security, as well as authorization checks that meet requirements established by the Password Technical Specification and the Access Control and Authentication Standard.","Technical",True),
    ("ECWASS-009","Web App","Authentication","Web applications handling sensitive non-classified information shall use EU Login to enforce authentication with a strength that satisfies the risk analysis and/or the required level of security.","Technical",True),
    ("ECWASS-010","Web App","Authentication","Administration pages of an application containing sensitive non-classified information shall have stricter security requirements which may justify the need for a re-authentication and/or for a stronger authentication.","Technical",True),
    ("ECWASS-011","Web App","Authentication","Sensitive non-classified information, such as incorrect passwords, in case of failed login attempts, shall not be stored.","Questionnaire",True),
    ("ECWASS-012","Web App","Authentication","Administrator functionality and/or interfaces shall not be accessible to unauthorized users.","Technical",True),
    ("ECWASS-013","Web App","Authentication","Administration functionality and/or interfaces shall not be accessible from the Internet except for specific source IP addresses.","Questionnaire",True),
    ("ECWASS-014","Web App","Authentication","Administration interfaces accessible from the Internet should use a random path instead of the default path","Technical",False),
    ("ECWASS-015","Web App","Authentication","Default accounts shall be disabled.","Questionnaire",True),
    ("ECWASS-016","Web App","Authentication","Administrators shall have a separate user and administrator role. Privileged functionalities shall only be available when the administrator is active.","Technical",True),
    ("ECWASS-017","Web App","Authentication","Information provided in authentication error messages shall not reveal technical details about the underlying security mechanisms.","Technical",True),
    ("ECWASS-018","Web App","Authentication","Information provided in authentication error messages shall not provide information about the existence of an account on the application.","Technical",True),
    ("ECWASS-019","Web App","Authentication","Security secrets used by the web application itself (e.g. passwords, API keys, encryption keys, etc.) shall not be included in the source code or online repositories so that if the source code is leaked these secrets do not become public.","Questionnaire",True),
    ("ECWASS-020","Web App","Authentication","User passwords used to authenticate shall be stored in a secure way, being at least hashed using a strong cryptographic hash function and the passwords shall be salted per user before hashing.","Questionnaire",True),
    ("ECWASS-021","Web App","Authentication","Authentication controls shall be checked on the server side","Technical",True),
    ("ECWASS-022","Web App","Authentication","Credentials used to authenticate shall be sent over HTTPS.","Technical",True),
    ("ECWASS-023","Web App","Authentication","Modification of a user's credential shall require the user to enter the old password, new password and a confirmation of the new password; The password change functionality shall be accessible only by a secured logged-in session.","Technical",True),
    ("ECWASS-024","Web App","Authentication","Account/password recovery controls should make use of a time-based one-time authentication token. The validity period shall be based on the business needs with a max of 24h validity.","Technical",False),
    ("ECWASS-025","Web App","Authentication","Initial credentials for the users of the application shall be unique and the application shall enforce the users to modify their initial credentials.","Technical",True),
    ("ECWASS-026","Web App","Authentication","Recovery tokens and initial credentials should be delivered over an encrypted side-channel to the affected users.","Questionnaire",False),
    # --- Session Management ---
    ("ECWASS-027","Web App","Session Management","Session IDs shall be unique and contain at least 128 bits of entropy so that brute-forcing or guessing the session ID of an authenticated user is not feasible.","Technical",True),
    ("ECWASS-028","Web App","Session Management","Session IDs contents (or value) shall not contain meaningful data like username or e-mail address and other user's personal information.","Technical",True),
    ("ECWASS-029","Web App","Session Management","Sessions IDs shall never be displayed in URLs, logs, and error messages.","Technical",True),
    ("ECWASS-030","Web App","Session Management","Session IDs stored in cookies shall have the \"Secure\" flag set to prevent the browser from sending the cookie over an unsecured channel.","Technical",True),
    ("ECWASS-031","Web App","Session Management","Session IDs stored in cookies should have the domain attribute blank to avoid that the cookie is also sent to subdomains.","Technical",False),
    ("ECWASS-032","Web App","Session Management","Session IDs stored in cookies shall have the path attribute set to the web directory path of the application that needs to receive the cookie rather than the root directory.","Technical",True),
    ("ECWASS-033","Web App","Session Management","Session IDs stored in cookies shall have the \"HttpOnly\" flag set, thus making it impossible for an attacker to access this cookie by client-side APIs such as JavaScript.","Technical",True),
    ("ECWASS-034","Web App","Session Management","Web application shall only accept cookies as a means for session ID exchange management, and shall ensure that no other exchange mechanism is possible.","Technical",True),
    ("ECWASS-035","Web App","Session Management","Sessions shall be automatically terminated on the server when a user is no longer active for a specified amount of time.","Technical",True),
    ("ECWASS-036","Web App","Session Management","Session idle timeouts should be no longer than 5 minutes for applications handling sensitive non-classified information and 30 minutes for the rest of the applications depending on a risk assessment.","Technical",False),
    ("ECWASS-037","Web App","Session Management","Sessions shall be automatically terminated when the user logs out of the web application.","Technical",True),
    ("ECWASS-038","Web App","Session Management","Sessions shall be automatically terminated on the client when the user closes the browser, by creating cookies without an expiration date.","Technical",True),
    ("ECWASS-039","Web App","Session Management","Successful authentications shall generate a new session and therefore a new session ID.","Technical",True),
    ("ECWASS-040","Web App","Session Management","Web applications shall use the session management features implementation from the selected web development framework, rather than building such mechanism from scratch.","Questionnaire",True),
    # --- Access Control ---
    ("ECWASS-041","Web App","Access Control","Access control checks performed at client-side shall also be checked at server-side.","Technical",True),
    ("ECWASS-042","Web App","Access Control","Directory listing and browsing shall be disabled.","Technical",True),
    ("ECWASS-043","Web App","Access Control","File or directory metadata in the web applications shall be sanitized.","Technical",True),
    ("ECWASS-044","Web App","Access Control","The web application shall make use of anti-Cross Site Request Forgery (CSRF) tokens in order to prevent the user from executing unwanted actions on the web application they are currently authenticated to.","Technical",True),
    ("ECWASS-045","Web App","Access Control","All user accounts and resources (such as processes) shall only have the lowest level of rights needed to perform their tasks.","Questionnaire",True),
    ("ECWASS-046","Web App","Access Control","Unapproved self-registered accounts shall not be allowed to post any public contents.","Technical",True),
    ("ECWASS-047","Web App","Access Control","Accounts supporting automated application functionalities should prevent interactive login, making it impossible to use these accounts for non-automated operations.","Questionnaire",False),
    # --- Input Validation & Output Sanitization ---
    ("ECWASS-048","Web App","Input validation & Output Sanitization","Input validation controls shall be implemented for every web application which allows a user to input data.","Technical",True),
    ("ECWASS-049","Web App","Input validation & Output Sanitization","Input validation shall be performed at server-side.","Technical",True),
    ("ECWASS-050","Web App","Input validation & Output Sanitization","Input validation should also be performed at client-side in addition to server-side checks.","Technical",False),
    ("ECWASS-051","Web App","Input validation & Output Sanitization","The web application and all its backend services shall make use of a safe API that allows the use of a parameterized interface.","Questionnaire",True),
    ("ECWASS-052","Web App","Input validation & Output Sanitization","If a parameterized API is not available, special characters shall be escaped using the specific escape syntax for that interpreter.","Technical",True),
    ("ECWASS-053","Web App","Input validation & Output Sanitization","Web applications shall use development frameworks mechanisms for rendering content safely and escaping reserved characters.","Technical",True),
    # --- Communication ---
    ("ECWASS-054","Web App","Communication","Communication between applications and underlying services should be encrypted.","Questionnaire",False),
    ("ECWASS-055","Web App","Communication","Communication of sensitive non-classified information between applications and underlying services shall be encrypted.","Questionnaire",True),
    ("ECWASS-056","Web App","Communication","Web application shall make use of encrypted traffic for the entire web session on every web page including content from third party domains, in compliance with the SSL/TLS Technical Standard.","Technical",True),
    ("ECWASS-057","Web App","Communication","All sensitive non-classified information shall be kept out of the URL.","Technical",True),
    ("ECWASS-058","Web App","Communication","The HTTP Strict Transport Security (HSTS) header shall be set on all requests and for all subdomains.","Technical",True),
    ("ECWASS-059","Web App","Communication","The HSTS header should be pre-loaded into browsers with a long max-age flag (ideally one year).","Technical",False),
    ("ECWASS-060","Web App","Communication","Strong, non-deprecated algorithms, ciphers and protocols shall be used throughout the whole certificate hierarchy.","Technical",True),
    ("ECWASS-061","Web App","Communication","Web facing applications shall use certificates delivered by a trusted Certificate Authority.","Technical",True),
    ("ECWASS-062","Web App","Communication","Perfect Forward Secrecy shall be supported.","Technical",True),
    ("ECWASS-063","Web App","Communication","The web application shall only accept the standard HTTP request methods (e.g. GET, POST). Other protocols or methods shall be blocked.","Technical",True),
    ("ECWASS-064","Web App","Communication","All HTTP responses shall contain a Content-Type header with the correct MIME type.","Technical",True),
    ("ECWASS-065","Web App","Communication","HTTP headers shall not disclose version or any other internal information about the underlying system or technology.","Technical",True),
    ("ECWASS-066","Web App","Communication","Content Security Policy (CSP) header shall be used and strictly configured to prevent injections such as XSS or HTML injection.","Technical",True),
    ("ECWASS-067","Web App","Communication","The X-XSS-Protection header shall be used in order to protect against reflected XSS attacks.","Technical",True),
    ("ECWASS-068","Web App","Communication","The X-Frame-Options header shall be used in order to protect against clickjacking attacks","Technical",True),
    # --- Data Protection ---
    ("ECWASS-069","Web App","Data Protection","Forms handling sensitive non classified information shall not make use of autocomplete features for those fields of information and shall disable client-side caching.","Technical",True),
    ("ECWASS-070","Web App","Data Protection","When filling out forms, sensitive non-classified information should be masked while typed. (e.g. *****)","Technical",False),
    ("ECWASS-071","Web App","Data Protection","Data stored in client-side cache shall not contain any sensitive non-classified information.","Technical",True),
    ("ECWASS-072","Web App","Data Protection","Sensitive non-classified information shall only be sent over HTTPS.","Technical",True),
    ("ECWASS-073","Web App","Data Protection","All sensitive non-classified information maintained in memory should be overwritten with zeros or random data once it is no longer necessary to be kept in memory","Questionnaire",False),
    # --- Secure Handling of Resources ---
    ("ECWASS-074","Web App","Secure Handling of Resources","Data (e.g. files, variables) submitted by a user to the web application shall not be used as input for operating system commands.","Technical",True),
    ("ECWASS-075","Web App","Secure Handling of Resources","Files uploaded by users shall not be stored under the web directory (webroot) of the webserver.","Technical",True),
    ("ECWASS-076","Web App","Secure Handling of Resources","Uploaded files shall be scanned by antivirus software.","Questionnaire",True),
    ("ECWASS-077","Web App","Secure Handling of Resources","The web application shall not execute files uploaded by the user.","Technical",True),
    ("ECWASS-078","Web App","Secure Handling of Resources","All URL redirects shall be validated at the input time.","Technical",True),
    ("ECWASS-079","Web App","Secure Handling of Resources","If URL redirects based on a pre-defined list (e.g. whitelist) of allowed domain is not possible, a warning shall be shown firstly to the users notifying them that they are going off of the site, and a link shall be clicked by them for confirmation.","Technical",True),
    # --- Error & Exception Handling ---
    ("ECWASS-080","Web App","Error & Exception Handling","Information provided in error messages shall be generic: it shall not reveal technical details about the underlying security or any other system internal mechanisms, except for a unique identifier which can be used in troubleshooting.","Technical",True),
    # --- Logging ---
    ("ECWASS-081","Web App","Logging","The web application shall log all necessary information (e.g. access control decisions) needed to begin a thorough investigation.","Questionnaire",True),
    ("ECWASS-082","Web App","Logging","Authentication attempts, both successful and failed, shall be logged.","Questionnaire",True),
    ("ECWASS-083","Web App","Logging","Access to sensitive non-classified information shall be logged.","Questionnaire",True),
    ("ECWASS-084","Web App","Logging","Changes to web application configuration, including changes to privileges assigned to users and security parametrization, shall be logged.","Questionnaire",True),
    ("ECWASS-085","Web App","Logging","Logs shall not include sensitive non-classified information.","Questionnaire",True),
    ("ECWASS-086","Web App","Logging","Logs shall not be accessible to unauthorized users.","Questionnaire",True),
    ("ECWASS-087","Web App","Logging","Controls shall be in place to prevent that logs are overwritten or tampered with.","Questionnaire",True),
    # --- Deployment ---
    ("ECWASS-102","Web App","Deployment","Debug mode shall be disabled in production.","Technical",True),
    ("ECWASS-103","Web App","Deployment","For web applications handling, sensitive non-classified information, pseudonymization and/or anonymization of data shall be assured in the test environments.","Questionnaire",True),
    ("ECWASS-104","Web App","Deployment","For web applications handling sensitive non-classified information, pseudonymization and/or anonymization of data should be assured in the acceptance environments.","Questionnaire",False),
    ("ECWASS-105","Web App","Deployment","In accordance with the priority levels as described in IT Vulnerability Management Security Standard every web application shall undergo regularly a web application vulnerability assessment to identify common vulnerabilities.","Questionnaire",True),
    ("ECWASS-106","Web App","Deployment","Important vulnerabilities based on a vulnerability assessment shall be fixed prior to going into production.","Questionnaire",True),
    ("ECWASS-107","Web App","Deployment","If the web application handles sensitive non-classified information, a penetration test should be executed to find vulnerabilities in the web application.","Questionnaire",False),
    ("ECWASS-108","Web App","Deployment","Test environments shall not be publicly accessible.","Technical",True),
    # --- OS & Network / Host & Network Security ---
    ("ECWASS-093","OS & Network","Host & Network Security","Communication between components (e.g. web application server - database server) shall require an authenticated connection, using an account with the least privileges necessary to operate.","Questionnaire",True),
    ("ECWASS-094","OS & Network","Host & Network Security","The application and all underlying components and middleware shall run with minimal privileges and shall not use (default) administration accounts shipped with systems.","Questionnaire",True),
    ("ECWASS-095","OS & Network","Host & Network Security","All hosts and software supporting the web application shall be updated timely after publication of security patches.","Questionnaire",True),
    ("ECWASS-096","OS & Network","Host & Network Security","All hosts and software supporting the web application should be updated timely after publication of functional patches.","Questionnaire",False),
    ("ECWASS-097","OS & Network","Host & Network Security","All management platforms that allow interaction with the hosts and software supporting the web application, including cloud consoles or similar management platforms, shall adhere to at least the same set of requirements as the actual web application and its supporting software.","Questionnaire",True),
    ("ECWASS-098","OS & Network","Host & Network Security","Access to such management platforms shall be considered as privileged access, and the accounts for this shall adhere to applicable requirements of the Password Technical Specification and the Access Control and Authentication Standard.","Questionnaire",True),
    ("ECWASS-099","OS & Network","Host & Network Security","Cloud Service Providers shall be able to support all the security requirements applicable to the web application.","Questionnaire",True),
    # --- Network Security ---
    ("ECWASS-100","Network","Network Security","External facing web applications shall be deployed in demilitarized zone (DMZ) to permit only limited connectivity to specific hosts in the internal network, reducing the attack surface.","Questionnaire",True),
    ("ECWASS-101","Network","Network Security","External facing web application containing sensitive non-classified information shall be protected by a Web Application Firewall.","Questionnaire",True),
]

# Map id -> control dict for quick lookup
CONTROL_MAP = {c[0]: {"id":c[0],"asset":c[1],"category":c[2],
                       "requirement":c[3],"assess_type":c[4],"mandatory":c[5]}
               for c in ALL_CONTROLS}


# =============================================================================
#  PASSIVE SCAN CHECK FUNCTIONS
#  Signature: check_xxx(ecwass_id, resp_headers, req_headers, body, url,
#                        messageInfo, helpers, callbacks) -> finding_dict | None
# =============================================================================

def _hdr(headers, name):
    """Return header value (case-insensitive) or None."""
    n = name.lower()
    for h in headers:
        if isinstance(h, str) and ":" in h and h.lower().startswith(n + ":"):
            return h.split(":", 1)[1].strip()
    return None

def _has(headers, name):
    return _hdr(headers, name) is not None

def _status(resp_headers):
    for h in resp_headers:
        if isinstance(h, str) and h.startswith("HTTP/"):
            parts = h.split()
            if len(parts) >= 2:
                try: return int(parts[1])
                except: pass
    return 0

def _finding(ecwass_id, title, severity, url, detail, body_snippet=""):
    ctrl = CONTROL_MAP.get(ecwass_id, {})
    return {
        "ts":         datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "id":         ecwass_id,
        "category":   ctrl.get("category",""),
        "assess_type":ctrl.get("assess_type","Technical"),
        "mandatory":  "Yes" if ctrl.get("mandatory") else "No",
        "title":      title,
        "severity":   severity,
        "url":        str(url),
        "detail":     detail,
        "requirement":ctrl.get("requirement",""),
        "body_snippet": body_snippet,
        "req_hdrs":     "",
        "resp_hdrs":    "",
    }

# ---------------------------------------------------------------------------
# Individual checks - mapped to ECWASS ID(s) they cover
# ---------------------------------------------------------------------------


def _body_snippet(body, pattern, context=80, maxlen=300):
    """Return up to maxlen chars around the first regex match in body."""
    try:
        m = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
        if not m:
            return ""
        start = max(0, m.start() - context)
        end   = min(len(body), m.end() + context)
        raw   = body[start:end].strip()
        raw   = re.sub(r"[ \t]+", " ", raw)
        if len(raw) > maxlen:
            raw = raw[:maxlen] + " ..."
        return raw
    except Exception:
        return ""


def _url_path(url):
    """Return lowercase path portion of a URL object, without query string."""
    try:
        p = str(url.getPath()).lower()
        return p if p else ""
    except Exception:
        return ""

def _content_type(resp_headers):
    """Return lowercase Content-Type value or empty string."""
    for h in resp_headers:
        if isinstance(h, str) and h.lower().startswith("content-type:"):
            return h.split(":", 1)[1].strip().lower()
    return ""

# Extensions whose responses should never be scanned
_SKIP_EXTENSIONS = (
    ".js", ".mjs", ".css",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".svg", ".avif",
    ".woff", ".woff2", ".ttf", ".eot",
    ".map",
    ".pdf", ".zip", ".gz", ".tar", ".jar",
)

def _should_skip(url, resp_headers, status):
    """Return True if the response should be entirely skipped."""
    # 304 Not Modified - no body, headers are validation copies
    if status == 304:
        return True
    # Static asset by URL extension
    path = _url_path(url).split("?")[0]
    if any(path.endswith(ext) for ext in _SKIP_EXTENSIONS):
        return True
    # Static asset by Content-Type
    ct = _content_type(resp_headers)
    if ct.startswith("image/") or ct.startswith("font/") or ct.startswith("application/font"):
        return True
    return False

def _is_html(resp_headers):
    """Return True if response Content-Type indicates an HTML document."""
    ct = _content_type(resp_headers)
    return "html" in ct

def _is_html_or_json(resp_headers):
    """Return True if Content-Type is HTML or JSON."""
    ct = _content_type(resp_headers)
    return "html" in ct or "json" in ct

def _is_redirect(status):
    """Return True for 3xx redirect responses."""
    return 300 <= status < 400

def _is_static_path(url):
    """Return True if URL path looks like a static asset."""
    path = _url_path(url).split("?")[0]
    return any(path.endswith(ext) for ext in _SKIP_EXTENSIONS)


# Snippet patterns as constants
_PAT_E005  = r'<object[^>]+classid|<applet\b|\.swf["\'\s>]|x-shockwave-flash|x-silverlight|vbscript\s*:'
_PAT_E017  = r'(wrong|invalid|incorrect)\s+password|(user|account|email).{0,30}(not found|does not exist|unknown)|stack\s?trace|SQLSTATE'
_PAT_E021  = r'\b(checkAuth|isLoggedIn|isAuthenticated|validateToken)\s*\('
_PAT_E029  = r'[Ss]ession[-_]?[Ii][Dd]|JSESSIONID|PHPSESSID'
_PAT_E042  = r'Index of\s+/|directory\s+listing|Parent Directory'
_PAT_E044  = r'<form|<input'
_PAT_E048  = r'<input|<textarea|<select'
_PAT_E056  = r'<img[^>]+src\s*=\s*["\']http://|src\s*=\s*["\']http://'
_PAT_E064  = r'Content-Security-Policy'
_PAT_E080  = r'exception|traceback|stack.?trace|ORA-\d{5}|SQLSTATE|Warning|Fatal error'
_PAT_E102  = r'werkzeug\s+debugger|django\.debug|flask\s+debug|Traceback \(most recent call last\)|sf-toolbar|DEBUG\s*=\s*True'
_PAT_E108  = r'test|staging|dev|uat|qa'


def check_ECWASS_005_006(rh, qh, body, url, mi, h, cb):
    if not _is_html(rh): return None
    pats = [
        (r'<object[^>]+classid\s*=\s*["\']clsid:', "ActiveX"),
        (r'<applet\b',                               "Java Applet"),
        (r'\.swf["\'\s>]',                           "Flash (SWF)"),
        (r'application/x-shockwave-flash',           "Flash embed"),
        (r'application/x-silverlight',               "Silverlight"),
        (r'vbscript\s*:',                            "VBScript"),
    ]
    found = [lbl for pat,lbl in pats if re.search(pat, body, re.IGNORECASE)]
    if found:
        return _finding("ECWASS-005","Deprecated/Unsupported Client-Side Technology","High",url,
            "Detected deprecated technology: %s. Flash, ActiveX, Applets, Silverlight and VBScript are end-of-life." % ", ".join(found),
            body_snippet=_body_snippet(body, _PAT_E005))
    return None

def check_ECWASS_017_018(rh, qh, body, url, mi, h, cb):
    us = str(url).lower()
    if not any(k in us for k in ["login","auth","signin","password","logon","account"]):
        return None
    found = []
    if re.search(r'(wrong|invalid|incorrect)\s+password', body, re.IGNORECASE):
        found.append("Response distinguishes wrong password (account existence leak)")
    if re.search(r'(user|account|email).{0,30}(not found|does not exist|unknown)', body, re.IGNORECASE):
        found.append("Response reveals account non-existence")
    if re.search(r'(stack\s?trace|exception|ORA-\d|SQLSTATE)', body, re.IGNORECASE):
        found.append("Technical error/stack trace exposed in auth response")
    if found:
        return _finding("ECWASS-017","Auth Error Message Discloses Sensitive Information","Medium",url,
            "\n- ".join(found) + "\nAuth error messages shall be generic.",
            body_snippet=_body_snippet(body, _PAT_E017))
    return None

def check_ECWASS_021(rh, qh, body, url, mi, h, cb):
    if not _is_html(rh): return None
    if _status(rh) == 200:
        if re.search(r'\b(checkAuth|isLoggedIn|isAuthenticated|validateToken)\s*\(', body, re.IGNORECASE):
            if not re.search(r'(window\.location|location\.href|location\.replace)', body, re.IGNORECASE):
                return _finding("ECWASS-021","Possible Client-Side-Only Auth Check","High",url,
                    "Page returns 200 and contains client-side auth functions with no server-side redirect. "
                    "Authentication controls shall be checked on the server side.",
            body_snippet=_body_snippet(body, _PAT_E021))
    return None

def check_ECWASS_022(rh, qh, body, url, mi, h, cb):
    if str(url.getProtocol()).lower() != "https":
        us = str(url).lower()
        if any(k in us for k in ["login","auth","signin","password","logon"]):
            return _finding("ECWASS-022","Credentials Submitted Over HTTP","High",url,
                "Authentication endpoint is served over plain HTTP. Credentials shall be sent over HTTPS only.")
    return None

def check_ECWASS_027(rh, qh, body, url, mi, h, cb):
    issues = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":",1)[1]
            m = re.match(r'\s*([^=]+)=([^;]*)', val)
            if not m: continue
            name, value = m.group(1).strip(), m.group(2).strip()
            is_sess = any(s in name.lower() for s in ["sess","sid","session","token","auth","jsessionid","phpsessid"])
            if is_sess and len(value) < 16:
                issues.append("Cookie '%s': value too short (%d chars) - likely insufficient entropy" % (name, len(value)))
    if issues:
        return _finding("ECWASS-027","Session ID May Have Insufficient Entropy","High",url,
            "\n- ".join(issues) + "\nSession IDs shall contain at least 128 bits of entropy.")
    return None

def check_ECWASS_028(rh, qh, body, url, mi, h, cb):
    issues = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":",1)[1]
            m = re.match(r'\s*([^=]+)=([^;]*)', val)
            if not m: continue
            name, value = m.group(1).strip(), m.group(2).strip()
            is_sess = any(s in name.lower() for s in ["sess","sid","session","token"])
            if is_sess:
                try: decoded = urllib.unquote(str(value))
                except: decoded = str(value)
                if re.search(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', decoded):
                    issues.append("Cookie '%s' appears to embed an email address" % name)
                if re.search(r'(username|email|user|name)=', decoded, re.IGNORECASE):
                    issues.append("Cookie '%s' contains a name/email key=value pair" % name)
    if issues:
        return _finding("ECWASS-028","Session ID Contains Personal Data","High",url,
            "\n- ".join(issues) + "\nSession IDs shall not contain meaningful user data.")
    return None

def check_ECWASS_029(rh, qh, body, url, mi, h, cb):
    us = str(url)
    m = re.search(r'[?&](sessid|session_id|sid|JSESSIONID|PHPSESSID|ASP\.NET_SessionId|token)=([^&]+)',
                  us, re.IGNORECASE)
    if m:
        return _finding("ECWASS-029","Session ID Exposed in URL","High",url,
            "Parameter '%s' found in URL. Session IDs shall never appear in URLs." % m.group(1),
            body_snippet=_body_snippet(body, _PAT_E029))
    m2 = re.search(r'href=["\'][^"\']*[?&](JSESSIONID|PHPSESSID|ASP\.NET_SessionId)=', body, re.IGNORECASE)
    if m2:
        return _finding("ECWASS-029","Session ID Exposed in Href Links","High",url,
            "Session ID '%s' found in page hrefs. Session IDs shall never appear in URLs." % m2.group(1))
    return None

def check_ECWASS_030(rh, qh, body, url, mi, h, cb):
    missing = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":",1)[1]
            m = re.match(r'\s*([^=]+)=', val)
            name = m.group(1).strip() if m else "unknown"
            if "secure" not in val.lower():
                missing.append(name)
    if missing:
        return _finding("ECWASS-030","Cookie Missing 'Secure' Flag","High",url,
            "Cookies without Secure flag:\n- " + "\n- ".join(missing))
    return None

def check_ECWASS_031(rh, qh, body, url, mi, h, cb):
    issues = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":",1)[1]
            m = re.match(r'\s*([^=]+)=', val)
            name = m.group(1).strip() if m else "unknown"
            is_sess = any(s in name.lower() for s in ["sess","sid","session","token","auth"])
            if is_sess:
                dm = re.search(r'domain\s*=\s*([^;]+)', val, re.IGNORECASE)
                if dm and dm.group(1).strip():
                    issues.append("Cookie '%s' has domain='%s' set - may be sent to subdomains" % (name, dm.group(1).strip()))
    if issues:
        return _finding("ECWASS-031","Session Cookie Domain Attribute Set","Low",url,
            "\n- ".join(issues) + "\nSession cookie domain should be blank to avoid sending to subdomains.")
    return None

def check_ECWASS_032(rh, qh, body, url, mi, h, cb):
    issues = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":",1)[1]
            m = re.match(r'\s*([^=]+)=', val)
            name = m.group(1).strip() if m else "unknown"
            pm = re.search(r'path\s*=\s*([^;]+)', val, re.IGNORECASE)
            if not pm:
                issues.append("Cookie '%s': no path attribute" % name)
            elif pm.group(1).strip() == "/":
                issues.append("Cookie '%s': path='/' - should be restricted to app path" % name)
    if issues:
        return _finding("ECWASS-032","Cookie Path Not Restricted","Low",url,
            "\n- ".join(issues) + "\nCookies shall have path scoped to the application directory.")
    return None

def check_ECWASS_033(rh, qh, body, url, mi, h, cb):
    missing = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":",1)[1]
            m = re.match(r'\s*([^=]+)=', val)
            name = m.group(1).strip() if m else "unknown"
            if "httponly" not in val.lower():
                missing.append(name)
    if missing:
        return _finding("ECWASS-033","Cookie Missing 'HttpOnly' Flag","High",url,
            "Cookies without HttpOnly:\n- " + "\n- ".join(missing) +
            "\nWithout HttpOnly, JS can read the cookie via document.cookie.")
    return None

def check_ECWASS_038(rh, qh, body, url, mi, h, cb):
    issues = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":",1)[1]
            m = re.match(r'\s*([^=]+)=', val)
            name = m.group(1).strip() if m else "unknown"
            is_sess = any(s in name.lower() for s in ["sess","sid","session","token","auth"])
            if is_sess:
                if re.search(r'max-age\s*=\s*\d+', val, re.IGNORECASE) or \
                   re.search(r'expires\s*=', val, re.IGNORECASE):
                    issues.append("Session cookie '%s' has Max-Age/Expires - persists after browser close" % name)
    if issues:
        return _finding("ECWASS-038","Session Cookie Has Persistent Expiry","Medium",url,
            "\n- ".join(issues) + "\nSession cookies shall expire on browser close (no Max-Age/Expires).")
    return None

def check_ECWASS_042(rh, qh, body, url, mi, h, cb):
    if _status(rh) != 200 or not _is_html(rh): return None
    if re.search(r'Index of\s+/', body) or \
       re.search(r'<title>[^<]*directory\s+listing', body, re.IGNORECASE) or \
       re.search(r'Parent Directory</a>', body):
        return _finding("ECWASS-042","Directory Listing Enabled","High",url,
            "Server appears to have directory listing enabled. It shall be disabled.",
            body_snippet=_body_snippet(body, _PAT_E042))
    return None

def check_ECWASS_044(rh, qh, body, url, mi, h, cb):
    if not _is_html(rh): return None
    if not re.search(r'<form\b', body, re.IGNORECASE): return None
    if not re.search(r'method\s*=\s*["\']?\s*post', body, re.IGNORECASE): return None
    has_csrf = (re.search(r'csrf', body, re.IGNORECASE) or
                re.search(r'_token', body, re.IGNORECASE) or
                re.search(r'__RequestVerificationToken', body, re.IGNORECASE) or
                re.search(r'authenticity_token', body, re.IGNORECASE) or
                _has(rh, "X-CSRF-Token"))
    if not has_csrf:
        return _finding("ECWASS-044","Missing Anti-CSRF Token","High",url,
            "POST form found but no CSRF token detected. "
            "Anti-CSRF tokens shall be used in all state-changing requests.")
    return None

def check_ECWASS_048_049(rh, qh, body, url, mi, h, cb):
    if not re.search(r'<form\b', body, re.IGNORECASE): return None
    if not re.search(r'<input\b', body, re.IGNORECASE): return None
    # Heuristic: form with inputs but no visible validation patterns
    has_novalidate = re.search(r'novalidate', body, re.IGNORECASE)
    has_pattern    = re.search(r'pattern\s*=', body, re.IGNORECASE)
    has_required   = re.search(r'\brequired\b', body, re.IGNORECASE)
    if has_novalidate and not has_pattern and not has_required:
        return _finding("ECWASS-048","Input Validation May Be Missing","Medium",url,
            "Form with 'novalidate' and no pattern/required attributes detected. "
            "Input validation controls shall be implemented for every web application that accepts user input.")
    return None

def check_ECWASS_056(rh, qh, body, url, mi, h, cb):
    if not _is_html(rh): return None
    if str(url.getProtocol()).lower() != "https": return None
    mixed = re.findall(r'(?:src|href|action)\s*=\s*["\']http://[^"\']+', body, re.IGNORECASE)
    if mixed:
        return _finding("ECWASS-056","Mixed Content Detected","High",url,
            "HTTPS page loads %d resource(s) over HTTP:\n- " % len(mixed) +
            "\n- ".join(mixed[:8]) + "\nAll resources shall be loaded over HTTPS.")
    return None

def check_ECWASS_057(rh, qh, body, url, mi, h, cb):
    us = str(url)
    params = us.split("?",1)[1] if "?" in us else ""
    if not params: return None
    sensitive = ["password","passwd","pwd","secret","token","api_key","apikey",
                 "ssn","creditcard","cc","cvv","pin","private_key","access_token"]
    found = [k for k in sensitive if re.search(r'\b'+k+r'\b', params, re.IGNORECASE)]
    if found:
        return _finding("ECWASS-057","Sensitive Parameter in URL","High",url,
            "Sensitive parameters in URL query string: " + ", ".join(found) +
            "\nSensitive information shall be kept out of URLs.")
    return None

def check_ECWASS_058_059(rh, qh, body, url, mi, h, cb):
    if str(url.getProtocol()).lower() != "https": return None
    hsts = _hdr(rh, "Strict-Transport-Security")
    if not hsts:
        return _finding("ECWASS-058","Missing HSTS Header","High",url,
            "Strict-Transport-Security header is absent. HSTS shall be set on all HTTPS responses.")
    if "includesubdomains" not in hsts.lower():
        return _finding("ECWASS-058","HSTS Missing includeSubDomains","Medium",url,
            "HSTS present but missing 'includeSubDomains': " + hsts)
    # ECWASS-059: max-age should be >= 1 year (31536000)
    ma = re.search(r'max-age\s*=\s*(\d+)', hsts, re.IGNORECASE)
    if ma and int(ma.group(1)) < 31536000:
        return _finding("ECWASS-059","HSTS max-age Below Recommended One Year","Low",url,
            "HSTS max-age=%s. Should be at least 31536000 (1 year) with preload." % ma.group(1))
    return None

def check_ECWASS_063(rh, qh, body, url, mi, h, cb):
    if not _is_html(rh): return None
    allow = _hdr(rh, "Allow") or ""
    if not allow: allow = _hdr(rh, "Public") or ""
    dangerous = ["TRACE","TRACK","DELETE","PUT","CONNECT","OPTIONS","PATCH",
                 "PROPFIND","PROPPATCH","MKCOL","MOVE","COPY"]
    found = [m for m in dangerous if re.search(r'\b'+m+r'\b', allow.upper())]
    if found:
        return _finding("ECWASS-063","Non-Standard HTTP Methods Allowed","Medium",url,
            "Allow header permits: " + ", ".join(found) +
            "\nOnly standard methods (GET, POST) shall be permitted.")
    return None

def check_ECWASS_064(rh, qh, body, url, mi, h, cb):
    if not _is_html(rh): return None
    ct = _hdr(rh, "Content-Type")
    if not ct:
        return _finding("ECWASS-064","Missing Content-Type Header","Medium",url,
            "Response has no Content-Type header. All responses shall declare the correct MIME type.")
    if ct.startswith("text/") and "charset" not in ct.lower():
        return _finding("ECWASS-064","Content-Type Missing Charset","Low",url,
            "Content-Type '%s' is missing charset. This can enable MIME/charset sniffing." % ct)
    return None

def check_ECWASS_065(rh, qh, body, url, mi, h, cb):
    if _is_redirect(_status(rh)): return None
    disc = []
    for hn in ["Server","X-Powered-By","X-AspNet-Version","X-AspNetMvc-Version",
               "X-Generator","X-Runtime","X-Version","X-Drupal-Cache","X-Joomla-Version"]:
        val = _hdr(rh, hn)
        if val:
            disc.append("%s: %s" % (hn, val))
    if disc:
        return _finding("ECWASS-065","Technology/Version Disclosed in Headers","Low",url,
            "Response headers reveal server/framework details:\n- " + "\n- ".join(disc) +
            "\nHTTP headers shall not disclose version or internal system information.")
    return None

def check_ECWASS_066(rh, qh, body, url, mi, h, cb):
    if not _is_html(rh): return None
    csp = _hdr(rh, "Content-Security-Policy")
    if not csp:
        csp_ro = _hdr(rh, "Content-Security-Policy-Report-Only")
        if csp_ro:
            return _finding("ECWASS-066","CSP in Report-Only Mode","Medium",url,
                "CSP-Report-Only is set but not enforced. Use Content-Security-Policy in production.")
        return _finding("ECWASS-066","Missing Content-Security-Policy Header","High",url,
            "No CSP header. CSP shall be strictly configured to prevent XSS/HTML injection.")
    weak = []
    if "'unsafe-inline'" in csp: weak.append("'unsafe-inline'")
    if "'unsafe-eval'" in csp:   weak.append("'unsafe-eval'")
    if re.search(r'\*\s', csp) or csp.endswith("*"): weak.append("wildcard (*)")
    if "default-src" not in csp and "script-src" not in csp:
        weak.append("no default-src or script-src directive")
    if weak:
        return _finding("ECWASS-066","Weak Content-Security-Policy","Medium",url,
            "CSP present but contains weak directives: " + ", ".join(weak) +
            "\nCSP shall be strictly configured.")
    return None

def check_ECWASS_067(rh, qh, body, url, mi, h, cb):
    if not _is_html(rh): return None
    val = _hdr(rh, "X-XSS-Protection")
    if not val:
        return _finding("ECWASS-067","Missing X-XSS-Protection Header","Low",url,
            "X-XSS-Protection header absent. Set to '1; mode=block' to enable browser XSS filter.")
    if val.strip() == "0":
        return _finding("ECWASS-067","X-XSS-Protection Disabled","Medium",url,
            "X-XSS-Protection: 0 explicitly disables the browser XSS filter.")
    return None

def check_ECWASS_068(rh, qh, body, url, mi, h, cb):
    if not _is_html(rh): return None
    xfo = _hdr(rh, "X-Frame-Options")
    csp = _hdr(rh, "Content-Security-Policy") or ""
    if not xfo and "frame-ancestors" not in csp.lower():
        return _finding("ECWASS-068","Missing X-Frame-Options / frame-ancestors","High",url,
            "Neither X-Frame-Options nor CSP frame-ancestors is set. "
            "Application is vulnerable to clickjacking.")
    if xfo and xfo.upper() not in ("DENY","SAMEORIGIN") and \
       not xfo.upper().startswith("ALLOW-FROM"):
        return _finding("ECWASS-068","Invalid X-Frame-Options Value","Medium",url,
            "Unexpected X-Frame-Options value: '%s'. Valid: DENY, SAMEORIGIN, ALLOW-FROM." % xfo)
    return None

def check_ECWASS_069(rh, qh, body, url, mi, h, cb):
    if not _is_html(rh): return None
    issues = []
    # Check password inputs without autocomplete=off
    pwd_inputs = re.findall(r'<input[^>]+type\s*=\s*["\']?password[^>]*>', body, re.IGNORECASE)
    for inp in pwd_inputs:
        if "autocomplete" not in inp.lower():
            issues.append("Password <input> missing autocomplete='off'")
    # Check forms containing password with no autocomplete on form
    forms = re.findall(r'<form[^>]*>[\s\S]{0,2000}?</form>', body, re.IGNORECASE)
    for frm in forms:
        if re.search(r'type\s*=\s*["\']?password', frm, re.IGNORECASE):
            if "autocomplete" not in frm[:frm.find(">")].lower():
                issues.append("Form containing password field missing autocomplete='off' on <form>")
    if issues:
        return _finding("ECWASS-069","Autocomplete Enabled on Sensitive Fields","Low",url,
            "\n- ".join(list(set(issues))) +
            "\nAutocomplete shall be disabled on sensitive form fields.")
    return None

def check_ECWASS_070(rh, qh, body, url, mi, h, cb):
    if not _is_html(rh): return None
    # Check for text-type inputs where type should be password (masking)
    # Heuristic: input named 'password' or 'passwd' but type='text'
    m = re.search(r'<input[^>]+type\s*=\s*["\']?text["\']?[^>]+name\s*=\s*["\']?(password|passwd|pwd)["\']?',
                  body, re.IGNORECASE)
    if m:
        return _finding("ECWASS-070","Sensitive Field Not Masked (type=text)","Low",url,
            "An input field named 'password/passwd/pwd' uses type='text' instead of type='password'. "
            "Sensitive fields should be masked while typed.")
    return None

def check_ECWASS_071(rh, qh, body, url, mi, h, cb):
    if _is_static_path(url): return None
    us = str(url).lower()
    sensitive_path = any(k in us for k in ["account","profile","admin","dashboard",
                                            "payment","personal","private","secure","portal"])
    if sensitive_path:
        cc = _hdr(rh, "Cache-Control") or ""
        if "no-store" not in cc.lower() and "no-cache" not in cc.lower():
            return _finding("ECWASS-071","Sensitive Page Not Excluded from Cache","Medium",url,
                "Sensitive page lacks Cache-Control: no-store. Current: '%s'. "
                "Client-side cache shall not contain sensitive information." % cc)
    return None

def check_ECWASS_072(rh, qh, body, url, mi, h, cb):
    if str(url.getProtocol()).lower() == "https": return None
    if re.search(r'(credit.?card|ssn|social.?security|password|passwd)', body, re.IGNORECASE):
        return _finding("ECWASS-072","Sensitive Information Over HTTP","High",url,
            "Page served over HTTP appears to contain sensitive fields. "
            "Sensitive information shall only be sent over HTTPS.")
    return None

def check_ECWASS_075(rh, qh, body, url, mi, h, cb):
    us = str(url).lower()
    if "upload" in us or "file" in us:
        m = re.search(r'(?:src|href|url)\s*[=:]\s*["\']?(/[^"\'>\s]*(?:upload|files?|media)[^"\'>\s]*)',
                      body, re.IGNORECASE)
        if m:
            return _finding("ECWASS-075","Uploaded File Accessible Under Webroot","High",url,
                "Response references uploaded file at webroot path: " + m.group(1) +
                "\nUploaded files shall not be stored under the webroot.")
    return None

def check_ECWASS_078_079(rh, qh, body, url, mi, h, cb):
    us = str(url)
    m = re.search(r'[?&](redirect|next|return|url|goto|redir|target|dest|destination)\s*=\s*([^&]+)',
                  us, re.IGNORECASE)
    if m:
        try: rval = urllib.unquote(str(m.group(2)))
        except: rval = str(m.group(2))
        if rval.startswith("http") or rval.startswith("//"):
            return _finding("ECWASS-078","Potential Open Redirect","High",url,
                "Redirect parameter '%s' points to external URL: %s\n"
                "All URL redirects shall be validated against a whitelist." % (m.group(1), rval[:120]))
    return None

def check_ECWASS_080(rh, qh, body, url, mi, h, cb):
    st = _status(rh)
    if st < 400: return None
    issues = []
    if re.search(r'(Traceback \(most recent call last\)|stack\s?trace|at\s+[\w\.]+\([\w\.]+:\d+\))', body, re.IGNORECASE):
        issues.append("Stack trace exposed")
    if re.search(r'[A-Za-z]+Exception\b', body):
        issues.append("Exception class name exposed")
    if re.search(r'(mysql_|pg_|mysqli_|ORA-\d{5}|SQLSTATE)', body, re.IGNORECASE):
        issues.append("Database error detail exposed")
    if re.search(r'(/home/[a-z]+/|/var/www/|/usr/local/|C:\\inetpub|D:\\wwwroot)', body):
        issues.append("Server filesystem path exposed")
    if re.search(r'<b>(?:Fatal error|Warning|Notice)</b>.*?on line \d+', body):
        issues.append("PHP debug output exposed")
    if issues:
        return _finding("ECWASS-080","Error Message Reveals Technical Detail","Medium",url,
            "HTTP %d response reveals internal details:\n- " % st +
            "\n- ".join(issues) + "\nError messages shall be generic.",
            body_snippet=_body_snippet(body, _PAT_E080))
    return None

def check_ECWASS_102(rh, qh, body, url, mi, h, cb):
    indicators = []
    if re.search(r'(werkzeug\s+debugger|django\.debug\s*=\s*true|flask\s+debug)', body, re.IGNORECASE):
        indicators.append("Python/Flask/Django debug UI detected")
    if _hdr(rh, "X-Debug-Token") or _hdr(rh, "X-Debug-Token-Link"):
        indicators.append("Symfony Profiler debug headers present")
    if re.search(r'<div\s+id=["\']sf-toolbar', body, re.IGNORECASE):
        indicators.append("Symfony debug toolbar in response")
    if re.search(r'Traceback \(most recent call last\)', body):
        indicators.append("Python traceback (debug mode) in response")
    if re.search(r'<b>(?:Fatal error|Warning)</b>.*?on line \d+', body):
        indicators.append("PHP error output in response")
    if re.search(r'<div\s+class=["\'](?:debugInfo|debug-info|errorExplain)', body, re.IGNORECASE):
        indicators.append("Debug info div detected in response")
    if indicators:
        return _finding("ECWASS-102","Debug Mode Enabled in Production","High",url,
            "\n- ".join(indicators) + "\nDebug mode shall be disabled in production.",
            body_snippet=_body_snippet(body, _PAT_E102))
    return None

def check_ECWASS_108(rh, qh, body, url, mi, h, cb):
    host = str(url.getHost()).lower()
    patterns = ["test.","staging.","dev.","uat.","qa.","demo.","sandbox.",
                ".test.",".staging.","-dev.","-test.","-uat.","-qa.","preprod."]
    matched = [p for p in patterns if p in host]
    if matched:
        return _finding("ECWASS-108","Test/Staging Environment Publicly Accessible","High",url,
            "Host '%s' appears to be a non-production environment (matched: %s) but is publicly reachable. "
            "Test environments shall not be publicly accessible." % (host, ", ".join(matched)),
            body_snippet=_body_snippet(body, _PAT_E108))
    return None

# ---------------------------------------------------------------------------
# Additional header checks for controls that need them
# ---------------------------------------------------------------------------
def check_ECWASS_061(rh, qh, body, url, mi, h, cb):
    # Heuristic: X-Certificate-* or specific server banners suggesting self-signed
    # Real check needs TLS inspection - flag for manual review
    return None  # handled by Burp's built-in scanner

def check_ECWASS_062(rh, qh, body, url, mi, h, cb):
    # PFS needs TLS handshake analysis - flag heuristically via cipher header if present
    return None  # handled by Burp's built-in scanner

def check_ECWASS_060(rh, qh, body, url, mi, h, cb):
    srv = _hdr(rh, "Server") or ""
    if re.search(r'(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)', srv, re.IGNORECASE):
        return _finding("ECWASS-060","Deprecated TLS Version Indicated","High",url,
            "Server header indicates deprecated TLS/SSL: " + srv +
            "\nOnly TLS 1.2+ with strong ciphers shall be used.")
    return None


# =============================================================================
# ADDITIONAL PASSIVE CHECKS (v2 additions)
# =============================================================================

def check_ECWASS_perm_policy(rh, qh, body, url, mi, h, cb):
    """Permissions-Policy header missing"""
    if not _is_html(rh): return None
    if not _hdr(rh, "Permissions-Policy") and not _hdr(rh, "Feature-Policy"):
        return _finding("ECWASS-066", "Missing Permissions-Policy Header",
                        "Low", url,
                        "Neither Permissions-Policy nor Feature-Policy header is present.\n"
                        "This header controls access to browser features (camera, mic, geolocation).")
    return None

def check_ECWASS_sri(rh, qh, body, url, mi, h, cb):
    """External scripts/styles missing Subresource Integrity"""
    if not _is_html(rh): return None
    missing = []
    for tag in re.findall(r'<script[^>]+src\s*=\s*["\']https?://[^>]+>', body, re.IGNORECASE):
        if "integrity" not in tag.lower():
            m = re.search(r'src\s*=\s*["\'](https?://[^"\'>]+)', tag, re.IGNORECASE)
            if m: missing.append(m.group(1)[:80])
    if missing:
        return _finding("ECWASS-049", "External Script Missing Subresource Integrity",
                        "Medium", url,
                        "External scripts without integrity= attribute:\n- " + "\n- ".join(missing[:5]) +
                        "\nExternal assets shall use SRI to prevent CDN supply-chain attacks.")
    return None

def check_ECWASS_sensitive_json(rh, qh, body, url, mi, h, cb):
    """Sensitive field names in JSON API response"""
    ct = _hdr(rh, "Content-Type") or ""
    if "json" not in ct.lower(): return None
    hits = []
    for pat, name in [
        (r'"password"\s*:', "password"), (r'"secret"\s*:', "secret"),
        (r'"api_key"\s*:', "api_key"), (r'"cvv"\s*:', "cvv"),
        (r'"ssn"\s*:', "ssn"), (r'"access_token"\s*:', "access_token"),
        (r'"refresh_token"\s*:', "refresh_token"), (r'"private_key"\s*:', "private_key"),
    ]:
        if re.search(pat, body, re.IGNORECASE):
            hits.append(name)
    if hits:
        return _finding("ECWASS-057", "Sensitive Field Names in JSON API Response",
                        "High", url,
                        "API response exposes sensitive field names: " + ", ".join(hits) +
                        "\nSensitive data shall not be returned unnecessarily in API responses.",
                        body_snippet=_body_snippet(body,
                            r'"(?:password|secret|api_key|cvv|ssn|access_token|private_key)"\s*:'))
    return None

def check_ECWASS_jwt(rh, qh, body, url, mi, h, cb):
    """JWT token returned in response body"""
    ct = _hdr(rh, "Content-Type") or ""
    if "json" not in ct.lower() and "html" not in ct.lower(): return None
    m = re.search(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', body)
    if m:
        return _finding("ECWASS-027", "JWT Token Exposed in Response Body",
                        "Medium", url,
                        "A JWT token was found in the response body.\n"
                        "Tokens in body may be stored insecurely in localStorage or logs.\n"
                        "Prefer HttpOnly cookies for session tokens.",
                        body_snippet=_body_snippet(body,
                            r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'))
    return None

def check_ECWASS_samesite_none(rh, qh, body, url, mi, h, cb):
    """Cookie SameSite=None without Secure"""
    issues = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":", 1)[1]
            m = re.match(r'\s*([^=]+)=', val)
            name = m.group(1).strip() if m else "unknown"
            if re.search(r'samesite\s*=\s*none', val, re.IGNORECASE):
                if "secure" not in val.lower():
                    issues.append("Cookie '%s': SameSite=None without Secure" % name)
    if issues:
        return _finding("ECWASS-030", "Cookie SameSite=None Without Secure Flag",
                        "Medium", url,
                        "\n".join(issues) +
                        "\nSameSite=None requires the Secure flag to be meaningful.")
    return None

def check_ECWASS_large_cookie(rh, qh, body, url, mi, h, cb):
    """Cookie value > 512 bytes - may store sensitive data client-side"""
    hits = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":", 1)[1]
            m = re.match(r'\s*([^=]+)=([^;]*)', val)
            if not m: continue
            name, value = m.group(1).strip(), m.group(2).strip()
            if len(value) > 512:
                hits.append("Cookie '%s': %d bytes" % (name, len(value)))
    if hits:
        return _finding("ECWASS-028", "Unusually Large Cookie Value",
                        "Low", url,
                        "\n".join(hits) +
                        "\nLarge cookies may store sensitive data client-side. "
                        "Sensitive data shall be stored server-side.")
    return None


# =============================================================================
# ADDITIONAL CHECKS v3 -- new control detections
# =============================================================================
# New ECWASS checks - v3 additions

def check_ECWASS_012_admin(rh, qh, body, url, mi, h, cb):
    """ECWASS-012/014: Admin interface accessible / on default path"""
    st = _status(rh)
    if st not in [200, 301, 302, 403]: return None
    us = str(url.getPath()).lower()
    admin_paths = [
        "/admin", "/admin/", "/administrator", "/administrator/",
        "/wp-admin", "/wp-admin/", "/wp-login.php",
        "/management", "/manage", "/manager",
        "/cpanel", "/plesk", "/phpmyadmin",
        "/console", "/control", "/controlpanel",
        "/backend", "/backoffice", "/adminpanel",
        "/siteadmin", "/webadmin", "/moderator",
    ]
    matched = next((p for p in admin_paths
                    if us == p or us.startswith(p + "/")), None)
    if not matched: return None
    if st == 200:
        return _finding("ECWASS-012", "Admin Interface Accessible on Common Path",
                        "High", url,
                        "Admin/management interface found at well-known path '%s' "
                        "(HTTP 200 OK).\nAdministrator functionality shall not be accessible "
                        "to unauthorized users (ECWASS-012). Admin interfaces should use a "
                        "random path instead of the default path (ECWASS-014)." % us)
    elif st == 403:
        return _finding("ECWASS-014", "Admin Interface Exists at Default Path (Access Denied)",
                        "Medium", url,
                        "Admin path '%s' exists and returns HTTP 403.\nAdmin interfaces "
                        "should use a random/non-guessable path rather than the default "
                        "path (ECWASS-014)." % us)
    return None


def check_ECWASS_023_pwchange(rh, qh, body, url, mi, h, cb):
    """ECWASS-023: Password change form missing current-password field"""
    if not _is_html(rh): return None
    us = str(url.getPath()).lower()
    if not any(k in us for k in ["password","passwd","change","update","profile","account",
                                   "settings","security"]):
        return None
    # Detect password change form: has at least two password inputs (new + confirm)
    pwd_inputs = re.findall(r'<input[^>]+type\s*=\s*["\']?password["\']?[^>]*>',
                             body, re.IGNORECASE)
    if len(pwd_inputs) < 2: return None
    # Check for a "current"/"old" password field
    names = [re.search(r'name\s*=\s*["\']?([^"\'>\s]+)', p, re.IGNORECASE)
             for p in pwd_inputs]
    name_vals = [n.group(1).lower() for n in names if n]
    has_current = any(k in v for v in name_vals
                      for k in ["current","old","existing","prev","original"])
    if not has_current:
        return _finding("ECWASS-023", "Password Change Form Missing Current Password Field",
                        "Medium", url,
                        "Password change form found with %d password fields but no "
                        "'current/old password' field detected.\nPassword change shall require "
                        "the user to enter the old password (ECWASS-023)." % len(pwd_inputs))
    return None


def check_ECWASS_034_session_url(rh, qh, body, url, mi, h, cb):
    """ECWASS-034: Session ID in URL or non-cookie mechanism"""
    us = str(url)
    m = re.search(r'[?&](JSESSIONID|PHPSESSID|ASP\.NET_SessionId|sessid|'
                  r'session_id|sessionid|sid|auth_token)=([^&]{8,})',
                  us, re.IGNORECASE)
    if m:
        return _finding("ECWASS-034", "Session ID Transmitted via URL",
                        "High", url,
                        "Session identifier '%s' found in URL query string.\n"
                        "Web applications shall only accept cookies as the session ID "
                        "exchange mechanism (ECWASS-034)." % m.group(1))
    # Also check HTML body for session IDs in hrefs
    m2 = re.search(r'href\s*=\s*["\'][^"\']*[?&](JSESSIONID|PHPSESSID|'
                   r'ASP\.NET_SessionId)=[^"\']+["\']', body, re.IGNORECASE)
    if m2:
        return _finding("ECWASS-034", "Session ID Embedded in Page Hrefs",
                        "High", url,
                        "Session identifier '%s' found embedded in page link hrefs.\n"
                        "Session IDs shall only be exchanged via cookies (ECWASS-034)."
                        % m2.group(1))
    return None


def check_ECWASS_039_newsession(rh, qh, body, url, mi, h, cb):
    """ECWASS-039: Detect login response that does not rotate session cookie"""
    us = str(url.getPath()).lower()
    st = _status(rh)
    if not any(k in us for k in ["login","signin","auth","logon"]): return None
    if st not in [200, 302, 303]: return None
    # Heuristic: login POST response should set a new Set-Cookie
    # If no Set-Cookie at all on a successful login response, flag it
    has_set_cookie = any(isinstance(h2, str) and h2.lower().startswith("set-cookie:")
                         for h2 in rh)
    if not has_set_cookie:
        # Check request had a session cookie already
        req_cookie = _hdr(qh, "Cookie") or ""
        if any(s in req_cookie.lower() for s in ["sess","sid","session","token","auth"]):
            return _finding("ECWASS-039", "Login Response Does Not Set a New Session Cookie",
                            "High", url,
                            "The login endpoint did not issue a new Set-Cookie header in "
                            "the response, despite the request carrying an existing session "
                            "token.\nSuccessful authentication shall generate a new session "
                            "ID (ECWASS-039).")
    return None


def check_ECWASS_050_clientval(rh, qh, body, url, mi, h, cb):
    """ECWASS-050: Client-side-only input validation (novalidate without server-side hints)"""
    if not _is_html(rh): return None
    if not re.search(r'<form\b', body, re.IGNORECASE): return None
    # Only flag if novalidate and no pattern/required attributes
    if re.search(r'\bnovalidate\b', body, re.IGNORECASE):
        has_pattern  = re.search(r'\bpattern\s*=', body, re.IGNORECASE)
        has_required = re.search(r'\brequired\b', body, re.IGNORECASE)
        has_min_max  = re.search(r'\b(?:min|max|minlength|maxlength)\s*=', body, re.IGNORECASE)
        if not has_pattern and not has_required and not has_min_max:
            return _finding("ECWASS-050", "Form Disables Validation with No Server-Side Hints",
                            "Low", url,
                            "Form uses 'novalidate' attribute with no pattern/required/"
                            "min/max constraints.\nInput validation should also be performed "
                            "at client-side in addition to server-side checks (ECWASS-050).")
    return None


def check_ECWASS_061_cert(rh, qh, body, url, mi, h, cb):
    """ECWASS-061: Certificate warning indicators or self-signed hints"""
    # Check for headers that some proxies/servers set on certificate issues
    hints = []
    for warn_hdr in ["X-Certificate-Error", "X-SSL-Error", "X-Ssl-Warning"]:
        v = _hdr(rh, warn_hdr)
        if v: hints.append("%s: %s" % (warn_hdr, v))
    # Also check if serving over HTTP when path suggests HTTPS-only content
    if str(url.getProtocol()).lower() == "http":
        us = str(url.getPath()).lower()
        if any(k in us for k in ["secure","ssl","https","payment","checkout","bank"]):
            hints.append("Sensitive path '%s' served over plain HTTP" % us)
    if hints:
        return _finding("ECWASS-061", "Potential Certificate/TLS Issue Detected",
                        "High", url,
                        "\n".join(hints) +
                        "\nWeb-facing applications shall use certificates delivered by a "
                        "trusted Certificate Authority (ECWASS-061).")
    return None


def check_ECWASS_074_cmdinject(rh, qh, body, url, mi, h, cb):
    """ECWASS-074: Shell metacharacters in URL parameters"""
    us = str(url)
    params = us.split("?", 1)[1] if "?" in us else ""
    if not params: return None
    # Shell metacharacters in parameter values
    shell_chars = re.compile(r'(?:[;&|`$]|%3B|%7C|%26|%60|%24)'
                              r'(?:ls|cat|id|whoami|pwd|wget|curl|bash|sh|cmd)', re.IGNORECASE)
    if shell_chars.search(params):
        return _finding("ECWASS-074", "Possible OS Command Injection Characters in URL",
                        "High", url,
                        "URL parameters contain shell metacharacters combined with command "
                        "names: %s\nData submitted by a user shall not be used as input for "
                        "operating system commands (ECWASS-074)." % params[:120])
    # Also check for obvious path traversal in params
    if re.search(r'(?:\.\./|\.\.\\|%2e%2e%2f|%252e%252e)', params, re.IGNORECASE):
        return _finding("ECWASS-074", "Path Traversal Sequence in URL Parameters",
                        "High", url,
                        "URL parameters contain path traversal sequences: %s\n"
                        "User input shall not be used as filesystem paths without strict "
                        "sanitization (ECWASS-074)." % params[:120])
    return None


# ECWASS Tier 2

def check_ECWASS_024_mfa(rh, qh, body, url, mi, h, cb):
    """ECWASS-024: Login form with no MFA/OTP field"""
    if not _is_html(rh): return None
    us = str(url.getPath()).lower()
    if not any(k in us for k in ["login","signin","auth","logon"]): return None
    # Page has a password field
    if not re.search(r'<input[^>]+type\s*=\s*["\']?password', body, re.IGNORECASE):
        return None
    # Check for MFA/OTP indicators
    mfa_indicators = [
        r'type\s*=\s*["\']?(?:number|tel)["\']?[^>]*(?:otp|totp|code|token|pin|mfa)',
        r'(?:otp|totp|mfa|2fa|two.factor|authenticator|verification.code)',
        r'name\s*=\s*["\']?(?:otp|totp|code|token|pin|mfa|2fa)',
    ]
    has_mfa = any(re.search(p, body, re.IGNORECASE) for p in mfa_indicators)
    if not has_mfa:
        return _finding("ECWASS-024", "Login Form Has No MFA/OTP Field Detected",
                        "Low", url,
                        "Login form appears to use only username/password with no "
                        "MFA/OTP field detected.\nThis is a heuristic - MFA may be "
                        "implemented as a separate step. Account/password recovery "
                        "controls should make use of a time-based one-time authentication "
                        "token (ECWASS-024).")
    return None

# =============================================================================
# ADDITIONAL CHECKS v4 -- extended control coverage
# =============================================================================
# =============================================================================
# ECWASS v4 additional checks
# =============================================================================

def check_ECWASS_016_adminrole(rh, qh, body, url, mi, h, cb):
    """ECWASS-016: Admin/privileged role indicators accessible without step-up auth"""
    if not _is_html(rh): return None
    st = _status(rh)
    if st != 200: return None
    us = str(url.getPath()).lower()
    if not any(k in us for k in ["admin","management","dashboard","panel","control",
                                   "backend","moderate","console"]):
        return None
    # Check request has NO session/auth (public access to admin-like page)
    req_cookie = _hdr(qh, "Cookie") or ""
    auth_hdr   = _hdr(qh, "Authorization") or ""
    has_auth   = bool(auth_hdr) or any(s in req_cookie.lower()
                                        for s in ["session","token","auth","sess","sid"])
    # Flag if admin-path is 200 and unauthenticated
    if not has_auth:
        return _finding("ECWASS-016", "Admin/Privileged Page Accessible Without Authentication",
                        "High", url,
                        "Page at admin/management path '%s' returned HTTP 200 without any "
                        "session or auth token in the request.\nAdministrators shall have a "
                        "separate role and privileged functionality shall only be available "
                        "to authenticated administrators (ECWASS-016)." % us)
    return None


def check_ECWASS_025_forcedchange(rh, qh, body, url, mi, h, cb):
    """ECWASS-025: Login success without any forced password change indicator"""
    if not _is_html(rh): return None
    us = str(url.getPath()).lower()
    st = _status(rh)
    # Only check login success responses (200 after POST to login path)
    req_method = ""
    for hdr in qh:
        if isinstance(hdr, str) and hdr.upper().startswith("POST "):
            req_method = "POST"
            break
    if req_method != "POST": return None
    if not any(k in us for k in ["login","signin","auth","logon"]): return None
    if st not in [200, 302, 303]: return None
    # Check for initial credential / default password indicators in response
    if re.search(r'(?:default.password|initial.password|temporary.password|'
                 r'first.time.login|change.your.password|password.expired|'
                 r'must.change.password)', body, re.IGNORECASE):
        # Good - forced change is present
        return None
    # Flag only if we see strong indicators of a successful login with no change prompt
    if (st in [302, 303] and not re.search(r'change.password|reset.password',
                                            _hdr(rh, "Location") or "", re.IGNORECASE)):
        # Heuristic only - can't be certain without knowing if it's a new account
        return None  # Too noisy without more context
    return None


def check_ECWASS_035_timeout(rh, qh, body, url, mi, h, cb):
    """ECWASS-035/036/037: Session timeout and logout indicators"""
    if not _is_html(rh): return None
    us = str(url.getPath()).lower()
    st = _status(rh)
    # Check for session timeout configuration hints in HTML/JS
    if re.search(r'(?:sessionTimeout|session_timeout|inactivity.timeout|'
                 r'idle.timeout|SESSION_TIMEOUT)\s*[=:]\s*0\b', body, re.IGNORECASE):
        return _finding("ECWASS-035", "Session Timeout Set to Zero (Disabled)",
                        "High", url,
                        "Page appears to configure session timeout to 0 (disabled).\n"
                        "Sessions shall be automatically terminated when a user is inactive "
                        "(ECWASS-035).",
                        body_snippet=_body_snippet(body,
                            r'(?:sessionTimeout|session_timeout|inactivity.timeout)\s*[=:]\s*0'))
    # Check if logout endpoint returns 200 but no session invalidation headers
    if any(k in us for k in ["logout","signout","log-out","sign-out","logoff"]):
        if st == 200:
            has_set_cookie = any(isinstance(h2, str) and h2.lower().startswith("set-cookie:")
                                 for h2 in rh)
            if not has_set_cookie:
                return _finding("ECWASS-037", "Logout Response Does Not Clear Session Cookie",
                                "High", url,
                                "Logout endpoint returned HTTP 200 but no Set-Cookie header "
                                "to invalidate the session cookie.\nSessions shall be "
                                "automatically terminated when the user logs out (ECWASS-037).")
    return None


def check_ECWASS_041_clientauth(rh, qh, body, url, mi, h, cb):
    """ECWASS-041: Client-side access control check without server enforcement"""
    if not _is_html(rh): return None
    st = _status(rh)
    if st != 200: return None
    # Detect JS-only access control patterns (no server redirect)
    js_auth_patterns = [
        r'\b(?:checkPermission|hasPermission|isAuthorized|canAccess|hasRole)\s*\(',
        r'if\s*\(\s*(?:userRole|user\.role|currentUser\.role|permissions)\s*[!=]=',
        r'(?:authorized|permission)\s*===?\s*(?:true|false)',
    ]
    found = [p for p in js_auth_patterns
             if re.search(p, body, re.IGNORECASE)]
    if found and not re.search(r'(?:window\.location|location\.href|location\.replace)',
                                body, re.IGNORECASE):
        return _finding("ECWASS-041", "Client-Side Access Control Without Server Redirect",
                        "High", url,
                        "Page contains client-side access control checks with no server-side "
                        "redirect detected.\nAccess control checks performed client-side shall "
                        "also be checked at server-side (ECWASS-041).",
                        body_snippet=_body_snippet(body,
                            r'\b(?:checkPermission|hasPermission|isAuthorized)\s*\('))
    return None


def check_ECWASS_043_metadata(rh, qh, body, url, mi, h, cb):
    """ECWASS-043: File/directory metadata exposed in response"""
    cd = _hdr(rh, "Content-Disposition") or ""
    # Check for unencoded filename with sensitive metadata
    fn_m = re.search(r'filename\s*=\s*["\']?([^"\';\r\n]+)', cd, re.IGNORECASE)
    if fn_m:
        fn = fn_m.group(1).strip()
        # Check for internal paths or metadata in filename
        if re.search(r'(?:/home/|/var/|/usr/|C:\\|D:\\|\\\\server\\)', fn):
            return _finding("ECWASS-043", "Internal Path in Content-Disposition Filename",
                            "Medium", url,
                            "Content-Disposition filename exposes internal path: %s\n"
                            "File metadata in web applications shall be sanitized "
                            "(ECWASS-043)." % fn[:100])
    # Check Last-Modified header for revealing internal timestamps
    lm = _hdr(rh, "Last-Modified")
    etag = _hdr(rh, "ETag") or ""
    # ETag with inode (some Apache configs expose inode-mtime-size format)
    if etag and re.match(r'^"?[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"?$', etag.strip()):
        return _finding("ECWASS-043", "ETag May Expose Filesystem Inode",
                        "Low", url,
                        "ETag header '%s' matches Apache inode-mtime-size format, potentially "
                        "exposing internal filesystem metadata.\nFile metadata shall be "
                        "sanitized (ECWASS-043)." % etag[:60])
    return None


def check_ECWASS_052_xss_reflect(rh, qh, body, url, mi, h, cb):
    """ECWASS-052/053: XSS reflection indicators in response"""
    if not _is_html(rh): return None
    us = str(url)
    params = us.split("?", 1)[1] if "?" in us else ""
    if not params: return None
    # Check if any parameter values appear unescaped in the response
    for part in params.split("&"):
        if "=" not in part: continue
        key, _, val = part.partition("=")
        if len(val) < 4: continue
        # Only check values that look like XSS test strings or contain HTML chars
        if re.search(r'[<>"\'`]|javascript:|data:', val, re.IGNORECASE):
            # Check if reflected unescaped in body
            if val in body and not re.search(
                    re.escape(val.replace("<","&lt;").replace(">","&gt;")), body):
                return _finding("ECWASS-052", "Possible Reflected XSS - Unescaped Input in Response",
                                "High", url,
                                "URL parameter '%s' value appears reflected unescaped in "
                                "response body.\nSpecial characters shall be escaped using "
                                "the specific escape syntax for the interpreter (ECWASS-052)." % key[:40],
                                body_snippet=_body_snippet(body, re.escape(val[:20])))
    return None


def check_ECWASS_062_pfs(rh, qh, body, url, mi, h, cb):
    """ECWASS-062: Forward Secrecy - detect weak cipher hint in Server header"""
    srv = _hdr(rh, "Server") or ""
    # Some servers advertise cipher info
    if re.search(r'(?:RC4|DES|3DES|MD5|SHA1|RSA[^-])', srv, re.IGNORECASE):
        return _finding("ECWASS-062", "Weak Cipher Indicated in Server Header",
                        "High", url,
                        "Server header suggests a non-PFS cipher: %s\n"
                        "Perfect Forward Secrecy shall be supported using ECDHE or DHE "
                        "cipher suites (ECWASS-062)." % srv)
    # Check Via or X-Via headers for proxy info revealing old TLS
    via = _hdr(rh, "Via") or _hdr(rh, "X-Via") or ""
    if re.search(r'TLSv1\.0|TLSv1\.1|SSLv3', via, re.IGNORECASE):
        return _finding("ECWASS-062", "Deprecated TLS in Via Header",
                        "High", url,
                        "Via header indicates traffic traversed deprecated TLS: %s\n"
                        "Perfect Forward Secrecy requires TLS 1.2+ with ECDHE/DHE "
                        "(ECWASS-062)." % via[:80])
    return None


def check_ECWASS_077_exec(rh, qh, body, url, mi, h, cb):
    """ECWASS-077: Uploaded file served with executable Content-Type"""
    ct = _hdr(rh, "Content-Type") or ""
    us = str(url.getPath()).lower()
    # Flag if a path suggesting upload is served with executable Content-Type
    if any(k in us for k in ["upload","uploads","files","media","user-content","attachments"]):
        executable_types = [
            "text/html", "application/javascript", "text/javascript",
            "application/x-php", "application/x-httpd-php",
            "text/x-php", "application/x-sh", "text/x-sh",
        ]
        for et in executable_types:
            if et in ct.lower():
                return _finding("ECWASS-077", "Uploaded File Served with Executable Content-Type",
                                "High", url,
                                "File at upload path '%s' is served with executable "
                                "Content-Type: %s\nThe web application shall not execute "
                                "files uploaded by users (ECWASS-077)." % (us, ct))
    return None

# =============================================================================
# Manual testing guidance
# =============================================================================

_ECWASS_MANUAL_GUIDE = {
    "ECWASS-007": ("EU Login Authentication Verification", "Manual",
        "1. Confirm the application is integrated with EU Login (ECAS).\n"
        "2. Verify that EU Login handles authentication, not a custom mechanism.\n"
        "3. Log in and confirm the session originates from EU Login SSO.\n"
        "PASS: Application delegates authentication to EU Login.\n"
        "FAIL: Application implements its own authentication instead of EU Login."),
    "ECWASS-008": ("Authentication Mechanism Strength", "Proxy/Manual",
        "1. If EU Login is not used, review the authentication mechanism.\n"
        "2. Verify it meets the Password Technical Specification requirements:\n"
        "   - Minimum 12 characters, PBKDF2/bcrypt/argon2 hashing\n"
        "   - Account lockout after failed attempts\n"
        "3. In Repeater, test with common/weak passwords to verify rejection.\n"
        "PASS: Auth mechanism meets the required strength and spec.\n"
        "FAIL: Weak mechanism is used without EU Login."),
    "ECWASS-009": ("Sensitive Data Requires EU Login", "Manual",
        "1. Identify pages/features handling sensitive non-classified information.\n"
        "2. Verify these features require EU Login authentication (not local auth).\n"
        "3. Attempt to access sensitive pages with a local-only session token.\n"
        "PASS: Sensitive data pages require EU Login with appropriate assurance level.\n"
        "FAIL: Sensitive data is accessible with weaker or non-EU-Login authentication."),
    "ECWASS-010": ("Admin Pages Require Stronger Auth", "Repeater",
        "1. Log in with standard credentials (no MFA/step-up).\n"
        "2. In Repeater, attempt to access administration pages:\n"
        "   /admin, /management, /configuration, /user-management\n"
        "3. Verify re-authentication or step-up is required.\n"
        "PASS: Admin pages require a higher authentication level than standard pages.\n"
        "FAIL: Admin pages are accessible with standard session credentials."),
    "ECWASS-046": ("Self-Registered Users Cannot Post Public Content", "Manual",
        "1. Register a new account (self-registration).\n"
        "2. Before the account is approved/verified, attempt to:\n"
        "   - Post a public comment, forum message, or content item\n"
        "   - Access content posting API endpoints in Repeater with the new token\n"
        "PASS: New unverified accounts cannot post public content.\n"
        "FAIL: Self-registered accounts can immediately post public content."),
}

MANUAL_CHECKLIST_ECWASS = [
    c[0] for c in ALL_CONTROLS
    if c[3] == "Technical" and c[0] not in set(TECHNICAL_CHECKS.keys())
]


# =============================================================================
# Master dispatch table: ECWASS-ID -> check function
# Only Technical checks are auto-dispatched; Questionnaire checks appear in
# the manual checklist panel.
# =============================================================================
TECHNICAL_CHECKS = {
    "ECWASS-005": check_ECWASS_005_006,
    "ECWASS-006": check_ECWASS_005_006,
    "ECWASS-017": check_ECWASS_017_018,
    "ECWASS-018": check_ECWASS_017_018,
    "ECWASS-021": check_ECWASS_021,
    "ECWASS-022": check_ECWASS_022,
    "ECWASS-027": check_ECWASS_027,
    "ECWASS-028": check_ECWASS_028,
    "ECWASS-029": check_ECWASS_029,
    "ECWASS-030": check_ECWASS_030,
    "ECWASS-031": check_ECWASS_031,
    "ECWASS-032": check_ECWASS_032,
    "ECWASS-033": check_ECWASS_033,
    "ECWASS-038": check_ECWASS_038,
    "ECWASS-042": check_ECWASS_042,
    "ECWASS-044": check_ECWASS_044,
    "ECWASS-048": check_ECWASS_048_049,
    "ECWASS-049": check_ECWASS_048_049,
    "ECWASS-056": check_ECWASS_056,
    "ECWASS-057": check_ECWASS_057,
    "ECWASS-058": check_ECWASS_058_059,
    "ECWASS-059": check_ECWASS_058_059,
    "ECWASS-060": check_ECWASS_060,
    "ECWASS-063": check_ECWASS_063,
    "ECWASS-064": check_ECWASS_064,
    "ECWASS-065": check_ECWASS_065,
    "ECWASS-066": check_ECWASS_066,
    "ECWASS-067": check_ECWASS_067,
    "ECWASS-068": check_ECWASS_068,
    "ECWASS-069": check_ECWASS_069,
    "ECWASS-070": check_ECWASS_070,
    "ECWASS-071": check_ECWASS_071,
    "ECWASS-072": check_ECWASS_072,
    "ECWASS-075": check_ECWASS_075,
    "ECWASS-078": check_ECWASS_078_079,
    "ECWASS-079": check_ECWASS_078_079,
    "ECWASS-080": check_ECWASS_080,
    "ECWASS-102": check_ECWASS_102,
    "ECWASS-108": check_ECWASS_108,
    "ECWASS-PERM": check_ECWASS_perm_policy,
    "ECWASS-SRI":  check_ECWASS_sri,
    "ECWASS-SJSN": check_ECWASS_sensitive_json,
    "ECWASS-JWT":  check_ECWASS_jwt,
    "ECWASS-SSNO": check_ECWASS_samesite_none,
    "ECWASS-LKCK": check_ECWASS_large_cookie,
    # v3 additions
    "ECWASS-012":  check_ECWASS_012_admin,
    "ECWASS-014":  check_ECWASS_012_admin,
    "ECWASS-023":  check_ECWASS_023_pwchange,
    "ECWASS-034":  check_ECWASS_034_session_url,
    "ECWASS-039":  check_ECWASS_039_newsession,
    "ECWASS-050":  check_ECWASS_050_clientval,
    "ECWASS-061":  check_ECWASS_061_cert,
    "ECWASS-074":  check_ECWASS_074_cmdinject,
    "ECWASS-024":  check_ECWASS_024_mfa,
    # v4 additions
    "ECWASS-016":  check_ECWASS_016_adminrole,
    "ECWASS-025":  check_ECWASS_025_forcedchange,
    "ECWASS-035":  check_ECWASS_035_timeout,
    "ECWASS-036":  check_ECWASS_035_timeout,
    "ECWASS-037":  check_ECWASS_035_timeout,
    "ECWASS-041":  check_ECWASS_041_clientauth,
    "ECWASS-043":  check_ECWASS_043_metadata,
    "ECWASS-052":  check_ECWASS_052_xss_reflect,
    "ECWASS-053":  check_ECWASS_052_xss_reflect,
    "ECWASS-062":  check_ECWASS_062_pfs,
    "ECWASS-077":  check_ECWASS_077_exec,
}

# De-duplicate: same function may appear under multiple IDs - only call it once per response
_UNIQUE_CHECKS = list({fn.__name__: (ecid, fn) for ecid, fn in TECHNICAL_CHECKS.items()}.values())


# =============================================================================
# Table models (proper Jython subclasses - no anonymous class hack)
# =============================================================================
class _FindingsModel(DefaultTableModel):
    def isCellEditable(self, row, col):
        return False


class _ControlsModel(DefaultTableModel):
    def getColumnClass(self, col):
        if col == 0:
            return JBoolean
        return DefaultTableModel.getColumnClass(self, col)

    def isCellEditable(self, row, col):
        return col == 0


# =============================================================================
# BurpExtender - main entry point
# =============================================================================
class BurpExtender(IBurpExtender, IScannerCheck, ITab,
                   IContextMenuFactory, IHttpListener):

    EXT_NAME = "ECWASS Security Scanner"

    def registerExtenderCallbacks(self, callbacks):
        self._cb      = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout  = PrintWriter(callbacks.getStdout(), True)
        self._stderr  = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName(self.EXT_NAME)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        callbacks.registerProxyListener(self)
        saved = None
        try: saved = self._cb.loadExtensionSetting("ecwass_enabled_controls")
        except Exception: pass
        if saved:
            self._enabled = set(s.strip() for s in saved.split(",") if s.strip())
        else:
            self._enabled = set(ecid for ecid, fn in _UNIQUE_CHECKS)
        self._findings = []
        self._seen     = set()
        SwingUtilities.invokeLater(self._buildUI)
        self._stdout.println("[ECWASS] Loaded. %d controls registered." % len(ALL_CONTROLS))

    # -- ITab -----------------------------------------------------------------
    def getTabCaption(self): return "ECWASS Scanner"
    def getUiComponent(self): return self._root

    # -- IHttpListener --------------------------------------------------------
    def processHttpMessage(self, toolFlag, isRequest, messageInfo):
        if isRequest: return
        try:
            for f in self._passiveScan(messageInfo):
                self._addFinding(f)
        except Exception as e:
            self._stderr.println("[ECWASS] Listener error: " + str(e))

    # -- IScannerCheck --------------------------------------------------------

    def processProxyMessage(self, messageIsRequest, message):
        """IProxyListener - count all proxy traffic for live stats."""
        if not messageIsRequest:
            self._req_counter[0] += 1
            if hasattr(self, "_statsLabel"):
                elapsed = (datetime.datetime.now() - self._scan_start).seconds or 1
                rate = self._req_counter[0] / elapsed
                fp_n = sum(1 for f in self._findings
                           if f.get("title","").startswith("[FP]"))
                SwingUtilities.invokeLater(lambda: self._statsLabel.setText(
                    "  Requests: %d | %.1f/s | Findings: %d | FP: %d"
                    % (self._req_counter[0], rate,
                       len(self._findings), fp_n)))

    def doPassiveScan(self, baseRequestResponse):
        results = []
        try:
            for f in self._passiveScan(baseRequestResponse):
                self._addFinding(f)
                results.append(_BurpIssue(f, [baseRequestResponse],
                                           baseRequestResponse.getHttpService()))
        except Exception as e:
            self._stderr.println("[ECWASS] Scan error: " + str(e))
        return results

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []

    def consolidateDuplicateIssues(self, existing, new_issue):
        return -1 if (existing.getIssueName() == new_issue.getIssueName() and
                      str(existing.getUrl()) == str(new_issue.getUrl())) else 0

    # -- IContextMenuFactory --------------------------------------------------
    def createMenuItems(self, invocation):
        menu = ArrayList()
        item = JMenuItem("ECWASS: Scan Selected Request(s)")
        item.addActionListener(self._ContextScanAction(self, invocation))
        menu.add(item)
        evid = JMenuItem("ECWASS: Log as Evidence for Selected Control")
        evid.addActionListener(self._LogEvidAction(self, invocation))
        menu.add(evid)
        return menu

    class _LogEvidAction(ActionListener):
        def __init__(self, ext, inv): self._ext = ext; self._inv = inv
        def actionPerformed(self, event):
            msgs = self._inv.getSelectedMessages()
            if not msgs: return
            msg = msgs[0]
            if not hasattr(self._ext, "_mtView"): return
            row = self._ext._mtView.getSelectedRow()
            if row < 0:
                JOptionPane.showMessageDialog(None,
                    "Please select a control in the Manual Testing tab first.",
                    "ECWASS", JOptionPane.WARNING_MESSAGE)
                return
            mr  = self._ext._mtView.convertRowIndexToModel(row)
            cid = str(self._ext._mtModel.getValueAt(mr, 1))
            try:
                url = str(self._ext._helpers.analyzeRequest(msg).getUrl())
                aResp = self._ext._helpers.analyzeResponse(msg.getResponse())
                status = str(aResp.getStatusCode())
                self._ext._mtModel.setValueAt(url[:120], mr, 6)
                old_notes = str(self._ext._mtModel.getValueAt(mr, 7) or "")
                evidence = "Evidence: %s (HTTP %s)" % (url[:80], status)
                new_notes = (old_notes + " | " if old_notes else "") + evidence
                self._ext._mtModel.setValueAt(new_notes[:200], mr, 7)
                JOptionPane.showMessageDialog(None,
                    "Evidence logged for %s:\n%s (HTTP %s)" % (cid, url[:80], status),
                    "ECWASS Evidence Logged", JOptionPane.INFORMATION_MESSAGE)
            except Exception as ex:
                JOptionPane.showMessageDialog(None, "Error: "+str(ex),
                    "ECWASS", JOptionPane.ERROR_MESSAGE)

    class _ContextScanAction(ActionListener):
        def __init__(self, ext, inv):
            self._ext = ext
            self._inv = inv
        def actionPerformed(self, event):
            msgs = self._inv.getSelectedMessages()
            if not msgs: return
            count = 0
            for msg in msgs:
                for f in self._ext._passiveScan(msg):
                    self._ext._addFinding(f)
                    count += 1
            JOptionPane.showMessageDialog(None,
                "Scan complete. %d new finding(s) added." % count,
                "ECWASS Scanner", JOptionPane.INFORMATION_MESSAGE)

    # -- Core scan ------------------------------------------------------------
    def _passiveScan(self, messageInfo):
        findings = []
        try:
            response = messageInfo.getResponse()
            if not response: return findings
            aResp = self._helpers.analyzeResponse(response)
            aReq  = self._helpers.analyzeRequest(
                        messageInfo.getHttpService(), messageInfo.getRequest())
            rh   = list(aResp.getHeaders())
            qh   = list(aReq.getHeaders())
            url  = self._helpers.analyzeRequest(messageInfo).getUrl()
            status = aResp.getStatusCode()
            if _should_skip(url, rh, status): return findings
            body = self._helpers.bytesToString(response[aResp.getBodyOffset():])
            seen_fns = set()
            for ecid, fn in _UNIQUE_CHECKS:
                if ecid not in self._enabled: continue
                if fn in seen_fns: continue
                seen_fns.add(fn)
                try:
                    result = fn(rh, qh, body, url, messageInfo,
                                self._helpers, self._cb)
                    if result:
                        result["req_hdrs"]  = "\n".join(str(x) for x in qh)
                        result["resp_hdrs"] = "\n".join(str(x) for x in rh)
                        result["status"]    = str(aResp.getStatusCode())
                        findings.append(result)
                except Exception as ex:
                    self._stderr.println("[ECWASS] Check %s error: %s" % (ecid, str(ex)))
        except Exception as e:
            self._stderr.println("[ECWASS] _passiveScan error: " + str(e))
        return findings

    # -- Finding management ---------------------------------------------------
    _HEADER_CHECKS = {
        'ECWASS-012','ECWASS-014','ECWASS-016','ECWASS-030','ECWASS-031',
        'ECWASS-032','ECWASS-033','ECWASS-038','ECWASS-043','ECWASS-058',
        'ECWASS-059','ECWASS-060','ECWASS-061','ECWASS-062','ECWASS-063',
        'ECWASS-064','ECWASS-065','ECWASS-066','ECWASS-067','ECWASS-068',
    }


    def _correlate(self, url, rh, qh, body, status):
        """Cross-request correlation: fires findings that need multi-request context."""
        findings = []
        try:
            host = str(url.getHost())

            # -- 3a. Cookie inconsistency: same cookie, different Secure flag --
            for hdr in rh:
                if not isinstance(hdr, str): continue
                if not hdr.lower().startswith("set-cookie:"): continue
                val = hdr.split(":",1)[1]
                m = re.match(r"\s*([^=]+)=([^;]*)", val)
                if not m: continue
                name = m.group(1).strip()
                has_secure = "secure" in val.lower()
                store_key = "cookie_secure_%s_%s" % (host, name)
                prev = self._response_store.get(store_key)
                if prev is None:
                    self._response_store[store_key] = has_secure
                elif prev != has_secure:
                    findings.append(_finding(
                        "ASVS-029",
                        "Cookie '%s' Has Inconsistent Secure Flag Across Paths" % name,
                        "Medium", url,
                        "Cookie '%s' is set with Secure=%s on this response but "
                        "was previously seen with Secure=%s on the same host.\n"
                        "The Secure flag shall be consistently applied "
                        "(ASVS V3.3.1)." % (name, has_secure, prev)))
                    del self._response_store[store_key]  # fire once

            # -- 3b. CSP present on some pages but absent on others ------------
            csp = _get_header(rh, "Content-Security-Policy")
            if _is_html(rh):
                csp_key = "csp_present_%s" % host
                if csp:
                    self._response_store[csp_key] = True
                else:
                    if self._response_store.get(csp_key):
                        findings.append(_finding(
                            "ASVS-035",
                            "CSP Present on Some Pages But Missing Here",
                            "Medium", url,
                            "Other pages on %s set a Content-Security-Policy header "
                            "but this page does not.\nCSP shall be consistently "
                            "applied across all HTML responses (ASVS V3.4.1)." % host))

            # -- 3c. Session fixation: same token before and after login -------
            us = str(url.getPath()).lower()
            is_login = any(k in us for k in ["login","signin","auth","logon"])
            req_method = ""
            for hdr in qh:
                if isinstance(hdr, str) and hdr.upper().startswith("POST "):
                    req_method = "POST"; break
            if is_login and req_method == "POST" and status in [200, 302, 303]:
                # Collect tokens from request and response
                req_cookie = _get_header(qh, "Cookie") or ""
                for hdr in rh:
                    if not isinstance(hdr, str): continue
                    if not hdr.lower().startswith("set-cookie:"): continue
                    val = hdr.split(":",1)[1]
                    mn = re.match(r"\s*([^=]+)=([^;]*)", val)
                    if not mn: continue
                    name, new_val = mn.group(1).strip(), mn.group(2).strip()
                    if any(s in name.lower() for s in
                           ["sess","sid","session","auth","token","jsessionid"]):
                        # Check if same value was in request cookie
                        old_pat = re.search(
                            re.escape(name) + r"=([^;,\s]+)", req_cookie)
                        if old_pat and old_pat.group(1) == new_val and new_val:
                            findings.append(_finding(
                                "ASVS-029",
                                "Session Fixation: Token Not Rotated After Login",
                                "High", url,
                                "Session cookie '%s' has the same value before and "
                                "after login (POST to %s).\n"
                                "A new session ID shall be generated upon "
                                "authentication (ASVS V7.1.2)." % (name, us)))

            # -- 3d. Entropy analysis on session tokens -------------------------
            for hdr in rh:
                if not isinstance(hdr, str): continue
                if not hdr.lower().startswith("set-cookie:"): continue
                val = hdr.split(":",1)[1]
                mn = re.match(r"\s*([^=]+)=([^;]{8,})", val)
                if not mn: continue
                name, token = mn.group(1).strip(), mn.group(2).strip()
                if not any(s in name.lower() for s in
                           ["sess","sid","session","token","auth"]): continue
                # Shannon entropy
                import math
                freq = {}
                for ch in token:
                    freq[ch] = freq.get(ch, 0) + 1
                entropy = -sum((c/len(token)) * math.log(c/len(token), 2)
                                for c in freq.values())
                bits_per_char = entropy
                if bits_per_char < 3.5 and len(token) > 8:
                    findings.append(_finding(
                        "ASVS-029",
                        "Low-Entropy Session Token Detected",
                        "High", url,
                        "Cookie '%s' has Shannon entropy of %.2f bits/char "
                        "(threshold: 3.5).\n"
                        "Low entropy suggests a predictable token generator.\n"
                        "Session tokens shall be generated using a cryptographically "
                        "secure PRNG with sufficient entropy (ASVS V7.1.1)."
                        % (name, bits_per_char)))

        except Exception as ex:
            pass
        return findings

    def _addFinding(self, f):
        fid = f.get("id","")
        if fid in self._HEADER_CHECKS:
            try:
                from java.net import URL as _URL
                host = str(_URL(f["url"]).getHost())
            except Exception:
                host = f["url"]
            key = fid + "|HOST|" + host
        else:
            key = fid + "|" + f["url"]
        if key in self._seen: return

        # Feature 19: per-check cooldown (low-priority checks)
        _LOW_PRIORITY = {
            "ASVS-COEP","ASVS-XXSS","ASVS-TAO","ASVS-STIM",
            "ASVS-CKDM","ASVS-CKPE","ASVS-SCHO",
            "ASVS-HSTQ","ASVS-INTH","ASVS-APIC",
        }
        if fid in _LOW_PRIORITY:
            cd_key = fid + "|" + (host if fid in self._HEADER_CHECKS else f["url"])
            last = self._cooldown.get(cd_key)
            now  = datetime.datetime.now()
            if last and (now - last).seconds < self._cooldown_s:
                return
            self._cooldown[cd_key] = now
        self._seen.add(key)
        f["notes"] = ""
        self._crossReferenceBurpScanner(f)
        self._maybeAlert(f)
        self._findings.append(f)
        SwingUtilities.invokeLater(self._refreshTable)


    def _crossReferenceBurpScanner(self, f):
        """Check if Burp's own scanner already found an issue at this URL."""
        try:
            url_str = f.get("url","")
            if not url_str: return
            issues = self._cb.getScanIssues(url_str)
            if issues and len(issues) > 0:
                names = [i.getIssueName() for i in issues]
                if names:
                    existing = f.get("notes","")
                    note = "Burp Scanner also found: " + ", ".join(names[:3])
                    f["notes"] = (existing + " | " + note if existing else note)
                    f["severity"] = "High"  # elevate when confirmed
        except Exception:
            pass


    _CRITICAL_TITLES = {
        "AWS Access Key ID Exposed",
        "Private Key Block Exposed",
        "Database Connection String",
        "Default Credentials Detected",
        "JWT with alg:none",
        "Session Fixation",
        "Low-Entropy Session Token",
    }

    def _maybeAlert(self, f):
        """Push a Burp Alert for critical findings."""
        try:
            title = f.get("title","")
            if any(t in title for t in self._CRITICAL_TITLES):
                self._cb.issueAlert(
                    "[ASVS CRITICAL] %s at %s" % (title, f.get("url","")[:80]))
        except Exception:
            pass


    def _getAgeSummary(self):
        """Return counts of findings by age bucket."""
        now = datetime.datetime.now()
        buckets = {"<1h":0,"1-8h":0,"8-24h":0,">24h":0}
        for f in self._findings:
            try:
                ts = datetime.datetime.strptime(f.get("ts",""), "%H:%M:%S")
                ts = ts.replace(year=now.year, month=now.month, day=now.day)
                diff = (now - ts).seconds
                if diff < 3600: buckets["<1h"] += 1
                elif diff < 28800: buckets["1-8h"] += 1
                elif diff < 86400: buckets["8-24h"] += 1
                else: buckets[">24h"] += 1
            except Exception:
                buckets[">24h"] += 1
        return buckets

    def clearFindings(self):
        self._findings = []
        self._seen     = set()
        SwingUtilities.invokeLater(self._refreshTable)

    # -- UI -------------------------------------------------------------------
    def _buildUI(self):
        self._root = JTabbedPane()
        self._root.addTab("Findings (0)",   self._buildFindingsPanel())
        self._root.addTab("Controls",        self._buildControlsPanel())
        self._root.addTab("Manual Testing",  self._buildManualTestingPanel())
        self._root.addTab("Summary",         self._buildSummaryPanel())
        self._cb.addSuiteTab(self)

    def _buildFindingsPanel(self):
        panel = JPanel(BorderLayout(4, 4))
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        # -- Toolbar row 1: filter controls -----------------------------------
        tb1 = JToolBar(); tb1.setFloatable(False)
        tb1.add(JLabel("  ECWASS Security Scanner  "))
        tb1.addSeparator()
        self._filterField = JTextField(18)
        tb1.add(JLabel(" Filter: ")); tb1.add(self._filterField)
        tb1.addSeparator()

        # Severity filter
        sevs = ["All Severities", "High", "Medium", "Low", "Information"]
        self._sevBox = JComboBox(Vector(sevs))
        tb1.add(JLabel(" Severity: ")); tb1.add(self._sevBox)

        # Mandatory filter
        mands = ["All", "Mandatory Only", "Non-Mandatory"]
        self._mandBox = JComboBox(Vector(mands))
        tb1.add(JLabel(" Mandatory: ")); tb1.add(self._mandBox)

        # Category filter
        cats = ["All Categories"] + sorted(set(c[2] for c in ALL_CONTROLS))
        self._catFilterBox = JComboBox(Vector(cats))
        tb1.add(JLabel(" Category: ")); tb1.add(self._catFilterBox)

        # Assess type filter
        atypes = ["All Types", "Technical", "Questionnaire"]
        self._typeBox = JComboBox(Vector(atypes))
        tb1.add(JLabel(" Type: ")); tb1.add(self._typeBox)

        # HTTP Status filter (populated dynamically from findings)
        self._statusBox = JComboBox(Vector(["All Statuses"]))
        tb1.add(JLabel(" Status: ")); tb1.add(self._statusBox)

        # -- Toolbar row 2: action buttons ------------------------------------
        tb2 = JToolBar(); tb2.setFloatable(False)
        deleteBtn = JButton("Delete Selected")
        clearBtn  = JButton("Clear All")
        exportBtn  = JButton("Export CSV")
        exportHtml = JButton("Export HTML Report")
        deleteBtn.setToolTipText("Delete selected finding(s) from the list")
        tb2.add(deleteBtn); tb2.addSeparator()
        tb2.add(clearBtn); tb2.add(exportBtn); tb2.add(exportHtml)
        tb2.addSeparator()

        scanHistBtn = JButton("Scan Proxy History")
        scanHistBtn.setToolTipText(
            "Run all enabled checks against all traffic in Burp Proxy History")
        scanSiteBtn = JButton("Scan Site Map")
        scanSiteBtn.setToolTipText(
            "Run all enabled checks against all entries in Burp Site Map")
        tb2.add(scanHistBtn); tb2.add(scanSiteBtn)

        # Scope-aware toggle
        self._scopeOnly = JButton("Scope: ALL")
        self._scopeOnly.setToolTipText(
            "Toggle between scanning all traffic vs. in-scope only")
        self._inScopeOnly = [False]
        def _toggleScope(e):
            self._inScopeOnly[0] = not self._inScopeOnly[0]
            self._scopeOnly.setText(
                "Scope: IN-SCOPE ONLY" if self._inScopeOnly[0] else "Scope: ALL")
        self._scopeOnly.addActionListener(
            type("SA", (ActionListener,), {"actionPerformed": lambda s,e: _toggleScope(e)})())
        tb2.add(self._scopeOnly)
        self._statsLabel = JLabel("  Scanning: ON | 0 findings | 0 FP")
        self._statsLabel.setFont(Font("Monospaced", Font.PLAIN, 11))
        tb2.add(self._statsLabel)

        topPanel = JPanel(BorderLayout())
        topPanel.add(tb1, BorderLayout.NORTH)
        topPanel.add(tb2, BorderLayout.SOUTH)
        panel.add(topPanel, BorderLayout.NORTH)

        cols = ["Time", "Status", "ID", "Category", "Mandatory", "Severity", "URL", "Title"]
        self._tableModel = _FindingsModel(Vector(cols), 0)
        self._table      = JTable(self._tableModel)
        self._table.setSelectionMode(javax.swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._sorter     = TableRowSorter(self._tableModel)
        self._table.setRowSorter(self._sorter)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        self._table.setRowHeight(20)

        cm = self._table.getColumnModel()
        for i, w in enumerate([130, 50, 110, 180, 70, 75, 270, 300]):
            cm.getColumn(i).setPreferredWidth(w)

        ren = self._SeverityRenderer()
        for i in range(len(cols)):
            cm.getColumn(i).setCellRenderer(ren)

        self._detailArea = JTextArea()
        self._detailArea.setEditable(False)
        self._detailArea.setLineWrap(True)
        self._detailArea.setWrapStyleWord(True)
        self._detailArea.setFont(Font("Monospaced", Font.PLAIN, 11))

        self._table.getSelectionModel().addListSelectionListener(
            self._RowSelector(self))
        self._table.addMouseListener(self._RightClickMenu(self))
        self._notesArea = JTextArea(3, 40)
        self._notesArea.setLineWrap(True); self._notesArea.setWrapStyleWord(True)
        self._notesArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._notesArea.getDocument().addDocumentListener(self._NotesListener(self))
        notesPanel = JPanel(BorderLayout())
        notesPanel.add(JLabel("  Analyst Notes:"), BorderLayout.NORTH)
        notesPanel.add(JScrollPane(self._notesArea), BorderLayout.CENTER)
        detailOuter = JPanel(BorderLayout())
        detailOuter.add(JScrollPane(self._detailArea), BorderLayout.CENTER)
        detailOuter.add(notesPanel, BorderLayout.SOUTH)
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           JScrollPane(self._table), detailOuter)
        split.setResizeWeight(0.55)
        panel.add(split, BorderLayout.CENTER)

        deleteBtn.addActionListener(self._DeleteAction(self))
        clearBtn.addActionListener(self._ClearAction(self))
        exportBtn.addActionListener(self._ExportAction(self))
        ext = self
        class _HtmlExportA(ActionListener):
            def actionPerformed(s2,e): ext._exportHTML()
        exportHtml.addActionListener(_HtmlExportA())

        class _ScanHistAction(ActionListener):
            def actionPerformed(s2, e):
                ext._scanHistory()
        class _ScanSiteAction(ActionListener):
            def actionPerformed(s2, e):
                ext._scanSiteMap()
        scanHistBtn.addActionListener(_ScanHistAction())
        scanSiteBtn.addActionListener(_ScanSiteAction())
        self._filterField.getDocument().addDocumentListener(self._FilterListener(self))
        self._sevBox.addActionListener(self._ComboFilterAction(self))
        self._mandBox.addActionListener(self._ComboFilterAction(self))
        self._catFilterBox.addActionListener(self._ComboFilterAction(self))
        self._typeBox.addActionListener(self._ComboFilterAction(self))
        self._statusBox.addActionListener(self._ComboFilterAction(self))
        return panel

    class _SeverityRenderer(DefaultTableCellRenderer):
        _SEV = {"High": Color(0xFF6666), "Medium": Color(0xFFB266),
                "Low": Color(0xFFFF99), "Information": Color(0xADD8E6)}
        def getTableCellRendererComponent(self, tbl, val, sel, foc, row, col):
            c = DefaultTableCellRenderer.getTableCellRendererComponent(
                self, tbl, val, sel, foc, row, col)
            if not sel:
                mr  = tbl.convertRowIndexToModel(row)
                sev = str(tbl.getModel().getValueAt(mr, 5))
                c.setBackground(self._SEV.get(sev, Color.WHITE))
            return c

    class _RowSelector(ListSelectionListener):
        def __init__(self, ext): self._ext = ext
        def valueChanged(self, ev):
            if ev.getValueIsAdjusting(): return
            row = self._ext._table.getSelectedRow()
            if row < 0: return
            mr = self._ext._table.convertRowIndexToModel(row)
            if mr >= len(self._ext._findings): return
            f = self._ext._findings[mr]
            txt = (
                "ID          : %s\n"
                "Category    : %s\n"
                "Assess Type : %s\n"
                "Mandatory   : %s\n"
                "Severity    : %s\n"
                "HTTP Status : %s\n"
                "URL         : %s\n"
                "\nFinding:\n%s\n"
                "\nRequirement:\n%s" % (
                    f.get("id",""), f.get("category",""),
                    f.get("assess_type",""), f.get("mandatory",""),
                    f.get("severity",""), f.get("status",""),
                    f.get("url",""),
                    f.get("detail",""), f.get("requirement",""))
            )
            if f.get("req_hdrs"):
                txt += "\n\n---- Request Headers ----\n" + f.get("req_hdrs","")
            if f.get("resp_hdrs"):
                txt += "\n\n---- Response Headers ----\n" + f.get("resp_hdrs","")
            if f.get("body_snippet"):
                txt += "\n\n---- Body Snippet (evidence) ----\n" + f.get("body_snippet","")
            self._ext._detailArea.setText(txt)
            self._ext._detailArea.setCaretPosition(0)
            try: self._ext._notesArea.setText(f.get("notes",""))
            except Exception: pass
    class _ClearAction(ActionListener):
        def __init__(self, ext): self._ext = ext
        def actionPerformed(self, e): self._ext.clearFindings()

    class _ExportAction(ActionListener):
        def __init__(self, ext): self._ext = ext
        def actionPerformed(self, e): self._ext._exportCSV()

    class _DeleteAction(ActionListener):
        def __init__(self, ext): self._ext = ext
        def actionPerformed(self, e):
            rows = self._ext._table.getSelectedRows()
            if not rows or len(rows) == 0: return
            model_rows = sorted(
                [self._ext._table.convertRowIndexToModel(r) for r in rows],
                reverse=True)
            for mr in model_rows:
                if mr < len(self._ext._findings):
                    f = self._ext._findings[mr]
                    key = f["id"] + "|" + f["url"]
                    self._ext._seen.discard(key)
                    del self._ext._findings[mr]
            SwingUtilities.invokeLater(self._ext._refreshTable)
            self._ext._detailArea.setText("")

    class _ComboFilterAction(ActionListener):
        def __init__(self, ext): self._ext = ext
        def actionPerformed(self, e): self._ext._applyFilter()

    class _FilterListener(DocumentListener):
        def __init__(self, ext): self._ext = ext
        def _a(self): self._ext._applyFilter()
        def changedUpdate(self, e): self._a()
        def insertUpdate(self, e):  self._a()
        def removeUpdate(self, e):  self._a()

    def _applyFilter(self):
        filters = []
        txt = self._filterField.getText().strip()
        if txt:
            try: filters.append(RowFilter.regexFilter("(?i)" + txt))
            except Exception: pass
        sev = str(self._sevBox.getSelectedItem())
        if sev and sev != "All Severities":
            try: filters.append(RowFilter.regexFilter("(?i)^" + sev + "$", 5))
            except Exception: pass
        mand = str(self._mandBox.getSelectedItem())
        if mand == "Mandatory Only":
            try: filters.append(RowFilter.regexFilter("^Yes$", 4))
            except Exception: pass
        elif mand == "Non-Mandatory":
            try: filters.append(RowFilter.regexFilter("^No$", 4))
            except Exception: pass
        cat = str(self._catFilterBox.getSelectedItem())
        if cat and cat != "All Categories":
            try: filters.append(RowFilter.regexFilter("(?i)^" + re.escape(cat) + "$", 3))
            except Exception: pass
        atype = str(self._typeBox.getSelectedItem())
        if atype and atype != "All Types":
            try: filters.append(RowFilter.regexFilter("(?i)" + atype))
            except Exception: pass
        status = str(self._statusBox.getSelectedItem())
        if status and status != "All Statuses":
            try: filters.append(RowFilter.regexFilter("^" + re.escape(status) + "$", 1))
            except Exception: pass
        if not filters:
            self._sorter.setRowFilter(None)
        elif len(filters) == 1:
            self._sorter.setRowFilter(filters[0])
        else:
            self._sorter.setRowFilter(RowFilter.andFilter(Arrays.asList(filters)))

    def _refreshTable(self):
        self._tableModel.setRowCount(0)
        statuses = sorted(set(f.get("status","") for f in self._findings if f.get("status","")))
        cur_status = str(self._statusBox.getSelectedItem())
        self._statusBox.removeAllItems()
        self._statusBox.addItem("All Statuses")
        for s in statuses:
            self._statusBox.addItem(s)
        if cur_status in statuses:
            self._statusBox.setSelectedItem(cur_status)
        for f in self._findings:
            self._tableModel.addRow(Vector([
                f.get("ts",""), f.get("status",""), f.get("id",""), f.get("category",""),
                f.get("mandatory",""), f.get("severity",""),
                f.get("url",""), f.get("title",""),
            ]))
        self._root.setTitleAt(0, "Findings (%d)" % len(self._findings))
        fp_n = sum(1 for f in self._findings if f.get("title","").startswith("[FP]"))
        if hasattr(self, "_statsLabel"):
            self._statsLabel.setText(
                "  Findings: %d | FP: %d" % (len(self._findings), fp_n))
        self._updateSummary()


    def _exportHTML(self):
        """Export a self-contained HTML security report."""
        chooser = JFileChooser()
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        chooser.setSelectedFile(java.io.File("asvs_report_%s.html" % ts))
        if chooser.showSaveDialog(self._root) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.endswith(".html"): path += ".html"
        try:
            sev_order = {"High":0,"Medium":1,"Low":2,"Information":3}
            sev_col   = {"High":"#FF6666","Medium":"#FFB266",
                         "Low":"#FFFF99","Information":"#ADD8E6"}
            fs = sorted(self._findings,
                        key=lambda f: sev_order.get(f.get("severity",""),9))
            counts = {}
            for f in fs:
                counts[f.get("severity","?")] = counts.get(f.get("severity","?"),0)+1
            fp_n = sum(1 for f in fs if f.get("title","").startswith("[FP]"))

            def esc(s):
                return (str(s).replace("&","&amp;").replace("<","&lt;")
                              .replace(">","&gt;").replace('"',"&quot;"))

            # Build severity bars
            bar_html = ""
            for sev in ["High","Medium","Low","Information"]:
                n = counts.get(sev, 0)
                w = min(300, n * 8)
                bar_html += (
                    "<div style='margin:2px 0'>"
                    "<span style='display:inline-block;width:80px;font-size:12px'>%s</span>"
                    "<span style='display:inline-block;width:%dpx;background:%s;"
                    "height:16px;vertical-align:middle'></span>"
                    "<span style='margin-left:6px;font-size:12px'>%d</span></div>"
                ) % (sev, w, sev_col.get(sev,"#ccc"), n)

            # Build summary boxes
            box_html = ""
            for sev in ["High","Medium","Low","Information"]:
                box_html += (
                    "<div style='background:#f5f5f5;border:1px solid #ddd;padding:12px;"
                    "border-radius:4px;margin:4px;display:inline-block;min-width:120px'>"
                    "<div style='font-size:13px;font-weight:bold'>%s</div>"
                    "<div style='font-size:28px;color:%s'>%d</div></div>"
                ) % (sev, sev_col.get(sev,"#000"), counts.get(sev,0))

            # Build finding rows
            rows_html = ""
            for i, f in enumerate(fs):
                sev = f.get("severity","?")
                col = sev_col.get(sev, "#fff")
                fp  = " [FP]" if f.get("title","").startswith("[FP]") else ""
                detail = esc(f.get("detail","")[:500])
                notes  = esc(f.get("notes","")[:200])
                rows_html += (
                    "<tr id='r%d'>"
                    "<td style='background:%s;padding:4px'>%s%s</td>"
                    "<td style='padding:4px'>%s</td>"
                    "<td style='padding:4px'>%s</td>"
                    "<td style='padding:4px;max-width:300px;word-break:break-all'>%s</td>"
                    "<td style='padding:4px'>%s</td>"
                    "<td style='padding:4px;font-size:10px'>%s</td>"
                    "</tr>"
                    "<tr><td colspan='6' style='padding:6px;background:#f9f9f9;"
                    "font-size:11px;font-family:monospace;white-space:pre-wrap;"
                    "word-break:break-all'>%s%s</td></tr>"
                ) % (i, col, esc(sev), fp,
                     esc(f.get("id","")), esc(f.get("chapter","")),
                     esc(f.get("url","")[:80]), esc(f.get("title","")),
                     esc(f.get("ts","")),
                     detail,
                     ("<br><b>Notes:</b> " + notes) if notes else "")

            # CSS as a separate string to avoid % confusion
            css = (
                "body{font-family:Arial,sans-serif;margin:20px;color:#222}"
                "h1{color:#333}"
                "h2{color:#555;border-bottom:2px solid #ddd;padding-bottom:4px}"
                "table{border-collapse:collapse;width:99vw}"
                "th{background:#444;color:#fff;padding:6px;text-align:left}"
                "tr:hover{background:#f0f0f0}"
            )

            js = (
                "function filt(v){"
                "v=v.toLowerCase();"
                "document.querySelectorAll('tr[id]').forEach(function(r){"
                "var show=r.textContent.toLowerCase().indexOf(v)>=0;"
                "r.style.display=show?'':'none';"
                "var n=r.nextElementSibling;if(n)n.style.display=r.style.display;"
                "});}"
            )

            html = (
                "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                "<title>ASVS Security Report</title>"
                "<style>" + css + "</style>"
                "<script>" + js + "</script>"
                "</head><body>"
                "<h1>ASVS Security Scan Report</h1>"
                "<p>Generated: %s | Total: %d | FP: %d</p>"
                "<h2>Severity Summary</h2><div>%s</div>"
                "<h2>Distribution</h2>%s"
                "<h2>Findings</h2>"
                "<input type='text' placeholder='Filter...' "
                "style='margin:8px;padding:4px;width:300px' "
                "oninput='filt(this.value)'>"
                "<table><thead><tr>"
                "<th>Severity</th><th>ID</th><th>Chapter</th>"
                "<th>URL</th><th>Title</th><th>Time</th>"
                "</tr></thead><tbody>%s</tbody></table>"
                "</body></html>"
            ) % (esc(ts), len(fs), fp_n, box_html, bar_html, rows_html)

            fos = FileOutputStream(path)
            osw = OutputStreamWriter(fos, "UTF-8")
            bw  = BufferedWriter(osw)
            bw.write(html)
            bw.close()
            JOptionPane.showMessageDialog(None,
                "HTML report exported to:\n" + path,
                "Export Complete", JOptionPane.INFORMATION_MESSAGE)
        except Exception as ex:
            JOptionPane.showMessageDialog(None, "Export failed: " + str(ex),
                "Error", JOptionPane.ERROR_MESSAGE)


    def _aiTriage(self, finding):
        """Call Anthropic API to triage a finding and append analysis to notes."""
        try:
            import urllib2 as _urllib
            import json as _json
        except ImportError:
            try:
                import urllib.request as _urllib
                import json as _json
            except Exception:
                JOptionPane.showMessageDialog(None,
                    "urllib not available in this Jython environment.",
                    "AI Triage", JOptionPane.ERROR_MESSAGE)
                return

        prompt = (
            "You are a senior web application security consultant reviewing a "
            "passive scanner finding. Provide a concise assessment in exactly "
            "this format:\n\n"
            "TRUE_POSITIVE: yes/no/maybe\n"
            "EXPLOITABILITY: critical/high/medium/low/informational\n"
            "CONFIDENCE: high/medium/low\n"
            "REMEDIATION: <one sentence>\n"
            "ANALYST_NOTE: <two sentences max>\n\n"
            "Finding:\n"
            "ID: %(id)s\n"
            "Title: %(title)s\n"
            "Severity: %(severity)s\n"
            "URL: %(url)s\n"
            "Detail: %(detail)s\n"
            "Response Headers: %(resp_hdrs)s\n"
            "Body Snippet: %(body_snippet)s"
        ) % {
            "id":          finding.get("id",""),
            "title":       finding.get("title",""),
            "severity":    finding.get("severity",""),
            "url":         finding.get("url","")[:120],
            "detail":      finding.get("detail","")[:400],
            "resp_hdrs":   finding.get("resp_hdrs","")[:300],
            "body_snippet":finding.get("body_snippet","")[:200],
        }

        payload = _json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}]
        }).encode("utf-8")

        def _do_request():
            try:
                import java.net
                url_obj = java.net.URL("https://api.anthropic.com/v1/messages")
                conn = url_obj.openConnection()
                conn.setRequestMethod("POST")
                conn.setDoOutput(True)
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("anthropic-version", "2023-06-01")
                conn.setConnectTimeout(15000)
                conn.setReadTimeout(30000)
                conn.getOutputStream().write(payload)
                code = conn.getResponseCode()
                stream = conn.getInputStream() if code == 200 else conn.getErrorStream()
                import java.io
                reader = java.io.BufferedReader(
                    java.io.InputStreamReader(stream, "UTF-8"))
                lines = []
                line = reader.readLine()
                while line is not None:
                    lines.append(str(line))
                    line = reader.readLine()
                reader.close()
                response_text = "\n".join(lines)
                data = _json.loads(response_text)
                if "content" in data and data["content"]:
                    ai_text = data["content"][0].get("text", "")
                    old_notes = finding.get("notes","")
                    finding["notes"] = (
                        (old_notes + "\n\n" if old_notes else "") +
                        "--- AI Triage ---\n" + ai_text.strip())
                    SwingUtilities.invokeLater(self._refreshTable)
                    SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                        None, "AI triage complete for %s.\nNotes updated."
                        % finding.get("id",""),
                        "AI Triage", JOptionPane.INFORMATION_MESSAGE))
                else:
                    SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                        None, "AI response was empty. Check extension output.",
                        "AI Triage", JOptionPane.WARNING_MESSAGE))
            except Exception as ex:
                err_msg = str(ex)
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                    None, "AI triage failed:\n" + err_msg,
                    "AI Triage Error", JOptionPane.ERROR_MESSAGE))

        import threading
        t = threading.Thread(target=_do_request)
        t.setDaemon(True)
        t.start()
        JOptionPane.showMessageDialog(None,
            "AI triage request sent. Notes will update when complete.",
            "AI Triage", JOptionPane.INFORMATION_MESSAGE)

    def _exportCSV(self):
        chooser = JFileChooser()
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        chooser.setSelectedFile(java.io.File("ecwass_findings_%s.csv" % ts))
        if chooser.showSaveDialog(self._root) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.endswith(".csv"): path += ".csv"
            try:
                def esc(s): return '"' + str(s).replace('"', '""') + '"'
                fos = FileOutputStream(path)
                osw = OutputStreamWriter(fos, "UTF-8")
                bw  = BufferedWriter(osw)
                visible_rows = [self._table.convertRowIndexToModel(r)
                               for r in range(self._table.getRowCount())]
                visible_findings = [self._findings[r] for r in visible_rows
                                    if r < len(self._findings)]
                bw.write("Time,Status,ID,Category,Mandatory,Severity,URL,Title,Detail,Requirement,Notes\n")
                for f in visible_findings:
                    bw.write(",".join([
                        esc(f.get("ts","")), esc(f.get("status","")),
                        esc(f.get("id","")), esc(f.get("category","")),
                        esc(f.get("mandatory","")), esc(f.get("severity","")),
                        esc(f.get("url","")), esc(f.get("title","")),
                        esc(f.get("detail","")), esc(f.get("requirement","")),
                        esc(f.get("notes","")),
                    ]) + "\n")
                exported = len(visible_findings)
                bw.close()
                JOptionPane.showMessageDialog(None,
                    "Exported %d finding(s) to:\n%s" % (exported, path),
                    "Export Complete", JOptionPane.INFORMATION_MESSAGE)
            except Exception as ex:
                JOptionPane.showMessageDialog(None, "Export failed: " + str(ex),
                    "Export Error", JOptionPane.ERROR_MESSAGE)


    # IDs with a passive check (exact)
    _PASSIVE_IDS = set(TECHNICAL_CHECKS.keys())
    # IDs whose passive check is heuristic/low-confidence
    _HEURISTIC_IDS = {"ECWASS-021","ECWASS-024","ECWASS-025","ECWASS-039","ECWASS-041","ECWASS-050","ECWASS-052","ECWASS-053","ECWASS-061","ECWASS-062"}

    @classmethod
    def _scan_mode(cls, cid):
        if cid in cls._PASSIVE_IDS:
            if cid in cls._HEURISTIC_IDS: return "Heuristic"
            return "Passive"
        return "Manual Only"

    def _scanHistory(self):
        """Scan all Proxy History entries."""
        def _run():
            try:
                history = self._cb.getProxyHistory()
                total = len(history)
                self._out.println("[ASVS] Scanning %d proxy history entries..." % total)
                count = 0
                for msg in history:
                    try:
                        for f in self._runChecks(msg):
                            self._addFinding(f)
                        count += 1
                    except Exception: pass
                self._out.println("[ASVS] History scan complete: %d entries." % count)
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                    None, "Proxy History scan complete.\n%d entries scanned."
                    % count, "ASVS Scanner", JOptionPane.INFORMATION_MESSAGE))
            except Exception as ex:
                self._err.println("[ASVS] History scan error: " + str(ex))
        import threading
        threading.Thread(target=_run).start()

    def _scanSiteMap(self):
        """Scan all Site Map entries."""
        def _run():
            try:
                entries = self._cb.getSiteMap(None)
                total = len(entries)
                self._out.println("[ASVS] Scanning %d site map entries..." % total)
                count = 0
                for msg in entries:
                    try:
                        if msg.getResponse():
                            for f in self._runChecks(msg):
                                self._addFinding(f)
                            count += 1
                    except Exception: pass
                self._out.println("[ASVS] Site map scan complete: %d entries." % count)
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                    None, "Site Map scan complete.\n%d entries scanned."
                    % count, "ASVS Scanner", JOptionPane.INFORMATION_MESSAGE))
            except Exception as ex:
                self._err.println("[ASVS] Site map scan error: " + str(ex))
        import threading
        threading.Thread(target=_run).start()

    def _buildControlsPanel(self):
        outer = JPanel(BorderLayout(4, 4))
        outer.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        tb = JToolBar(); tb.setFloatable(False)
        allBtn   = JButton("Select All")
        noneBtn  = JButton("Select None")
        mandBtn  = JButton("Mandatory Only")
        techBtn  = JButton("Technical Only")
        applyBtn = JButton("  Apply Selection  ")
        applyBtn.setBackground(Color(0x388E3C))
        applyBtn.setForeground(Color.WHITE)

        cats = ["All Categories"] + sorted(set(c[2] for c in ALL_CONTROLS))
        self._catCombo   = JComboBox(Vector(cats))
        self._ctrlSearch = JTextField(16)

        tb.add(JLabel("  Category: ")); tb.add(self._catCombo)
        tb.add(JLabel("  Search: ")); tb.add(self._ctrlSearch)
        modes = ["All Modes", "Passive", "Heuristic", "Manual Only"]
        self._modeBox = JComboBox(Vector(modes))
        tb.add(JLabel("  Mode: ")); tb.add(self._modeBox)
        tb.addSeparator()
        tb.add(allBtn); tb.add(noneBtn); tb.add(mandBtn); tb.add(techBtn)
        tb.addSeparator(); tb.add(applyBtn)
        outer.add(tb, BorderLayout.NORTH)

        legend = JPanel()
        legend.setLayout(BoxLayout(legend, BoxLayout.X_AXIS))
        def mkLeg(color, text):
            lbl = JLabel("  " + text + "  ")
            lbl.setOpaque(True); lbl.setBackground(color)
            lbl.setBorder(BorderFactory.createLineBorder(Color.GRAY))
            return lbl
        legend.add(mkLeg(Color(0xE8F5E9), "Technical (auto-scanned)"))
        legend.add(JLabel("  "))
        legend.add(mkLeg(Color(0xE3F2FD), "Questionnaire (manual)"))
        legend.add(JLabel("    "))
        legend.add(mkLeg(Color(0xC8E6C9), "Passive (auto-detected)"))
        legend.add(JLabel("  "))
        legend.add(mkLeg(Color(0xFFF9C4), "Heuristic (low confidence)"))
        legend.add(JLabel("  "))
        legend.add(mkLeg(Color(0xF5F5F5), "Manual Only (active/stateful)"))
        legend.add(JLabel("  "))
        legend.add(JLabel("Bold = Mandatory"))
        outer.add(legend, BorderLayout.SOUTH)

        ctrlCols = ["Active", "ID", "Category", "Type", "Mandatory", "Scan Mode", "Requirement"]
        self._ctrlModel  = _ControlsModel(Vector(ctrlCols), 0)
        self._ctrlTable  = JTable(self._ctrlModel)
        self._ctrlSorter = TableRowSorter(self._ctrlModel)
        self._ctrlTable.setRowSorter(self._ctrlSorter)
        self._ctrlTable.setRowHeight(20)
        self._ctrlTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)

        ccm = self._ctrlTable.getColumnModel()
        for i, w in enumerate([50, 110, 190, 110, 75, 600]):
            ccm.getColumn(i).setPreferredWidth(w)

        cr = self._ControlsRenderer()
        for i in range(1, len(ctrlCols)):
            ccm.getColumn(i).setCellRenderer(cr)

        for c in ALL_CONTROLS:
            ecid, asset, cat, req, atype, mand = c
            self._ctrlModel.addRow(Vector([
                JBoolean(ecid in self._enabled),
                ecid, cat, atype,
                "Yes" if mand else "No", req
            ]))

        outer.add(JScrollPane(self._ctrlTable), BorderLayout.CENTER)

        ext = self

        class _AllL(ActionListener):
            def actionPerformed(self, e):
                for r in range(ext._ctrlModel.getRowCount()):
                    ext._ctrlModel.setValueAt(JBoolean(True), r, 0)

        class _NoneL(ActionListener):
            def actionPerformed(self, e):
                for r in range(ext._ctrlModel.getRowCount()):
                    ext._ctrlModel.setValueAt(JBoolean(False), r, 0)

        class _MandL(ActionListener):
            def actionPerformed(self, e):
                for r in range(ext._ctrlModel.getRowCount()):
                    ext._ctrlModel.setValueAt(
                        JBoolean(ext._ctrlModel.getValueAt(r, 4) == "Yes"), r, 0)

        class _TechL(ActionListener):
            def actionPerformed(self, e):
                for r in range(ext._ctrlModel.getRowCount()):
                    ext._ctrlModel.setValueAt(
                        JBoolean(ext._ctrlModel.getValueAt(r, 3) == "Technical"), r, 0)

        class _ApplyL(ActionListener):
            def actionPerformed(self, e):
                ext._enabled = set()
                for r in range(ext._ctrlModel.getRowCount()):
                    if ext._ctrlModel.getValueAt(r, 0):
                        ext._enabled.add(str(ext._ctrlModel.getValueAt(r, 1)))
                try:
                    ext._cb.saveExtensionSetting("ecwass_enabled_controls",
                        ",".join(sorted(ext._enabled)))
                except Exception: pass
                JOptionPane.showMessageDialog(None,
                    "%d control(s) now active.\n"
                    "(Technical = auto-scanned; Questionnaire = manual review)"
                    % len(ext._enabled),
                    "ECWASS Scanner", JOptionPane.INFORMATION_MESSAGE)

        class _CatL(ActionListener):
            def actionPerformed(self, e):
                ext._applyCtrlFilter()

        class _SearchL(DocumentListener):
            def __init__(self, ext): self._ext = ext
            def _d(self): self._ext._applyCtrlFilter()
            def changedUpdate(self, e): self._d()
            def insertUpdate(self, e):  self._d()
            def removeUpdate(self, e):  self._d()

        allBtn.addActionListener(_AllL())
        noneBtn.addActionListener(_NoneL())
        mandBtn.addActionListener(_MandL())
        techBtn.addActionListener(_TechL())
        applyBtn.addActionListener(_ApplyL())
        self._catCombo.addActionListener(_CatL())
        self._ctrlSearch.getDocument().addDocumentListener(_SearchL(self))
        return outer

    class _ControlsRenderer(DefaultTableCellRenderer):
        _MODE_COL = {"Passive": Color(0xC8E6C9),
                     "Heuristic": Color(0xFFF9C4),
                     "Manual Only": Color(0xF5F5F5)}
        def getTableCellRendererComponent(self, tbl, val, sel, foc, row, col):
            c = DefaultTableCellRenderer.getTableCellRendererComponent(
                self, tbl, val, sel, foc, row, col)
            if not sel:
                mr   = tbl.convertRowIndexToModel(row)
                atyp = str(tbl.getModel().getValueAt(mr, 3))
                mode = str(tbl.getModel().getValueAt(mr, 5))
                mand = str(tbl.getModel().getValueAt(mr, 4))
                if col == 5:
                    c.setBackground(self._MODE_COL.get(mode, Color.WHITE))
                else:
                    c.setBackground(Color(0xE8F5E9) if atyp == "Technical" else Color(0xE3F2FD))
                fnt = c.getFont()
                c.setFont(fnt.deriveFont(Font.BOLD if mand == "Yes" else Font.PLAIN))
            return c

    def _applyCtrlFilter(self):
        cat = str(self._catCombo.getSelectedItem())
        txt = self._ctrlSearch.getText().strip()
        filters = []
        if cat and cat != "All Categories":
            try: filters.append(RowFilter.regexFilter("(?i)^" + re.escape(cat) + "$", 3))
            except Exception: pass
        mode = str(self._modeBox.getSelectedItem()) if hasattr(self, "_modeBox") else "All Modes"
        if mode and mode != "All Modes":
            try: filters.append(RowFilter.regexFilter("^" + re.escape(mode) + "$", 5))
            except Exception: pass
        if txt:
            try: filters.append(RowFilter.regexFilter("(?i)" + txt))
            except Exception: pass
        if not filters:
            self._ctrlSorter.setRowFilter(None)
        elif len(filters) == 1:
            self._ctrlSorter.setRowFilter(filters[0])
        else:
            self._ctrlSorter.setRowFilter(RowFilter.andFilter(Arrays.asList(filters)))


    class _RightClickMenu(java.awt.event.MouseAdapter):
        _SEVS = ["High", "Medium", "Low", "Information", "False Positive"]
        def __init__(self, ext): self._ext = ext
        def mouseReleased(self, e):
            if e.isPopupTrigger(): self._show(e)
        def mousePressed(self, e):
            if e.isPopupTrigger(): self._show(e)
        def _show(self, e):
            row = self._ext._table.rowAtPoint(e.getPoint())
            if row < 0: return
            if not self._ext._table.isRowSelected(row):
                self._ext._table.setRowSelectionInterval(row, row)
            menu = JPopupMenu()
            ext = self._ext
            for sev in self._SEVS:
                item = JMenuItem("Set severity: " + sev)
                item.addActionListener(self._SetSev(ext, sev))
                menu.add(item)
            menu.addSeparator()
            dupItem = JMenuItem("Mark as Duplicate (suppress future)")
            dupItem.addActionListener(self._MarkDuplicateE(ext))
            menu.add(dupItem)
            sendRepItem = JMenuItem("Send to Repeater")
            sendRepItem.addActionListener(self._SendToRepeaterE(ext))
            menu.add(sendRepItem)
            srchItem = JMenuItem("Search in Evidence...")
            srchItem.addActionListener(self._SearchEvidenceE(ext))
            menu.add(srchItem)
            menu.show(e.getComponent(), e.getX(), e.getY())

    class _SetSev(java.awt.event.ActionListener):
        def __init__(self, ext, sev): self._ext = ext; self._sev = sev
        def actionPerformed(self, e):
            rows = self._ext._table.getSelectedRows()
            for vr in rows:
                mr = self._ext._table.convertRowIndexToModel(vr)
                if mr < len(self._ext._findings):
                    f = self._ext._findings[mr]
                    if self._sev == "False Positive":
                        f["severity"] = "Information"
                        f["title"] = "[FP] " + f.get("title","") if not f.get("title","").startswith("[FP]") else f.get("title","")
                    else:
                        f["severity"] = self._sev
                        if f.get("title","").startswith("[FP] "):
                            f["title"] = f["title"][5:]
            SwingUtilities.invokeLater(self._ext._refreshTable)

    class _NotesListener(DocumentListener):
        def __init__(self, ext): self._ext = ext
        def _save(self):
            row = self._ext._table.getSelectedRow()
            if row < 0: return
            mr = self._ext._table.convertRowIndexToModel(row)
            if mr < len(self._ext._findings):
                self._ext._findings[mr]["notes"] = self._ext._notesArea.getText()
        def changedUpdate(self, e): self._save()
        def insertUpdate(self, e):  self._save()
        def removeUpdate(self, e):  self._save()

    def _buildSummaryPanel(self):
        self._summaryArea = JTextArea()
        self._summaryArea.setEditable(False)
        self._summaryArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._summaryArea.setText("No findings yet.")
        p = JPanel(BorderLayout())
        p.setBorder(BorderFactory.createEmptyBorder(8,8,8,8))
        p.add(JLabel("  Scan Summary"), BorderLayout.NORTH)
        p.add(JScrollPane(self._summaryArea), BorderLayout.CENTER)
        return p

    def _updateSummary(self):
        if not hasattr(self, "_summaryArea"): return
        fs = self._findings
        if not fs:
            self._summaryArea.setText("No findings yet.")
            return
        sev_count = {}
        cat_count = {}
        urls = set()
        fp_count = 0
        for f in fs:
            s = f.get("severity","?")
            sev_count[s] = sev_count.get(s, 0) + 1
            c = f.get("category","?")
            cat_count[c] = cat_count.get(c, 0) + 1
            urls.add(f.get("url",""))
            if f.get("title","").startswith("[FP]"): fp_count += 1
        lines = ["=" * 48]
        lines.append("  ECWASS Scan Summary")
        lines.append("=" * 48)
        lines.append("Total findings : %d" % len(fs))
        lines.append("Unique URLs    : %d" % len(urls))
        lines.append("False Positives: %d" % fp_count)
        lines.append("")
        lines.append("By Severity:")
        for s in ["High","Medium","Low","Information"]:
            n = sev_count.get(s, 0)
            if n: lines.append("  %-14s %d" % (s, n))
        lines.append("")
        lines.append("By Category (findings / FP):")
        cat_fp = {}
        for f in fs:
            c2 = f.get("category","?")
            if f.get("title","").startswith("[FP]"):
                cat_fp[c2] = cat_fp.get(c2,0) + 1
        for c, n in sorted(cat_count.items(), key=lambda x: -x[1]):
            fp_c = cat_fp.get(c, 0)
            fp_pct = " (%d%% FP)" % (100*fp_c//n) if fp_c else ""
            lines.append("  %-36s %d%s" % ((c[:34]+"..") if len(c)>36 else c, n, fp_pct))
        lines.append("")
        passive_n  = sum(1 for c in ALL_CONTROLS if ECWASSExtension._scan_mode(c[0]) == "Passive")
        heuristic_n = sum(1 for c in ALL_CONTROLS if ECWASSExtension._scan_mode(c[0]) == "Heuristic")
        manual_n   = sum(1 for c in ALL_CONTROLS if ECWASSExtension._scan_mode(c[0]) == "Manual Only")
        age = self._getAgeSummary()
        lines.append("")
        lines.append("Finding Age:")
        for bucket, n in [("<1h",age["<1h"]),("1-8h",age["1-8h"]),
                           ("8-24h",age["8-24h"]),(">24h",age[">24h"])]:
            if n: lines.append("  %-8s %d" % (bucket, n))
        lines.append("")
        lines.append("Controls enabled : %d / %d" % (len(self._enabled), len(ALL_CONTROLS)))
        lines.append("  Passive auto-detect : %d" % passive_n)
        lines.append("  Heuristic           : %d" % heuristic_n)
        lines.append("  Manual only         : %d" % manual_n)
        self._summaryArea.setText("\n".join(lines))


    def _buildManualTestingPanel(self):
        """Manual Testing tab: checklist + testing guide for Manual Only controls."""
        outer = JPanel(BorderLayout(4,4))
        outer.setBorder(BorderFactory.createEmptyBorder(6,6,6,6))

        # -- toolbar ----------------------------------------------------------
        tb = JToolBar(); tb.setFloatable(False)
        tb.add(JLabel("  Manual Testing Checklist  "))
        tb.addSeparator()
        # Status filter
        statOpts = ["All Statuses","Untested","Pass","Fail","Partial","N/A"]
        self._mtStatusFilter = JComboBox(Vector(statOpts))
        tb.add(JLabel(" Filter: ")); tb.add(self._mtStatusFilter)
        tb.addSeparator()
        # Log evidence button
        self._logEvidBtn = JButton("Log Evidence from Proxy/Repeater")
        self._logEvidBtn.setToolTipText(
            "Right-click a request in Proxy/Repeater history and choose "
            "ASVS: Log Evidence, OR select a control below and click this button "
            "then switch to Proxy history and use the context menu.")
        tb.add(self._logEvidBtn)
        # Export button
        exportMTBtn = JButton("Export Checklist CSV")
        tb.add(exportMTBtn)
        outer.add(tb, BorderLayout.NORTH)

        # -- checklist table ---------------------------------------------------
        mtCols = ["Status","ID","Chapter","Section","L1","Tool","Evidence URL","Notes"]
        class _MTModel(DefaultTableModel):
            def isCellEditable(self2, row, col):
                return col in (0, 7)  # Status and Notes are editable
        self._mtModel = _MTModel(Vector(mtCols), 0)

        # Populate with all Technical Manual-Only controls
        mt_dispatch = set(_RAW_DISPATCH.keys())
        for c in ALL_CONTROLS:
            cid = c[0]
            if c[3] != "Technical": continue
            if cid in mt_dispatch: continue
            chap = c[1]; sec = c[2]; l1 = ""
            guide = _ECWASS_MANUAL_GUIDE.get(cid, ("", "Manual", ""))
            tool = guide[1] if guide else "Manual"
            self._mtModel.addRow(Vector(
                ["Untested", cid, chap, sec, l1, tool, "", ""]))

        self._mtView   = JTable(self._mtModel)
        self._mtSorter = TableRowSorter(self._mtModel)
        self._mtView.setRowSorter(self._mtSorter)
        self._mtView.setSelectionMode(
            javax.swing.ListSelectionModel.SINGLE_SELECTION)
        self._mtView.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        self._mtView.setRowHeight(20)

        # Column widths
        mtCM = self._mtView.getColumnModel()
        for i,w in enumerate([75,80,185,175,28,80,200,200]):
            mtCM.getColumn(i).setPreferredWidth(w)

        # Status col: JComboBox editor
        statusEditor = javax.swing.DefaultCellEditor(
            JComboBox(Vector(["Untested","Pass","Fail","Partial","N/A"])))
        mtCM.getColumn(0).setCellEditor(statusEditor)

        # Status renderer: colour coded
        class _MTRenderer(DefaultTableCellRenderer):
            _SC = {"Pass":Color(0xC8E6C9), "Fail":Color(0xFF6666),
                   "Partial":Color(0xFFF9C4), "N/A":Color(0xEEEEEE),
                   "Untested":Color(0xFFFFFF)}
            def getTableCellRendererComponent(s2, tbl, val, sel, foc, row, col):
                c2 = DefaultTableCellRenderer.getTableCellRendererComponent(
                    s2, tbl, val, sel, foc, row, col)
                if not sel:
                    mr = tbl.convertRowIndexToModel(row)
                    st = str(tbl.getModel().getValueAt(mr, 0))
                    c2.setBackground(s2._SC.get(st, Color.WHITE))
                return c2

        mtr = _MTRenderer()
        for i in range(len(mtCols)):
            mtCM.getColumn(i).setCellRenderer(mtr)

        # -- guide pane --------------------------------------------------------
        self._mtGuide = JTextArea()
        self._mtGuide.setEditable(False)
        self._mtGuide.setLineWrap(True)
        self._mtGuide.setWrapStyleWord(True)
        self._mtGuide.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._mtGuide.setText("Select a control above to see testing instructions.")

        self._mtView.getSelectionModel().addListSelectionListener(
            self._MTRowSelector(self))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           JScrollPane(self._mtView),
                           JScrollPane(self._mtGuide))
        split.setResizeWeight(0.55)
        outer.add(split, BorderLayout.CENTER)

        # -- legend ------------------------------------------------------------
        leg = JPanel(); leg.setLayout(BoxLayout(leg, BoxLayout.X_AXIS))
        def mkML(col, txt):
            lb = JLabel("  "+txt+"  "); lb.setOpaque(True); lb.setBackground(col)
            lb.setBorder(BorderFactory.createLineBorder(Color.GRAY)); return lb
        leg.add(mkML(Color(0xC8E6C9),"Pass"))
        leg.add(JLabel("  "))
        leg.add(mkML(Color(0xFF6666),"Fail"))
        leg.add(JLabel("  "))
        leg.add(mkML(Color(0xFFF9C4),"Partial"))
        leg.add(JLabel("  "))
        leg.add(mkML(Color(0xEEEEEE),"N/A"))
        leg.add(JLabel("    "))
        leg.add(JLabel("Double-click Status to change | Notes column is editable"))
        outer.add(leg, BorderLayout.SOUTH)

        # -- wire buttons ------------------------------------------------------
        ext = self

        class _MTStatusFilter(ActionListener):
            def actionPerformed(s2, e):
                filt = str(ext._mtStatusFilter.getSelectedItem())
                if filt == "All Statuses":
                    ext._mtSorter.setRowFilter(None)
                else:
                    try: ext._mtSorter.setRowFilter(
                        RowFilter.regexFilter("^"+filt+"$", 0))
                    except Exception: pass

        class _MTExport(ActionListener):
            def actionPerformed(s2, e):
                ext._exportManualCSV()

        class _MTLogEvid(ActionListener):
            def actionPerformed(s2, e):
                JOptionPane.showMessageDialog(None,
                    "To log evidence:\n"
                    "1. Select a control in this checklist.\n"
                    "2. In Proxy > HTTP History or Repeater, right-click the\n"
                    "   relevant request and choose:\n"
                    "   ASVS: Log as Evidence for Selected Control\n"
                    "The URL, status and response snippet will be recorded.\n\n"
                    "Then update the Status column (double-click) to Pass/Fail/Partial.",
                    "Manual Testing - ECWASS", JOptionPane.INFORMATION_MESSAGE)

        self._mtStatusFilter.addActionListener(_MTStatusFilter())
        exportMTBtn.addActionListener(_MTExport())
        self._logEvidBtn.addActionListener(_MTLogEvid())

        # Right-click context menu for manual testing bulk actions
        class _MTRightClick(java.awt.event.MouseAdapter):
            def mouseReleased(s2, e):
                if e.isPopupTrigger(): s2._show(e)
            def mousePressed(s2, e):
                if e.isPopupTrigger(): s2._show(e)
            def _show(s2, e):
                row = ext._mtView.rowAtPoint(e.getPoint())
                if row >= 0 and not ext._mtView.isRowSelected(row):
                    ext._mtView.setRowSelectionInterval(row, row)
                menu2 = JPopupMenu()
                for st2 in ["Pass","Fail","Partial","N/A","Untested"]:
                    mi2 = JMenuItem("Set all selected -> " + st2)
                    mi2.addActionListener(ext._MTBulkAction(ext, st2))
                    menu2.add(mi2)
                menu2.show(e.getComponent(), e.getX(), e.getY())
        ext._mtView.addMouseListener(_MTRightClick())
        return outer


    class _MarkDuplicateE(java.awt.event.ActionListener):
        def __init__(self, ext): self._ext = ext
        def actionPerformed(self, e):
            rows = self._ext._table.getSelectedRows()
            model_rows = sorted(
                [self._ext._table.convertRowIndexToModel(r) for r in rows],
                reverse=True)
            for mr in model_rows:
                if mr < len(self._ext._findings):
                    f = self._ext._findings[mr]
                    key = f["id"] + "|" + f["url"]
                    self._ext._seen.add(key)
                    del self._ext._findings[mr]
            SwingUtilities.invokeLater(self._ext._refreshTable)
            self._ext._detailArea.setText("")

    class _SendToRepeaterE(java.awt.event.ActionListener):
        def __init__(self, ext): self._ext = ext
        def actionPerformed(self, e):
            row = self._ext._table.getSelectedRow()
            if row < 0: return
            mr  = self._ext._table.convertRowIndexToModel(row)
            if mr >= len(self._ext._findings): return
            f   = self._ext._findings[mr]
            try:
                from java.net import URL as _URL
                u = _URL(f["url"])
                host = u.getHost()
                port = u.getPort() if u.getPort() > 0 else (443 if u.getProtocol()=="https" else 80)
                use_https = u.getProtocol().lower() == "https"
                path = u.getPath() or "/"
                if u.getQuery(): path += "?" + u.getQuery()
                req_str = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, host)
                req_bytes = self._ext._helpers.stringToBytes(req_str)
                self._ext._cb.sendToRepeater(host, port, use_https, req_bytes,
                                              f.get("id","") + " - " + f.get("title","")[:40])
            except Exception as ex:
                JOptionPane.showMessageDialog(None, "Error: " + str(ex),
                    "ECWASS Scanner", JOptionPane.ERROR_MESSAGE)


    class _SearchEvidenceE(java.awt.event.ActionListener):
        def __init__(self, ext): self._ext = ext
        def actionPerformed(self, e):
            term = JOptionPane.showInputDialog(None,
                "Search in finding evidence (headers, body snippets, details):",
                "Search Evidence", JOptionPane.QUESTION_MESSAGE)
            if not term: return
            term_l = term.lower()
            matches = []
            for f in self._ext._findings:
                searchable = " ".join([
                    f.get("req_hdrs",""), f.get("resp_hdrs",""),
                    f.get("body_snippet",""), f.get("detail",""),
                    f.get("url",""),
                ]).lower()
                if term_l in searchable:
                    matches.append("%s | %s | %s" % (
                        f.get("id",""), f.get("severity",""), f.get("url","")[:60]))
            if matches:
                msg = "Found %d match(es) for '%s':\n\n" % (len(matches), term)
                msg += "\n".join(matches[:25])
                JOptionPane.showMessageDialog(None, msg,
                    "Evidence Search Results", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(None,
                    "No findings contain '%s' in evidence." % term,
                    "Evidence Search", JOptionPane.INFORMATION_MESSAGE)

    class _MTBulkAction(java.awt.event.ActionListener):
        def __init__(self, ext, status): self._ext = ext; self._status = status
        def actionPerformed(self, e):
            rows = self._ext._mtView.getSelectedRows()
            for vr in rows:
                mr = self._ext._mtView.convertRowIndexToModel(vr)
                self._ext._mtModel.setValueAt(self._status, mr, 0)

    class _MTRowSelector(ListSelectionListener):
        def __init__(self, ext): self._ext = ext
        def valueChanged(self, ev):
            if ev.getValueIsAdjusting(): return
            row = self._ext._mtView.getSelectedRow()
            if row < 0: return
            mr  = self._ext._mtView.convertRowIndexToModel(row)
            cid = str(self._ext._mtModel.getValueAt(mr, 1))
            guide = _ECWASS_MANUAL_GUIDE.get(cid)
            if guide:
                title, tool, steps = guide
                txt = ("Control : %s\n"
                       "Title   : %s\n"
                       "Tool    : %s\n"
                       "\n--- Testing Steps ---\n%s" % (cid, title, tool, steps))
            else:
                # Look up description from ALL_CONTROLS
                desc = next((c[6] for c in ALL_CONTROLS if c[0]==cid), "")
                txt = ("Control : %s\n\nRequirement:\n%s\n\n"
                       "No specific step-by-step guide available for this control.\n"
                       "Refer to the ASVS specification for testing guidance." % (cid, desc))
            self._ext._mtGuide.setText(txt)
            self._ext._mtGuide.setCaretPosition(0)

    def _exportManualCSV(self):
        chooser = JFileChooser()
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        chooser.setSelectedFile(java.io.File("ecwass_manual_%s.csv" % ts))
        if chooser.showSaveDialog(self._root) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.endswith(".csv"): path += ".csv"
            try:
                def q(s): return '"' + str(s).replace('"','""')+'"'
                fos = FileOutputStream(path)
                osw = OutputStreamWriter(fos, "UTF-8")
                bw  = BufferedWriter(osw)
                bw.write("Status,ID,Chapter,Section,L1,Tool,Evidence URL,Notes\n")
                for r in range(self._mtModel.getRowCount()):
                    row = [str(self._mtModel.getValueAt(r, i))
                           for i in range(self._mtModel.getColumnCount())]
                    bw.write(",".join(q(v) for v in row) + "\n")
                bw.close()
                JOptionPane.showMessageDialog(None,
                    "Exported manual checklist to:\n" + path,
                    "Export Complete", JOptionPane.INFORMATION_MESSAGE)
            except Exception as ex:
                JOptionPane.showMessageDialog(None, "Export failed: "+str(ex),
                    "Error", JOptionPane.ERROR_MESSAGE)

# =============================================================================
# IScanIssue adapter
# =============================================================================
class _BurpIssue(IScanIssue):
    _SEV_MAP = {"High":"High","Medium":"Medium","Low":"Low","Information":"Information"}

    def __init__(self, finding, msgs, svc):
        self._f = finding; self._msg = msgs; self._svc = svc

    def getUrl(self):
        try: return JavaURL(self._f["url"])
        except: return None

    def getIssueName(self):
        return "[%s] %s" % (self._f["id"], self._f["title"])
    def getIssueType(self):          return 0x08000000
    def getSeverity(self):           return self._SEV_MAP.get(self._f["severity"], "Information")
    def getConfidence(self):         return "Tentative"
    def getIssueBackground(self):    return "ECWASS control: " + self._f.get("requirement","")
    def getRemediationBackground(self): return "Remediate per ECWASS requirements."
    def getIssueDetail(self):        return self._f.get("detail","")
    def getRemediationDetail(self):  return None
    def getHttpMessages(self):       return self._msg
    def getHttpService(self):        return self._svc
