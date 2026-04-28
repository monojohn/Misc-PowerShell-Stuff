# -*- coding: utf-8 -*-
# =============================================================================
# ASVS Web Application Security Scanner - Burp Suite Pro Extension
# Version 1.0 | Compatible: Burp Suite Pro 2023.x/2024.x + Jython 2.7.3+
# Covers all 345 ASVS controls from asvs-3.csv
# Selectable controls with L1/L2/L3 level filter | Auto-scan + Manual checklist
# =============================================================================

from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from burp import IContextMenuFactory, IHttpListener

from java.awt import BorderLayout, Color, Font
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from java.io import PrintWriter
from java.lang import Boolean as JBoolean
from java.net import URL as JavaURL
from java.util import ArrayList, Arrays, Vector
import javax.swing
from javax.swing import (BorderFactory, BoxLayout, JButton, JComboBox, JFileChooser,
                          JLabel, JMenuItem, JOptionPane, JPanel, JPopupMenu,
                          JScrollPane, JSplitPane, JTable, JTabbedPane,
                          JTextArea, JTextField, JToolBar, RowFilter,
                          SwingUtilities)
from javax.swing.event import ListSelectionListener, DocumentListener
from javax.swing.table import (DefaultTableCellRenderer, DefaultTableModel,
                                TableRowSorter)

import datetime
import re
import java.io
from java.io import FileOutputStream, OutputStreamWriter, BufferedWriter

ALL_CONTROLS = [
    ("ASVS-001","V1","Encoding and Sanitization","V1.1","Encoding and Sanitization Architecture","V1.1.1","Verify that input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in that form is expected, and that this is done before processing the input further, for example it is not performed after input validation or sanitization.",True,True,False,"Technical"),
    ("ASVS-002","V1","Encoding and Sanitization","V1.2","Injection Prevention","V1.2.1","Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure.",True,False,False,"Technical"),
    ("ASVS-003","V1","Encoding and Sanitization","V1.2","Injection Prevention","V1.2.2","Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:).",True,False,False,"Technical"),
    ("ASVS-004","V1","Encoding and Sanitization","V1.2","Injection Prevention","V1.2.3","Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection).",True,False,False,"Technical"),
    ("ASVS-005","V1","Encoding and Sanitization","V1.2","Injection Prevention","V1.2.4","Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures.",True,False,False,"Technical"),
    ("ASVS-006","V1","Encoding and Sanitization","V1.2","Injection Prevention","V1.2.5","Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding.",True,False,False,"Technical"),
    ("ASVS-007","V1","Encoding and Sanitization","V1.2","Injection Prevention","V1.2.6","Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented.",True,True,False,"Technical"),
    ("ASVS-008","V1","Encoding and Sanitization","V1.2","Injection Prevention","V1.2.7","Verify that the application is protected against XPath injection attacks by using query parameterization or precompiled queries.",True,True,False,"Technical"),
    ("ASVS-009","V1","Encoding and Sanitization","V1.2","Injection Prevention","V1.2.10","Verify that the application is protected against CSV and Formula Injection. The application must follow the escaping rules defined in RFC 4180 sections 2.6 and 2.7 when exporting CSV content. Additionally, when exporting to CSV or other spreadsheet formats (such as XLS, XLSX, or ODF), special characters (including '=', '+', '-', '@', '\\t' (tab), and '\\0' (null character)) must be escaped with a single quote if they appear as the first character in a field value.",True,True,True,"Technical"),
    ("ASVS-010","V1","Encoding and Sanitization","V1.3","Sanitization","V1.3.1","Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature.",True,False,False,"Technical"),
    ("ASVS-011","V1","Encoding and Sanitization","V1.3","Sanitization","V1.3.3","Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long.",True,True,False,"Technical"),
    ("ASVS-012","V1","Encoding and Sanitization","V1.3","Sanitization","V1.3.4","Verify that user-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only tags and attributes (such as draw graphics) that are safe for the application, e.g., do not contain scripts and foreignObject.",True,True,False,"Technical"),
    ("ASVS-013","V1","Encoding and Sanitization","V1.3","Sanitization","V1.3.5","Verify that the application sanitizes or disables user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar.",True,True,False,"Technical"),
    ("ASVS-014","V1","Encoding and Sanitization","V1.3","Sanitization","V1.3.6","Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service.",True,True,False,"Technical"),
    ("ASVS-015","V1","Encoding and Sanitization","V1.3","Sanitization","V1.3.7","Verify that the application protects against template injection attacks by not allowing templates to be built based on untrusted input. Where there is no alternative, any untrusted input being included dynamically during template creation must be sanitized or strictly validated.",True,True,False,"Technical"),
    ("ASVS-016","V1","Encoding and Sanitization","V1.3","Sanitization","V1.3.8","Verify that the application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface (JNDI) queries and that JNDI is configured securely to prevent JNDI injection attacks.",True,True,False,"Technical"),
    ("ASVS-017","V1","Encoding and Sanitization","V1.3","Sanitization","V1.3.9","Verify that the application sanitizes content before it is sent to memcache to prevent injection attacks.",True,True,False,"Technical"),
    ("ASVS-018","V1","Encoding and Sanitization","V1.3","Sanitization","V1.3.11","Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection.",True,True,False,"Technical"),
    ("ASVS-019","V1","Encoding and Sanitization","V1.3","Sanitization","V1.3.12","Verify that regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is sanitized to mitigate ReDoS or Runaway Regex attacks.",True,True,True,"Technical"),
    ("ASVS-020","V1","Encoding and Sanitization","V1.5","Safe Deserialization","V1.5.1","Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks.",True,False,False,"Technical"),
    ("ASVS-021","V1","Encoding and Sanitization","V1.5","Safe Deserialization","V1.5.2","Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input.",True,True,False,"Technical"),
    ("ASVS-022","V2","Validation and Business Logic","V2.2","Input Validation","V2.2.1","Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input.",True,False,False,"Technical"),
    ("ASVS-023","V2","Validation and Business Logic","V2.2","Input Validation","V2.2.2","Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control.",True,False,False,"Technical"),
    ("ASVS-024","V2","Validation and Business Logic","V2.3","Business Logic Security","V2.3.1","Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps.",True,False,False,"Technical"),
    ("ASVS-025","V2","Validation and Business Logic","V2.4","Anti-automation","V2.4.1","Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources.",True,True,False,"Technical"),
    ("ASVS-026","V2","Validation and Business Logic","V2.4","Anti-automation","V2.4.2","Verify that business logic flows require realistic human timing, preventing excessively rapid transaction submissions.",True,True,True,"Technical"),
    ("ASVS-027","V3","Web Frontend Security","V3.2","Unintended Content Interpretation","V3.2.1","Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field.",True,False,False,"Technical"),
    ("ASVS-028","V3","Web Frontend Security","V3.3","Cookie Setup","V3.3.1","Verify that cookies have the 'Secure' attribute set, and if the '\\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name.",True,False,False,"Technical"),
    ("ASVS-029","V3","Web Frontend Security","V3.3","Cookie Setup","V3.3.2","Verify that each cookie's 'SameSite' attribute value is set according to the purpose of the cookie, to limit exposure to user interface redress attacks and browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF).",True,True,False,"Technical"),
    ("ASVS-030","V3","Web Frontend Security","V3.3","Cookie Setup","V3.3.3","Verify that cookies have the '__Host-' prefix for the cookie name unless they are explicitly designed to be shared with other hosts.",True,True,False,"Technical"),
    ("ASVS-031","V3","Web Frontend Security","V3.3","Cookie Setup","V3.3.4","Verify that if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token), the cookie must have the 'HttpOnly' attribute set and the same value (e. g. session token) must only be transferred to the client via the 'Set-Cookie' header field.",True,True,False,"Technical"),
    ("ASVS-032","V3","Web Frontend Security","V3.3","Cookie Setup","V3.3.5","Verify that when the application writes a cookie, the cookie name and value length combined are not over 4096 bytes. Overly large cookies will not be stored by the browser and therefore not sent with requests, preventing the user from using application functionality which relies on that cookie.",True,True,True,"Technical"),
    ("ASVS-033","V3","Web Frontend Security","V3.4","Browser Security Mechanism Headers","V3.4.1","Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well.",True,False,False,"Technical"),
    ("ASVS-034","V3","Web Frontend Security","V3.4","Browser Security Mechanism Headers","V3.4.2","Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information.",True,False,False,"Technical"),
    ("ASVS-035","V3","Web Frontend Security","V3.4","Browser Security Mechanism Headers","V3.4.3","Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined.",True,True,False,"Technical"),
    ("ASVS-036","V3","Web Frontend Security","V3.4","Browser Security Mechanism Headers","V3.4.4","Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response's Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response's Content-Type is 'text/css'. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser.",True,True,False,"Technical"),
    ("ASVS-037","V3","Web Frontend Security","V3.4","Browser Security Mechanism Headers","V3.4.5","Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer' HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname.",True,True,False,"Technical"),
    ("ASVS-038","V3","Web Frontend Security","V3.4","Browser Security Mechanism Headers","V3.4.6","Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon.",True,True,False,"Technical"),
    ("ASVS-039","V3","Web Frontend Security","V3.4","Browser Security Mechanism Headers","V3.4.7","Verify that the Content-Security-Policy header field specifies a location to report violations.",True,True,True,"Technical"),
    ("ASVS-040","V3","Web Frontend Security","V3.4","Browser Security Mechanism Headers","V3.4.8","Verify that all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross---Origin---Opener---Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting.",True,True,True,"Technical"),
    ("ASVS-041","V3","Web Frontend Security","V3.5","Browser Origin Separation","V3.5.1","Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF).",True,False,False,"Technical"),
    ("ASVS-042","V3","Web Frontend Security","V3.5","Browser Origin Separation","V3.5.2","Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field.",True,False,False,"Technical"),
    ("ASVS-043","V3","Web Frontend Security","V3.5","Browser Origin Separation","V3.5.3","Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as 'safe' such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected.",True,False,False,"Technical"),
    ("ASVS-044","V3","Web Frontend Security","V3.5","Browser Origin Separation","V3.5.4","Verify that separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies.",True,True,False,"Technical"),
    ("ASVS-045","V3","Web Frontend Security","V3.5","Browser Origin Separation","V3.5.5","Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid.",True,True,False,"Technical"),
    ("ASVS-046","V3","Web Frontend Security","V3.5","Browser Origin Separation","V3.5.6","Verify that JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks.",True,True,True,"Technical"),
    ("ASVS-047","V3","Web Frontend Security","V3.5","Browser Origin Separation","V3.5.7","Verify that data requiring authorization is not included in script resource responses, like JavaScript files, to prevent Cross-Site Script Inclusion (XSSI) attacks.",True,True,True,"Technical"),
    ("ASVS-048","V3","Web Frontend Security","V3.5","Browser Origin Separation","V3.5.8","Verify that authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded on behalf of the user only when intended. This can be accomplished by strict validation of the Sec-Fetch-* HTTP request header fields to ensure that the request did not originate from an inappropriate cross-origin call, or by setting a restrictive Cross-Origin-Resource-Policy HTTP response header field to instruct the browser to block returned content.",True,True,True,"Technical"),
    ("ASVS-049","V3","Web Frontend Security","V3.6","External Resource Integrity","V3.6.1","Verify that client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on a Content Delivery Network) if the resource is static and versioned and Subresource Integrity (SRI) is used to validate the integrity of the asset. If this is not possible, there should be a documented security decision to justify this for each resource.",True,True,True,"Technical"),
    ("ASVS-050","V3","Web Frontend Security","V3.7","Other Browser Security Considerations","V3.7.1","Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets.",True,True,False,"Technical"),
    ("ASVS-051","V3","Web Frontend Security","V3.7","Other Browser Security Considerations","V3.7.2","Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist.",True,True,False,"Technical"),
    ("ASVS-052","V3","Web Frontend Security","V3.7","Other Browser Security Considerations","V3.7.3","Verify that the application shows a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation.",True,True,True,"Technical"),
    ("ASVS-053","V3","Web Frontend Security","V3.7","Other Browser Security Considerations","V3.7.4","Verify that the application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field.",True,True,True,"Technical"),
    ("ASVS-054","V4","API and Web Service","V4.1","Generic Web Service Security","V4.1.1","Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as 'text/', '/+xml' and '/xml'.",True,False,False,"Technical"),
    ("ASVS-055","V4","API and Web Service","V4.1","Generic Web Service Security","V4.1.2","Verify that only user-facing endpoints (intended for manual web-browser access) automatically redirect from HTTP to HTTPS, while other services or endpoints do not implement transparent redirects. This is to avoid a situation where a client is erroneously sending unencrypted HTTP requests, but since the requests are being automatically redirected to HTTPS, the leakage of sensitive data goes undiscovered.",True,True,False,"Technical"),
    ("ASVS-056","V4","API and Web Service","V4.1","Generic Web Service Security","V4.1.3","Verify that any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a web proxy, or a backend-for-frontend service, cannot be overridden by the end-user. Example headers might include X-Real-IP, X-Forwarded-*, or X-User-ID.",True,True,False,"Technical"),
    ("ASVS-057","V4","API and Web Service","V4.1","Generic Web Service Security","V4.1.4","Verify that only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during preflight requests) can be used and that unused methods are blocked.",True,True,True,"Technical"),
    ("ASVS-058","V4","API and Web Service","V4.2","HTTP Message Structure Validation","V4.2.1","Verify that all application components (including load balancers, firewalls, and application servers) determine boundaries of incoming HTTP messages using the appropriate mechanism for the HTTP version to prevent HTTP request smuggling. In HTTP/1.x, if a Transfer-Encoding header field is present, the Content-Length header must be ignored per RFC 2616. When using HTTP/2 or HTTP/3, if a Content-Length header field is present, the receiver must ensure that it is consistent with the length of the DATA frames.",True,True,False,"Technical"),
    ("ASVS-059","V4","API and Web Service","V4.2","HTTP Message Structure Validation","V4.2.2","Verify that when generating HTTP messages, the Content-Length header field does not conflict with the length of the content as determined by the framing of the HTTP protocol, in order to prevent request smuggling attacks.",True,True,True,"Technical"),
    ("ASVS-060","V4","API and Web Service","V4.2","HTTP Message Structure Validation","V4.2.3","Verify that the application does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields such as Transfer-Encoding to prevent response splitting and header injection attacks.",True,True,True,"Technical"),
    ("ASVS-061","V4","API and Web Service","V4.2","HTTP Message Structure Validation","V4.2.4","Verify that the application only accepts HTTP/2 and HTTP/3 requests where the header fields and values do not contain any CR (\\r), LF (\\n), or CRLF (\\r\\n) sequences, to prevent header injection attacks.",True,True,True,"Technical"),
    ("ASVS-062","V4","API and Web Service","V4.2","HTTP Message Structure Validation","V4.2.5","Verify that, if the application (backend or frontend) builds and sends requests, it uses validation, sanitization, or other mechanisms to avoid creating URIs (such as for API calls) or HTTP request header fields (such as Authorization or Cookie), which are too long to be accepted by the receiving component. This could cause a denial of service, such as when sending an overly long request (e.g., a long cookie header field), which results in the server always responding with an error status.",True,True,True,"Technical"),
    ("ASVS-063","V4","API and Web Service","V4.3","GraphQL","V4.3.1","Verify that a query allowlist, depth limiting, amount limiting, or query cost analysis is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries.",True,True,False,"Technical"),
    ("ASVS-064","V4","API and Web Service","V4.3","GraphQL","V4.3.2","Verify that GraphQL introspection queries are disabled in the production environment unless the GraphQL API is meant to be used by other parties.",True,True,False,"Technical"),
    ("ASVS-065","V4","API and Web Service","V4.4","WebSocket","V4.4.1","Verify that WebSocket over TLS (WSS) is used for all WebSocket connections.",True,False,False,"Technical"),
    ("ASVS-066","V4","API and Web Service","V4.4","WebSocket","V4.4.2","Verify that, during the initial HTTP WebSocket handshake, the Origin header field is checked against a list of origins allowed for the application.",True,True,False,"Technical"),
    ("ASVS-067","V4","API and Web Service","V4.4","WebSocket","V4.4.3","Verify that, if the application's standard session management cannot be used, dedicated tokens are being used for this, which comply with the relevant Session Management security requirements.",True,True,False,"Technical"),
    ("ASVS-068","V4","API and Web Service","V4.4","WebSocket","V4.4.4","Verify that dedicated WebSocket session management tokens are initially obtained or validated through the previously authenticated HTTPS session when transitioning an existing HTTPS session to a WebSocket channel.",True,True,False,"Technical"),
    ("ASVS-069","V5","File Handling","V5.2","File Upload and Content","V5.2.1","Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack.",True,False,False,"Technical"),
    ("ASVS-070","V5","File Handling","V5.2","File Upload and Content","V5.2.2","Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted.",True,False,False,"Technical"),
    ("ASVS-071","V5","File Handling","V5.2","File Upload and Content","V5.2.3","Verify that the application checks compressed files (e.g., zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file.",True,True,False,"Technical"),
    ("ASVS-072","V5","File Handling","V5.2","File Upload and Content","V5.2.4","Verify that a file size quota and maximum number of files per user are enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files.",True,True,True,"Technical"),
    ("ASVS-073","V5","File Handling","V5.2","File Upload and Content","V5.2.5","Verify that the application does not allow uploading compressed files containing symlinks unless this is specifically required (in which case it will be necessary to enforce an allowlist of the files that can be symlinked to).",True,True,True,"Technical"),
    ("ASVS-074","V5","File Handling","V5.2","File Upload and Content","V5.2.6","Verify that the application rejects uploaded images with a pixel size larger than the maximum allowed, to prevent pixel flood attacks.",True,True,True,"Technical"),
    ("ASVS-075","V5","File Handling","V5.3","File Storage","V5.3.1","Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request.",True,False,False,"Technical"),
    ("ASVS-076","V5","File Handling","V5.3","File Storage","V5.3.2","Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks.",True,False,False,"Technical"),
    ("ASVS-077","V5","File Handling","V5.4","File Download","V5.4.1","Verify that the application validates or ignores user-submitted filenames, including in a JSON, JSONP, or URL parameter and specifies a filename in the Content-Disposition header field in the response.",True,True,False,"Technical"),
    ("ASVS-078","V5","File Handling","V5.4","File Download","V5.4.2","Verify that file names served (e.g., in HTTP response header fields or email attachments) are encoded or sanitized (e.g., following RFC 6266) to preserve document structure and prevent injection attacks.",True,True,False,"Technical"),
    ("ASVS-079","V6","Authentication","V6.2","Password Security","V6.2.1","Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended.",True,False,False,"Technical"),
    ("ASVS-080","V6","Authentication","V6.2","Password Security","V6.2.2","Verify that users can change their password.",True,False,False,"Technical"),
    ("ASVS-081","V6","Authentication","V6.2","Password Security","V6.2.3","Verify that password change functionality requires the user's current and new password.",True,False,False,"Technical"),
    ("ASVS-082","V6","Authentication","V6.2","Password Security","V6.2.4","Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length.",True,False,False,"Technical"),
    ("ASVS-083","V6","Authentication","V6.2","Password Security","V6.2.5","Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters.",True,False,False,"Technical"),
    ("ASVS-084","V6","Authentication","V6.2","Password Security","V6.2.6","Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password.",True,False,False,"Technical"),
    ("ASVS-085","V6","Authentication","V6.2","Password Security","V6.2.7","Verify that 'paste' functionality, browser password helpers, and external password managers are permitted.",True,False,False,"Technical"),
    ("ASVS-086","V6","Authentication","V6.2","Password Security","V6.2.8","Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation.",True,False,False,"Technical"),
    ("ASVS-087","V6","Authentication","V6.2","Password Security","V6.2.9","Verify that passwords of at least 64 characters are permitted.",True,True,False,"Technical"),
    ("ASVS-088","V6","Authentication","V6.2","Password Security","V6.2.12","Verify that passwords submitted during account registration or password changes are checked against a set of breached passwords.",True,True,False,"Technical"),
    ("ASVS-089","V6","Authentication","V6.3","General Authentication Security","V6.3.3","Verify that either a multi-factor authentication mechanism or a combination of single-factor authentication mechanisms, must be used in order to access the application. For L3, one of the factors must be a hardware-based authentication mechanism which provides compromise and impersonation resistance against phishing attacks while verifying the intent to authenticate by requiring a user-initiated action (such as a button press on a FIDO hardware key or a mobile phone). Relaxing any of the considerations in this requirement requires a fully documented rationale and a comprehensive set of mitigating controls.",True,True,False,"Technical"),
    ("ASVS-090","V6","Authentication","V6.3","General Authentication Security","V6.3.4","Verify that, if the application includes multiple authentication pathways, there are no undocumented pathways and that security controls and authentication strength are enforced consistently.",True,True,False,"Technical"),
    ("ASVS-091","V6","Authentication","V6.3","General Authentication Security","V6.3.6","Verify that email is not used as either a single-factor or multi-factor authentication mechanism.",True,True,True,"Technical"),
    ("ASVS-092","V6","Authentication","V6.3","General Authentication Security","V6.3.7","Verify that users are notified after updates to authentication details, such as credential resets or modification of the username or email address.",True,True,True,"Technical"),
    ("ASVS-093","V6","Authentication","V6.3","General Authentication Security","V6.3.8","Verify that valid users cannot be deduced from failed authentication challenges, such as by basing on error messages, HTTP response codes, or different response times. Registration and forgot password functionality must also have this protection.",True,True,True,"Technical"),
    ("ASVS-094","V6","Authentication","V6.4","Authentication Factor Lifecycle and Recovery","V6.4.2","Verify that password hints or knowledge-based authentication (so-called 'secret questions') are not present.",True,False,False,"Technical"),
    ("ASVS-095","V6","Authentication","V6.4","Authentication Factor Lifecycle and Recovery","V6.4.3","Verify that a secure process for resetting a forgotten password is implemented, that does not bypass any enabled multi-factor authentication mechanisms.",True,True,False,"Technical"),
    ("ASVS-096","V6","Authentication","V6.5","General Multi-factor authentication requirements","V6.5.1","Verify that lookup secrets, out-of-band authentication requests or codes, and time-based one-time passwords (TOTPs) are only successfully usable once.",True,True,False,"Technical"),
    ("ASVS-097","V6","Authentication","V6.5","General Multi-factor authentication requirements","V6.5.4","Verify that lookup secrets and out-of-band authentication codes have a minimum of 20 bits of entropy (typically 4 random alphanumeric characters or 6 random digits is sufficient).",True,True,False,"Technical"),
    ("ASVS-098","V6","Authentication","V6.5","General Multi-factor authentication requirements","V6.5.5","Verify that out-of-band authentication requests, codes, or tokens, as well as time-based one-time passwords (TOTPs) have a defined lifetime. Out of band requests must have a maximum lifetime of 10 minutes and for TOTP a maximum lifetime of 30 seconds.",True,True,False,"Technical"),
    ("ASVS-099","V6","Authentication","V6.5","General Multi-factor authentication requirements","V6.5.6","Verify that any authentication factor (including physical devices) can be revoked in case of theft or other loss.",True,True,True,"Technical"),
    ("ASVS-100","V6","Authentication","V6.5","General Multi-factor authentication requirements","V6.5.7","Verify that biometric authentication mechanisms are only used as secondary factors together with either something you have or something you know.",True,True,True,"Technical"),
    ("ASVS-101","V6","Authentication","V6.6","Out-of-Band authentication mechanisms","V6.6.1","Verify that authentication mechanisms using the Public Switched Telephone Network (PSTN) to deliver One-time Passwords (OTPs) via phone or SMS are offered only when the phone number has previously been validated, alternate stronger methods (such as Time based One-time Passwords) are also offered, and the service provides information on their security risks to users. For L3 applications, phone and SMS must not be available as options.",True,True,False,"Technical"),
    ("ASVS-102","V6","Authentication","V6.6","Out-of-Band authentication mechanisms","V6.6.2","Verify that out-of-band authentication requests, codes, or tokens are bound to the original authentication request for which they were generated and are not usable for a previous or subsequent one.",True,True,False,"Technical"),
    ("ASVS-103","V6","Authentication","V6.6","Out-of-Band authentication mechanisms","V6.6.3","Verify that a code based out-of-band authentication mechanism is protected against brute force attacks by using rate limiting. Consider also using a code with at least 64 bits of entropy.",True,True,False,"Technical"),
    ("ASVS-104","V6","Authentication","V6.6","Out-of-Band authentication mechanisms","V6.6.4","Verify that, where push notifications are used for multi-factor authentication, rate limiting is used to prevent push bombing attacks. Number matching may also mitigate this risk.",True,True,True,"Technical"),
    ("ASVS-105","V6","Authentication","V6.8","Authentication with an Identity Provider","V6.8.1","Verify that, if the application supports multiple identity providers (IdPs), the user's identity cannot be spoofed via another supported identity provider (eg. by using the same user identifier). The standard mitigation would be for the application to register and identify the user using a combination of the IdP ID (serving as a namespace) and the user's ID in the IdP.",True,True,False,"Technical"),
    ("ASVS-106","V6","Authentication","V6.8","Authentication with an Identity Provider","V6.8.2","Verify that the presence and integrity of digital signatures on authentication assertions (for example on JWTs or SAML assertions) are always validated, rejecting any assertions that are unsigned or have invalid signatures.",True,True,False,"Technical"),
    ("ASVS-107","V6","Authentication","V6.8","Authentication with an Identity Provider","V6.8.4","Verify that, if an application uses a separate Identity Provider (IdP) and expects specific authentication strength, methods, or recentness for specific functions, the application verifies this using the information returned by the IdP. For example, if OIDC is used, this might be achieved by validating ID Token claims such as 'acr', 'amr', and 'auth_time' (if present). If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used (for example, single-factor authentication using username and password).",True,True,False,"Technical"),
    ("ASVS-108","V7","Session Management","V7.2","Fundamental Session Management Security","V7.2.1","Verify that the application performs all session token verification using a trusted, backend service.",True,False,False,"Technical"),
    ("ASVS-109","V7","Session Management","V7.2","Fundamental Session Management Security","V7.2.2","Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys.",True,False,False,"Technical"),
    ("ASVS-110","V7","Session Management","V7.2","Fundamental Session Management Security","V7.2.3","Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy.",True,False,False,"Technical"),
    ("ASVS-111","V7","Session Management","V7.2","Fundamental Session Management Security","V7.2.4","Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token.",True,False,False,"Technical"),
    ("ASVS-112","V7","Session Management","V7.3","Session Timeout","V7.3.1","Verify that there is an inactivity timeout such that re-authentication is enforced according to risk analysis and documented security decisions.",True,True,False,"Technical"),
    ("ASVS-113","V7","Session Management","V7.3","Session Timeout","V7.3.2","Verify that there is an absolute maximum session lifetime such that re-authentication is enforced according to risk analysis and documented security decisions.",True,True,False,"Technical"),
    ("ASVS-114","V7","Session Management","V7.4","Session Termination","V7.4.1","Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key.",True,False,False,"Technical"),
    ("ASVS-115","V7","Session Management","V7.4","Session Termination","V7.4.3","Verify that the application gives the option to terminate all other active sessions after a successful change or removal of any authentication factor (including password change via reset or recovery and, if present, an MFA settings update).",True,True,False,"Technical"),
    ("ASVS-116","V7","Session Management","V7.4","Session Termination","V7.4.4","Verify that all pages that require authentication have easy and visible access to logout functionality.",True,True,False,"Technical"),
    ("ASVS-117","V7","Session Management","V7.5","Defenses Against Session Abuse","V7.5.1","Verify that the application requires full re-authentication before allowing modifications to sensitive account attributes which may affect authentication such as email address, phone number, MFA configuration, or other information used in account recovery.",True,True,False,"Technical"),
    ("ASVS-118","V7","Session Management","V7.5","Defenses Against Session Abuse","V7.5.2","Verify that users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions.",True,True,False,"Technical"),
    ("ASVS-119","V7","Session Management","V7.5","Defenses Against Session Abuse","V7.5.3","Verify that the application requires further authentication with at least one factor or secondary verification before performing highly sensitive transactions or operations.",True,True,True,"Technical"),
    ("ASVS-120","V7","Session Management","V7.6","Federated Re-authentication","V7.6.1","Verify that session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as documented, requiring re-authentication as necessary such as when the maximum time between IdP authentication events is reached.",True,True,False,"Technical"),
    ("ASVS-121","V7","Session Management","V7.6","Federated Re-authentication","V7.6.2","Verify that creation of a session requires either the user's consent or an explicit action, preventing the creation of new application sessions without user interaction.",True,True,False,"Technical"),
    ("ASVS-122","V8","Authorization","V8.2","General Authorization Design","V8.2.2","Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA).",True,False,False,"Technical"),
    ("ASVS-123","V8","Authorization","V8.2","General Authorization Design","V8.2.3","Verify that the application ensures that field-level access is restricted to consumers with explicit permissions to specific fields to mitigate broken object property level authorization (BOPLA).",True,True,False,"Technical"),
    ("ASVS-124","V8","Authorization","V8.2","General Authorization Design","V8.2.4","Verify that adaptive security controls based on a consumer's environmental and contextual attributes (such as time of day, location, IP address, or device) are implemented for authentication and authorization decisions, as defined in the application's documentation. These controls must be applied when the consumer tries to start a new session and also during an existing session.",True,True,True,"Technical"),
    ("ASVS-125","V8","Authorization","V8.3","Operation Level Authorization","V8.3.1","Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript.",True,False,False,"Technical"),
    ("ASVS-126","V8","Authorization","V8.3","Operation Level Authorization","V8.3.2","Verify that changes to values on which authorization decisions are made are applied immediately. Where changes cannot be applied immediately, (such as when relying on data in self-contained tokens), there must be mitigating controls to alert when a consumer performs an action when they are no longer authorized to do so and revert the change. Note that this alternative would not mitigate information leakage.",True,True,True,"Technical"),
    ("ASVS-127","V9","Self-contained Tokens","V9.1","Token source and integrity","V9.1.1","Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents.",True,False,False,"Technical"),
    ("ASVS-128","V9","Self-contained Tokens","V9.1","Token source and integrity","V9.1.2","Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion.",True,False,False,"Technical"),
    ("ASVS-129","V9","Self-contained Tokens","V9.1","Token source and integrity","V9.1.3","Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources.",True,False,False,"Technical"),
    ("ASVS-130","V9","Self-contained Tokens","V9.2","Token content","V9.2.1","Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified.",True,False,False,"Technical"),
    ("ASVS-131","V9","Self-contained Tokens","V9.2","Token content","V9.2.2","Verify that the service receiving a token validates the token to be the correct type and is meant for the intended purpose before accepting the token's contents. For example, only access tokens can be accepted for authorization decisions and only ID Tokens can be used for proving user authentication.",True,True,False,"Technical"),
    ("ASVS-132","V9","Self-contained Tokens","V9.2","Token content","V9.2.3","Verify that the service only accepts tokens which are intended for use with that service (audience). For JWTs, this can be achieved by validating the 'aud' claim against an allowlist defined in the service.",True,True,False,"Technical"),
    ("ASVS-133","V9","Self-contained Tokens","V9.2","Token content","V9.2.4","Verify that, if a token issuer uses the same private key for issuing tokens to different audiences, the issued tokens contain an audience restriction that uniquely identifies the intended audiences. This will prevent a token from being reused with an unintended audience. If the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation.",True,True,False,"Technical"),
    ("ASVS-134","V10","OAuth and OIDC","V10.1","Generic OAuth and OIDC Security","V10.1.2","Verify that the client only accepts values from the authorization server (such as the authorization code or ID Token) if these values result from an authorization flow that was initiated by the same user agent session and transaction. This requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code_verifier', 'state' or OIDC 'nonce', are not guessable, are specific to the transaction, and are securely bound to both the client and the user agent session in which the transaction was started.",True,True,False,"Technical"),
    ("ASVS-135","V10","OAuth and OIDC","V10.2","OAuth Client","V10.2.1","Verify that, if the code flow is used, the OAuth client has protection against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF), which trigger token requests, either by using proof key for code exchange (PKCE) functionality or checking the 'state' parameter that was sent in the authorization request.",True,True,False,"Technical"),
    ("ASVS-136","V10","OAuth and OIDC","V10.2","OAuth Client","V10.2.2","Verify that, if the OAuth client can interact with more than one authorization server, it has a defense against mix-up attacks. For example, it could require that the authorization server return the 'iss' parameter value and validate it in the authorization response and the token response.",True,True,False,"Technical"),
    ("ASVS-137","V10","OAuth and OIDC","V10.2","OAuth Client","V10.2.3","Verify that the OAuth client only requests the required scopes (or other authorization parameters) in requests to the authorization server.",True,True,True,"Technical"),
    ("ASVS-138","V10","OAuth and OIDC","V10.3","OAuth Resource Server","V10.3.1","Verify that the resource server only accepts access tokens that are intended for use with that service (audience). The audience may be included in a structured access token (such as the 'aud' claim in JWT), or it can be checked using the token introspection endpoint.",True,True,False,"Technical"),
    ("ASVS-139","V10","OAuth and OIDC","V10.3","OAuth Resource Server","V10.3.2","Verify that the resource server enforces authorization decisions based on claims from the access token that define delegated authorization. If claims such as 'sub', 'scope', and 'authorization_details' are present, they must be part of the decision.",True,True,False,"Technical"),
    ("ASVS-140","V10","OAuth and OIDC","V10.3","OAuth Resource Server","V10.3.4","Verify that, if the resource server requires specific authentication strength, methods, or recentness, it verifies that the presented access token satisfies these constraints. For example, if present, using the OIDC 'acr', 'amr' and 'auth_time' claims respectively.",True,True,False,"Technical"),
    ("ASVS-141","V10","OAuth and OIDC","V10.3","OAuth Resource Server","V10.3.5","Verify that the resource server prevents the use of stolen access tokens or replay of access tokens (from unauthorized parties) by requiring sender-constrained access tokens, either Mutual TLS for OAuth 2 or OAuth 2 Demonstration of Proof of Possession (DPoP).",True,True,True,"Technical"),
    ("ASVS-142","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.1","Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison.",True,False,False,"Technical"),
    ("ASVS-143","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.2","Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code.",True,False,False,"Technical"),
    ("ASVS-144","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.3","Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications.",True,False,False,"Technical"),
    ("ASVS-145","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.4","Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used.",True,False,False,"Technical"),
    ("ASVS-146","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.5","Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided.",True,False,False,"Technical"),
    ("ASVS-147","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.6","Verify that, if the code grant is used, the authorization server mitigates authorization code interception attacks by requiring proof key for code exchange (PKCE). For authorization requests, the authorization server must require a valid 'code_challenge' value and must not accept a 'code_challenge_method' value of 'plain'. For a token request, it must require validation of the 'code_verifier' parameter.",True,True,False,"Technical"),
    ("ASVS-148","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.7","Verify that if the authorization server supports unauthenticated dynamic client registration, it mitigates the risk of malicious client applications. It must validate client metadata such as any registered URIs, ensure the user's consent, and warn the user before processing an authorization request with an untrusted client application.",True,True,False,"Technical"),
    ("ASVS-149","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.8","Verify that refresh tokens have an absolute expiration, including if sliding refresh token expiration is applied.",True,True,False,"Technical"),
    ("ASVS-150","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.9","Verify that refresh tokens and reference access tokens can be revoked by an authorized user using the authorization server user interface, to mitigate the risk of malicious clients or stolen tokens.",True,True,False,"Technical"),
    ("ASVS-151","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.10","Verify that confidential client is authenticated for client-to-authorized server backchannel requests such as token requests, pushed authorization requests (PAR), and token revocation requests.",True,True,False,"Technical"),
    ("ASVS-152","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.11","Verify that the authorization server configuration only assigns the required scopes to the OAuth client.",True,True,False,"Technical"),
    ("ASVS-153","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.12","Verify that for a given client, the authorization server only allows the 'response_mode' value that this client needs to use. For example, by having the authorization server validate this value against the expected values or by using pushed authorization request (PAR) or JWT-secured Authorization Request (JAR).",True,True,True,"Technical"),
    ("ASVS-154","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.13","Verify that grant type 'code' is always used together with pushed authorization requests (PAR).",True,True,True,"Technical"),
    ("ASVS-155","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.14","Verify that the authorization server issues only sender-constrained (Proof-of-Possession) access tokens, either with certificate-bound access tokens using mutual TLS (mTLS) or DPoP-bound access tokens (Demonstration of Proof of Possession).",True,True,True,"Technical"),
    ("ASVS-156","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.15","Verify that, for a server-side client (which is not executed on the end-user device), the authorization server ensures that the 'authorization_details' parameter value is from the client backend and that the user has not tampered with it. For example, by requiring the usage of pushed authorization request (PAR) or JWT-secured Authorization Request (JAR).",True,True,True,"Technical"),
    ("ASVS-157","V10","OAuth and OIDC","V10.4","OAuth Authorization Server","V10.4.16","Verify that the client is confidential and the authorization server requires the use of strong client authentication methods (based on public-key cryptography and resistant to replay attacks), such as mutual TLS ('tls_client_auth', 'self_signed_tls_client_auth') or private key JWT ('private_key_jwt').",True,True,True,"Technical"),
    ("ASVS-158","V10","OAuth and OIDC","V10.5","OIDC Client","V10.5.1","Verify that the client (as the relying party) mitigates ID Token replay attacks. For example, by ensuring that the 'nonce' claim in the ID Token matches the 'nonce' value sent in the authentication request to the OpenID Provider (in OAuth2 refereed to as the authorization request sent to the authorization server).",True,True,False,"Technical"),
    ("ASVS-159","V10","OAuth and OIDC","V10.5","OIDC Client","V10.5.3","Verify that the client rejects attempts by a malicious authorization server to impersonate another authorization server through authorization server metadata. The client must reject authorization server metadata if the issuer URL in the authorization server metadata does not exactly match the pre-configured issuer URL expected by the client.",True,True,False,"Technical"),
    ("ASVS-160","V10","OAuth and OIDC","V10.5","OIDC Client","V10.5.4","Verify that the client validates that the ID Token is intended to be used for that client (audience) by checking that the 'aud' claim from the token is equal to the 'client_id' value for the client.",True,True,False,"Technical"),
    ("ASVS-161","V10","OAuth and OIDC","V10.5","OIDC Client","V10.5.5","Verify that, when using OIDC back-channel logout, the relying party mitigates denial of service through forced logout and cross-JWT confusion in the logout flow. The client must verify that the logout token is correctly typed with a value of 'logout+jwt', contains the 'event' claim with the correct member name, and does not contain a 'nonce' claim. Note that it is also recommended to have a short expiration (e.g., 2 minutes).",True,True,False,"Technical"),
    ("ASVS-162","V10","OAuth and OIDC","V10.6","OpenID Provider","V10.6.1","Verify that the OpenID Provider only allows values 'code', 'ciba', 'id_token', or 'id_token code' for response mode. Note that 'code' is preferred over 'id_token code' (the OIDC Hybrid flow), and 'token' (any Implicit flow) must not be used.",True,True,False,"Technical"),
    ("ASVS-163","V10","OAuth and OIDC","V10.6","OpenID Provider","V10.6.2","Verify that the OpenID Provider mitigates denial of service through forced logout. By obtaining explicit confirmation from the end-user or, if present, validating parameters in the logout request (initiated by the relying party), such as the 'id_token_hint'.",True,True,False,"Technical"),
    ("ASVS-164","V10","OAuth and OIDC","V10.7","Consent Management","V10.7.1","Verify that the authorization server ensures that the user consents to each authorization request. If the identity of the client cannot be assured, the authorization server must always explicitly prompt the user for consent.",True,True,False,"Technical"),
    ("ASVS-165","V10","OAuth and OIDC","V10.7","Consent Management","V10.7.2","Verify that when the authorization server prompts for user consent, it presents sufficient and clear information about what is being consented to. When applicable, this should include the nature of the requested authorizations (typically based on scope, resource server, Rich Authorization Requests (RAR) authorization details), the identity of the authorized application, and the lifetime of these authorizations.",True,True,False,"Technical"),
    ("ASVS-166","V10","OAuth and OIDC","V10.7","Consent Management","V10.7.3","Verify that the user can review, modify, and revoke consents which the user has granted through the authorization server.",True,True,False,"Technical"),
    ("ASVS-167","V11","Cryptography","V11.2","Secure Cryptography Implementation","V11.2.5","Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable vulnerabilities, such as Padding Oracle attacks.",True,True,True,"Technical"),
    ("ASVS-168","V12","Secure Communication","V12.1","General TLS Security Guidance","V12.1.1","Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option.",True,False,False,"Technical"),
    ("ASVS-169","V12","Secure Communication","V12.1","General TLS Security Guidance","V12.1.2","Verify that only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3 applications must only support cipher suites which provide forward secrecy.",True,True,False,"Technical"),
    ("ASVS-170","V12","Secure Communication","V12.1","General TLS Security Guidance","V12.1.3","Verify that the application validates that mTLS client certificates are trusted before using the certificate identity for authentication or authorization.",True,True,False,"Technical"),
    ("ASVS-171","V12","Secure Communication","V12.2","HTTPS Communication with External Facing Services","V12.2.1","Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications.",True,False,False,"Questionnaire"),
    ("ASVS-172","V12","Secure Communication","V12.2","HTTPS Communication with External Facing Services","V12.2.2","Verify that external facing services use publicly trusted TLS certificates.",True,False,False,"Questionnaire"),
    ("ASVS-173","V13","Configuration","V13.2","Backend Communication Configuration","V13.2.3","Verify that if a credential has to be used for service authentication, the credential being used by the consumer is not a default credential (e.g., root/root or admin/admin).",True,True,False,"Technical"),
    ("ASVS-174","V13","Configuration","V13.2","Backend Communication Configuration","V13.2.5","Verify that the web or application server is configured with an allowlist of resources or systems to which the server can send requests or load data or files from.",True,True,False,"Technical"),
    ("ASVS-175","V13","Configuration","V13.4","Unintended Information Leakage","V13.4.1","Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself.",True,False,False,"Technical"),
    ("ASVS-176","V13","Configuration","V13.4","Unintended Information Leakage","V13.4.2","Verify that debug modes are disabled for all components in production environments to prevent exposure of debugging features and information leakage.",True,True,False,"Technical"),
    ("ASVS-177","V13","Configuration","V13.4","Unintended Information Leakage","V13.4.3","Verify that web servers do not expose directory listings to clients unless explicitly intended.",True,True,False,"Technical"),
    ("ASVS-178","V13","Configuration","V13.4","Unintended Information Leakage","V13.4.4","Verify that using the HTTP TRACE method is not supported in production environments, to avoid potential information leakage.",True,True,False,"Technical"),
    ("ASVS-179","V13","Configuration","V13.4","Unintended Information Leakage","V13.4.5","Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended.",True,True,False,"Technical"),
    ("ASVS-180","V13","Configuration","V13.4","Unintended Information Leakage","V13.4.6","Verify that the application does not expose detailed version information of backend components.",True,True,True,"Technical"),
    ("ASVS-181","V13","Configuration","V13.4","Unintended Information Leakage","V13.4.7","Verify that the web tier is configured to only serve files with specific file extensions to prevent unintentional information, configuration, and source code leakage.",True,True,True,"Technical"),
    ("ASVS-182","V14","Data Protection","V14.2","General Data Protection","V14.2.1","Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token.",True,False,False,"Technical"),
    ("ASVS-183","V14","Data Protection","V14.2","General Data Protection","V14.2.5","Verify that caching mechanisms are configured to only cache responses which have the expected content type for that resource and do not contain sensitive, dynamic content. The web server should return a 404 or 302 response when a non-existent file is accessed rather than returning a different, valid file. This should prevent Web Cache Deception attacks.",True,True,True,"Technical"),
    ("ASVS-184","V14","Data Protection","V14.2","General Data Protection","V14.2.8","Verify that sensitive information is removed from the metadata of user-submitted files unless storage is consented to by the user.",True,True,True,"Technical"),
    ("ASVS-185","V14","Data Protection","V14.3","Client-side Data Protection","V14.3.1","Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated.",True,False,False,"Technical"),
    ("ASVS-186","V14","Data Protection","V14.3","Client-side Data Protection","V14.3.2","Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers.",True,True,False,"Technical"),
    ("ASVS-187","V14","Data Protection","V14.3","Client-side Data Protection","V14.3.3","Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of session tokens.",True,True,False,"Technical"),
    ("ASVS-188","V15","Secure Coding and Architecture","V15.2","Security Architecture and Dependencies","V15.2.1","Verify that the application only contains components which have not breached the documented update and remediation time frames.",True,False,False,"Questionnaire"),
    ("ASVS-189","V15","Secure Coding and Architecture","V15.3","Defensive Coding","V15.3.1","Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users.",True,False,False,"Technical"),
    ("ASVS-190","V15","Secure Coding and Architecture","V15.3","Defensive Coding","V15.3.2","Verify that where the application backend makes calls to external URLs, it is configured to not follow redirects unless it is intended functionality.",True,True,False,"Technical"),
    ("ASVS-191","V15","Secure Coding and Architecture","V15.3","Defensive Coding","V15.3.3","Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action.",True,True,False,"Technical"),
    ("ASVS-192","V15","Secure Coding and Architecture","V15.3","Defensive Coding","V15.3.6","Verify that JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or Map() instead of object literals.",True,True,False,"Technical"),
    ("ASVS-193","V15","Secure Coding and Architecture","V15.3","Defensive Coding","V15.3.7","Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields).",True,True,False,"Technical"),
    ("ASVS-194","V15","Secure Coding and Architecture","V15.4","Safe Concurrency","V15.4.2","Verify that checks on a resource's state, such as its existence or permissions, and the actions that depend on them are performed as a single atomic operation to prevent time-of-check to time-of-use (TOCTOU) race conditions. For example, checking if a file exists before opening it, or verifying a user-s access before granting it.",True,True,True,"Technical"),
    ("ASVS-195","V16","Security Logging and Error Handling","V16.5","Error Handling","V16.5.1","Verify that a generic message is returned to the consumer when an unexpected or security-sensitive error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, secret keys, and tokens.",True,True,False,"Technical"),
    ("ASVS-196","V16","Security Logging and Error Handling","V16.5","Error Handling","V16.5.2","Verify that the application continues to operate securely when external resource access fails, for example, by using patterns such as circuit breakers or graceful degradation.",True,True,False,"Technical"),
    ("ASVS-197","V16","Security Logging and Error Handling","V16.5","Error Handling","V16.5.3","Verify that the application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic.",True,True,False,"Technical"),
    ("ASVS-198","V17","WebRTC","V17.1","TURN Server","V17.1.2","Verify that the Traversal Using Relays around NAT (TURN) service is not susceptible to resource exhaustion when legitimate users attempt to open a large number of ports on the TURN server.",True,True,True,"Technical"),
    ("ASVS-199","V17","WebRTC","V17.2","Media","V17.2.2","Verify that the media server is configured to use and support approved Datagram Transport Layer Security (DTLS) cipher suites and a secure protection profile for the DTLS Extension for establishing keys for the Secure Real-time Transport Protocol (DTLS-SRTP).",True,True,False,"Technical"),
    ("ASVS-200","V17","WebRTC","V17.2","Media","V17.2.3","Verify that Secure Real-time Transport Protocol (SRTP) authentication is checked at the media server to prevent Real-time Transport Protocol (RTP) injection attacks from leading to either a Denial of Service condition or audio or video media insertion into media streams.",True,True,False,"Technical"),
    ("ASVS-201","V17","WebRTC","V17.2","Media","V17.2.4","Verify that the media server is able to continue processing incoming media traffic when encountering malformed Secure Real-time Transport Protocol (SRTP) packets.",True,True,False,"Technical"),
    ("ASVS-202","V17","WebRTC","V17.2","Media","V17.2.5","Verify that the media server is able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users.",True,True,True,"Technical"),
    ("ASVS-203","V17","WebRTC","V17.2","Media","V17.2.6","Verify that the media server is not susceptible to the 'ClientHello' Race Condition vulnerability in Datagram Transport Layer Security (DTLS) by checking if the media server is publicly known to be vulnerable or by performing the race condition test.",True,True,True,"Technical"),
    ("ASVS-204","V17","WebRTC","V17.2","Media","V17.2.7","Verify that any audio or video recording mechanisms associated with the media server are able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users.",True,True,True,"Technical"),
    ("ASVS-205","V17","WebRTC","V17.2","Media","V17.2.8","Verify that the Datagram Transport Layer Security (DTLS) certificate is checked against the Session Description Protocol (SDP) fingerprint attribute, terminating the media stream if the check fails, to ensure the authenticity of the media stream.",True,True,True,"Technical"),
    ("ASVS-206","V17","WebRTC","V17.3","Signaling","V17.3.1","Verify that the signaling server is able to continue processing legitimate incoming signaling messages during a flood attack. This should be achieved by implementing rate limiting at the signaling level.",True,True,False,"Technical"),
    ("ASVS-207","V17","WebRTC","V17.3","Signaling","V17.3.2","Verify that the signaling server is able to continue processing legitimate signaling messages when encountering malformed signaling message that could cause a denial of service condition. This could include implementing input validation, safely handling integer overflows, preventing buffer overflows, and employing other robust error-handling techniques.",True,True,False,"Technical"),
    ("ASVS-208","V2","Validation and Business Logic","V2.2","Input Validation","V2.2.3","Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules.",True,True,False,"Questionnaire"),
    ("ASVS-209","V2","Validation and Business Logic","V2.3","Business Logic Security","V2.3.2","Verify that business logic limits are implemented per the application's documentation to avoid business logic flaws being exploited.",True,True,False,"Questionnaire"),
    ("ASVS-210","V2","Validation and Business Logic","V2.3","Business Logic Security","V2.3.4","Verify that business logic level locking mechanisms are used to ensure that limited quantity resources (such as theater seats or delivery slots) cannot be double-booked by manipulating the application's logic.",True,True,False,"Questionnaire"),
    ("ASVS-211","V5","File Handling","V5.3","File Storage","V5.3.3","Verify that server-side file processing, such as file decompression, ignores user-provided path information to prevent vulnerabilities such as zip slip.",True,True,True,"Questionnaire"),
    ("ASVS-212","V6","Authentication","V6.2","Password Security","V6.2.11","Verify that the documented list of context specific words is used to prevent easy to guess passwords being created.",True,True,False,"Questionnaire"),
    ("ASVS-213","V6","Authentication","V6.3","General Authentication Security","V6.3.1","Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation.",True,False,False,"Questionnaire"),
    ("ASVS-214","V6","Authentication","V6.3","General Authentication Security","V6.3.2","Verify that default user accounts (e.g., 'root', 'admin', or 'sa') are not present in the application or are disabled.",True,False,False,"Questionnaire"),
    ("ASVS-215","V6","Authentication","V6.4","Authentication Factor Lifecycle and Recovery","V6.4.1","Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password.",True,False,False,"Questionnaire"),
    ("ASVS-216","V6","Authentication","V6.7","Cryptographic authentication mechanism","V6.7.2","Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device.",True,True,True,"Questionnaire"),
    ("ASVS-217","V6","Authentication","V6.8","Authentication with an Identity Provider","V6.8.3","Verify that SAML assertions are uniquely processed and used only once within the validity period to prevent replay attacks.",True,True,False,"Questionnaire"),
    ("ASVS-218","V8","Authorization","V8.2","General Authorization Design","V8.2.1","Verify that the application ensures that function-level access is restricted to consumers with explicit permissions.",True,False,False,"Questionnaire"),
    ("ASVS-219","V8","Authorization","V8.4","Other Authorization Considerations","V8.4.1","Verify that multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect tenants with which they do not have permissions to interact.",True,True,False,"Questionnaire"),
    ("ASVS-220","V11","Cryptography","V11.3","Encryption Algorithms","V11.3.1","Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used.",True,False,False,"Questionnaire"),
    ("ASVS-221","V11","Cryptography","V11.5","Random Values","V11.5.1","Verify that all random numbers and strings which are intended to be non-guessable must be generated using a cryptographically secure pseudo-random number generator (CSPRNG) and have at least 128 bits of entropy. Note that UUIDs do not respect this condition.",True,True,False,"Questionnaire"),
    ("ASVS-222","V12","Secure Communication","V12.1","General TLS Security Guidance","V12.1.4","Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured.",True,True,True,"Questionnaire"),
    ("ASVS-223","V12","Secure Communication","V12.1","General TLS Security Guidance","V12.1.5","Verify that Encrypted Client Hello (ECH) is enabled in the application's TLS settings to prevent exposure of sensitive metadata, such as the Server Name Indication (SNI), during TLS handshake processes.",True,True,True,"Questionnaire"),
    ("ASVS-224","V14","Data Protection","V14.2","General Data Protection","V14.2.3","Verify that defined sensitive data is not sent to untrusted parties (e.g., user trackers) to prevent unwanted collection of data outside of the application's control.",True,True,False,"Questionnaire"),
    ("ASVS-225","V14","Data Protection","V14.2","General Data Protection","V14.2.6","Verify that the application only returns the minimum required sensitive data for the application's functionality. For example, only returning some of the digits of a credit card number and not the full number. If the complete data is required, it should be masked in the user interface unless the user specifically views it.",True,True,True,"Questionnaire"),
    ("ASVS-226","V15","Secure Coding and Architecture","V15.2","Security Architecture and Dependencies","V15.2.2","Verify that the application has implemented defenses against loss of availability due to functionality which is time-consuming or resource-demanding, based on the documented security decisions and strategies for this.",True,True,False,"Questionnaire"),
    ("ASVS-227","V15","Secure Coding and Architecture","V15.2","Security Architecture and Dependencies","V15.2.3","Verify that the production environment only includes functionality that is required for the application to function, and does not expose extraneous functionality such as test code, sample snippets, and development functionality.",True,True,False,"Questionnaire"),
    ("ASVS-228","V15","Secure Coding and Architecture","V15.3","Defensive Coding","V15.3.4","Verify that all proxying and middleware components transfer the user's original IP address correctly using trusted data fields that cannot be manipulated by the end user, and the application and web server use this correct value for logging and security decisions such as rate limiting, taking into account that even the original IP address may not be reliable due to dynamic IPs, VPNs, or corporate firewalls.",True,True,False,"Questionnaire"),
    ("ASVS-229","V17","WebRTC","V17.1","TURN Server","V17.1.1","Verify that the Traversal Using Relays around NAT (TURN) service only allows access to IP addresses that are not reserved for special purposes (e.g., internal networks, broadcast, loopback). Note that this applies to both IPv4 and IPv6 addresses.",True,True,False,"Questionnaire"),
    ("ASVS-230","V1","Encoding and Sanitization","V1.1","Encoding and Sanitization Architecture","V1.1.2","Verify that the application performs output encoding and escaping either as a final step before being used by the interpreter for which it is intended or by the interpreter itself.",True,True,False,"Questionnaire"),
    ("ASVS-231","V1","Encoding and Sanitization","V1.2","Injection Prevention","V1.2.8","Verify that LaTeX processors are configured securely (such as not using the '--shell-escape' flag) and an allowlist of commands is used to prevent LaTeX injection attacks.",True,True,False,"Questionnaire"),
    ("ASVS-232","V1","Encoding and Sanitization","V1.2","Injection Prevention","V1.2.9","Verify that the application escapes special characters in regular expressions (typically using a backslash) to prevent them from being misinterpreted as metacharacters.",True,True,False,"Questionnaire"),
    ("ASVS-233","V1","Encoding and Sanitization","V1.3","Sanitization","V1.3.2","Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed.",True,False,False,"Questionnaire"),
    ("ASVS-234","V1","Encoding and Sanitization","V1.3","Sanitization","V1.3.10","Verify that format strings which might resolve in an unexpected or malicious way when used are sanitized before being processed.",True,True,False,"Questionnaire"),
    ("ASVS-235","V1","Encoding and Sanitization","V1.4","Memory, String, and Unmanaged Code","V1.4.1","Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows.",True,True,False,"Questionnaire"),
    ("ASVS-236","V1","Encoding and Sanitization","V1.4","Memory, String, and Unmanaged Code","V1.4.2","Verify that sign, range, and input validation techniques are used to prevent integer overflows.",True,True,False,"Questionnaire"),
    ("ASVS-237","V1","Encoding and Sanitization","V1.4","Memory, String, and Unmanaged Code","V1.4.3","Verify that dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities.",True,True,False,"Questionnaire"),
    ("ASVS-238","V1","Encoding and Sanitization","V1.5","Safe Deserialization","V1.5.3","Verify that different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL parsers), perform parsing in a consistent way and use the same character encoding mechanism to avoid issues such as JSON Interoperability vulnerabilities or different URI or file parsing behavior being exploited in Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks.",True,True,True,"Questionnaire"),
    ("ASVS-239","V2","Validation and Business Logic","V2.1","Validation and Business Logic Documentation","V2.1.1","Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format.",True,False,False,"Questionnaire"),
    ("ASVS-240","V2","Validation and Business Logic","V2.1","Validation and Business Logic Documentation","V2.1.2","Verify that the application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match.",True,True,False,"Questionnaire"),
    ("ASVS-241","V2","Validation and Business Logic","V2.1","Validation and Business Logic Documentation","V2.1.3","Verify that expectations for business logic limits and validations are documented, including both per-user and globally across the application.",True,True,False,"Questionnaire"),
    ("ASVS-242","V2","Validation and Business Logic","V2.3","Business Logic Security","V2.3.3","Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state.",True,True,False,"Questionnaire"),
    ("ASVS-243","V2","Validation and Business Logic","V2.3","Business Logic Security","V2.3.5","Verify that high-value business logic flows require multi-user approval to prevent unauthorized or accidental actions. This could include but is not limited to large monetary transfers, contract approvals, access to classified information, or safety overrides in manufacturing.",True,True,True,"Questionnaire"),
    ("ASVS-244","V3","Web Frontend Security","V3.1","Web Frontend Security Documentation","V3.1.1","Verify that application documentation states the expected security features that browsers using the application must support (such as HTTPS, HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), and other relevant HTTP security mechanisms). It must also define how the application must behave when some of these features are not available (such as warning the user or blocking access).",True,True,True,"Questionnaire"),
    ("ASVS-245","V3","Web Frontend Security","V3.2","Unintended Content Interpretation","V3.2.2","Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript.",True,False,False,"Questionnaire"),
    ("ASVS-246","V3","Web Frontend Security","V3.2","Unintended Content Interpretation","V3.2.3","Verify that the application avoids DOM clobbering when using client-side JavaScript by employing explicit variable declarations, performing strict type checking, avoiding storing global variables on the document object, and implementing namespace isolation.",True,True,True,"Questionnaire"),
    ("ASVS-247","V3","Web Frontend Security","V3.7","Other Browser Security Considerations","V3.7.5","Verify that the application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features.",True,True,True,"Questionnaire"),
    ("ASVS-248","V4","API and Web Service","V4.1","Generic Web Service Security","V4.1.5","Verify that per-message digital signatures are used to provide additional assurance on top of transport protections for requests or transactions which are highly sensitive or which traverse a number of systems.",True,True,True,"Questionnaire"),
    ("ASVS-249","V5","File Handling","V5.1","File Handling Documentation","V5.1.1","Verify that the documentation defines the permitted file types, expected file extensions, and maximum size (including unpacked size) for each upload feature. Additionally, ensure that the documentation specifies how files are made safe for end-users to download and process, such as how the application behaves when a malicious file is detected.",True,True,False,"Questionnaire"),
    ("ASVS-250","V5","File Handling","V5.4","File Download","V5.4.3","Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known malicious content.",True,True,False,"Questionnaire"),
    ("ASVS-251","V6","Authentication","V6.1","Authentication Documentation","V6.1.1","Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout.",True,False,False,"Questionnaire"),
    ("ASVS-252","V6","Authentication","V6.1","Authentication Documentation","V6.1.2","Verify that a list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar.",True,True,False,"Questionnaire"),
    ("ASVS-253","V6","Authentication","V6.1","Authentication Documentation","V6.1.3","Verify that, if the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them.",True,True,False,"Questionnaire"),
    ("ASVS-254","V6","Authentication","V6.2","Password Security","V6.2.10","Verify that a user's password stays valid until it is discovered to be compromised or the user rotates it. The application must not require periodic credential rotation.",True,True,False,"Questionnaire"),
    ("ASVS-255","V6","Authentication","V6.3","General Authentication Security","V6.3.5","Verify that users are notified of suspicious authentication attempts (successful or unsuccessful). This may include authentication attempts from an unusual location or client, partially successful authentication (only one of multiple factors), an authentication attempt after a long period of inactivity or a successful authentication after several unsuccessful attempts.",True,True,True,"Questionnaire"),
    ("ASVS-256","V6","Authentication","V6.4","Authentication Factor Lifecycle and Recovery","V6.4.4","Verify that if a multi-factor authentication factor is lost, evidence of identity proofing is performed at the same level as during enrollment.",True,True,False,"Questionnaire"),
    ("ASVS-257","V6","Authentication","V6.4","Authentication Factor Lifecycle and Recovery","V6.4.5","Verify that renewal instructions for authentication mechanisms which expire are sent with enough time to be carried out before the old authentication mechanism expires, configuring automated reminders if necessary.",True,True,True,"Questionnaire"),
    ("ASVS-258","V6","Authentication","V6.4","Authentication Factor Lifecycle and Recovery","V6.4.6","Verify that administrative users can initiate the password reset process for the user, but that this does not allow them to change or choose the user's password. This prevents a situation where they know the user's password.",True,True,True,"Questionnaire"),
    ("ASVS-259","V6","Authentication","V6.5","General Multi-factor authentication requirements","V6.5.2","Verify that, when being stored in the application's backend, lookup secrets with less than 112 bits of entropy (19 random alphanumeric characters or 34 random digits) are hashed with an approved password storage hashing algorithm that incorporates a 32-bit random salt. A standard hash function can be used if the secret has 112 bits of entropy or more.",True,True,False,"Questionnaire"),
    ("ASVS-260","V6","Authentication","V6.5","General Multi-factor authentication requirements","V6.5.3","Verify that lookup secrets, out-of-band authentication code, and time-based one-time password seeds, are generated using a Cryptographically Secure Pseudorandom Number Generator (CSPRNG) to avoid predictable values.",True,True,False,"Questionnaire"),
    ("ASVS-261","V6","Authentication","V6.5","General Multi-factor authentication requirements","V6.5.8","Verify that time-based one-time passwords (TOTPs) are checked based on a time source from a trusted service and not from an untrusted or client provided time.",True,True,True,"Questionnaire"),
    ("ASVS-262","V6","Authentication","V6.7","Cryptographic authentication mechanism","V6.7.1","Verify that the certificates used to verify cryptographic authentication assertions are stored in a way protects them from modification.",True,True,True,"Questionnaire"),
    ("ASVS-263","V7","Session Management","V7.1","Session Management Documentation","V7.1.1","Verify that the user's session inactivity timeout and absolute maximum session lifetime are documented, are appropriate in combination with other controls, and that the documentation includes justification for any deviations from NIST SP 800-63B re-authentication requirements.",True,True,False,"Questionnaire"),
    ("ASVS-264","V7","Session Management","V7.1","Session Management Documentation","V7.1.2","Verify that the documentation defines how many concurrent (parallel) sessions are allowed for one account as well as the intended behaviors and actions to be taken when the maximum number of active sessions is reached.",True,True,False,"Questionnaire"),
    ("ASVS-265","V7","Session Management","V7.1","Session Management Documentation","V7.1.3","Verify that all systems that create and manage user sessions as part of a federated identity management ecosystem (such as SSO systems) are documented along with controls to coordinate session lifetimes, termination, and any other conditions that require re-authentication.",True,True,False,"Questionnaire"),
    ("ASVS-266","V7","Session Management","V7.4","Session Termination","V7.4.2","Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company).",True,False,False,"Questionnaire"),
    ("ASVS-267","V7","Session Management","V7.4","Session Termination","V7.4.5","Verify that application administrators are able to terminate active sessions for an individual user or for all users.",True,True,False,"Questionnaire"),
    ("ASVS-268","V8","Authorization","V8.1","Authorization Documentation","V8.1.1","Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes.",True,False,False,"Questionnaire"),
    ("ASVS-269","V8","Authorization","V8.1","Authorization Documentation","V8.1.2","Verify that authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status.",True,True,False,"Questionnaire"),
    ("ASVS-270","V8","Authorization","V8.1","Authorization Documentation","V8.1.3","Verify that the application's documentation defines the environmental and contextual attributes (including but not limited to, time of day, user location, IP address, or device) that are used in the application to make security decisions, including those pertaining to authentication and authorization.",True,True,True,"Questionnaire"),
    ("ASVS-271","V8","Authorization","V8.1","Authorization Documentation","V8.1.4","Verify that authentication and authorization documentation defines how environmental and contextual factors are used in decision-making, in addition to function-level, data-specific, and field-level authorization. This should include the attributes evaluated, thresholds for risk, and actions taken (e.g., allow, challenge, deny, step-up authentication).",True,True,True,"Questionnaire"),
    ("ASVS-272","V8","Authorization","V8.3","Operation Level Authorization","V8.3.3","Verify that access to an object is based on the originating subject's (e.g. consumer's) permissions, not on the permissions of any intermediary or service acting on their behalf. For example, if a consumer calls a web service using a self-contained token for authentication, and the service then requests data from a different service, the second service will use the consumer's token, rather than a machine-to-machine token from the first service, to make permission decisions.",True,True,True,"Questionnaire"),
    ("ASVS-273","V8","Authorization","V8.4","Other Authorization Considerations","V8.4.2","Verify that access to administrative interfaces incorporates multiple layers of security, including continuous consumer identity verification, device security posture assessment, and contextual risk analysis, ensuring that network location or trusted endpoints are not the sole factors for authorization even though they may reduce the likelihood of unauthorized access.",True,True,True,"Questionnaire"),
    ("ASVS-274","V10","OAuth and OIDC","V10.1","Generic OAuth and OIDC Security","V10.1.1","Verify that tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend pattern for browser-based JavaScript applications, access and refresh tokens shall only be accessible for the backend.",True,True,False,"Questionnaire"),
    ("ASVS-275","V10","OAuth and OIDC","V10.3","OAuth Resource Server","V10.3.3","Verify that if an access control decision requires identifying a unique user from an access token (JWT or related token introspection response), the resource server identifies the user from claims that cannot be reassigned to other users. Typically, it means using a combination of 'iss' and 'sub' claims.",True,True,False,"Questionnaire"),
    ("ASVS-276","V10","OAuth and OIDC","V10.5","OIDC Client","V10.5.2","Verify that the client uniquely identifies the user from ID Token claims, usually the 'sub' claim, which cannot be reassigned to other users (for the scope of an identity provider).",True,True,False,"Questionnaire"),
    ("ASVS-277","V11","Cryptography","V11.1","Cryptographic Inventory and Documentation","V11.1.1","Verify that there is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that follows a key management standard such as NIST SP 800-57. This should include ensuring that keys are not overshared (for example, with more than two entities for shared secrets and more than one entity for private keys).",True,True,False,"Questionnaire"),
    ("ASVS-278","V11","Cryptography","V11.1","Cryptographic Inventory and Documentation","V11.1.2","Verify that a cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application. It must also document where keys can and cannot be used in the system, and the types of data that can and cannot be protected using the keys.",True,True,False,"Questionnaire"),
    ("ASVS-279","V11","Cryptography","V11.1","Cryptographic Inventory and Documentation","V11.1.3","Verify that cryptographic discovery mechanisms are employed to identify all instances of cryptography in the system, including encryption, hashing, and signing operations.",True,True,True,"Questionnaire"),
    ("ASVS-280","V11","Cryptography","V11.1","Cryptographic Inventory and Documentation","V11.1.4","Verify that a cryptographic inventory is maintained. This must include a documented plan that outlines the migration path to new cryptographic standards, such as post-quantum cryptography, in order to react to future threats.",True,True,True,"Questionnaire"),
    ("ASVS-281","V11","Cryptography","V11.2","Secure Cryptography Implementation","V11.2.1","Verify that industry-validated implementations (including libraries and hardware-accelerated implementations) are used for cryptographic operations.",True,True,False,"Questionnaire"),
    ("ASVS-282","V11","Cryptography","V11.2","Secure Cryptography Implementation","V11.2.2","Verify that the application is designed with crypto agility such that random number, authenticated encryption, MAC, or hashing algorithms, key lengths, rounds, ciphers and modes can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks. Similarly, it must also be possible to replace keys and passwords and re-encrypt data. This will allow for seamless upgrades to post-quantum cryptography (PQC), once high-assurance implementations of approved PQC schemes or standards are widely available.",True,True,False,"Questionnaire"),
    ("ASVS-283","V11","Cryptography","V11.2","Secure Cryptography Implementation","V11.2.3","Verify that all cryptographic primitives utilize a minimum of 128-bits of security based on the algorithm, key size, and configuration. For example, a 256-bit ECC key provides roughly 128 bits of security where RSA requires a 3072-bit key to achieve 128 bits of security.",True,True,False,"Questionnaire"),
    ("ASVS-284","V11","Cryptography","V11.2","Secure Cryptography Implementation","V11.2.4","Verify that all cryptographic operations are constant-time, with no 'short-circuit' operations in comparisons, calculations, or returns, to avoid leaking information.",True,True,True,"Questionnaire"),
    ("ASVS-285","V11","Cryptography","V11.3","Encryption Algorithms","V11.3.2","Verify that only approved ciphers and modes such as AES with GCM are used.",True,False,False,"Questionnaire"),
    ("ASVS-286","V11","Cryptography","V11.3","Encryption Algorithms","V11.3.3","Verify that encrypted data is protected against unauthorized modification preferably by using an approved authenticated encryption method or by combining an approved encryption method with an approved MAC algorithm.",True,True,False,"Questionnaire"),
    ("ASVS-287","V11","Cryptography","V11.3","Encryption Algorithms","V11.3.4","Verify that nonces, initialization vectors, and other single-use numbers are not used for more than one encryption key and data-element pair. The method of generation must be appropriate for the algorithm being used.",True,True,True,"Questionnaire"),
    ("ASVS-288","V11","Cryptography","V11.3","Encryption Algorithms","V11.3.5","Verify that any combination of an encryption algorithm and a MAC algorithm is operating in encrypt-then-MAC mode.",True,True,True,"Questionnaire"),
    ("ASVS-289","V11","Cryptography","V11.4","Hashing and Hash-based Functions","V11.4.1","Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose.",True,False,False,"Questionnaire"),
    ("ASVS-290","V11","Cryptography","V11.4","Hashing and Hash-based Functions","V11.4.2","Verify that passwords are stored using an approved, computationally intensive, key derivation function (also known as a 'password hashing function'), with parameter settings configured based on current guidance. The settings should balance security and performance to make brute-force attacks sufficiently challenging for the required level of security.",True,True,False,"Questionnaire"),
    ("ASVS-291","V11","Cryptography","V11.4","Hashing and Hash-based Functions","V11.4.3","Verify that hash functions used in digital signatures, as part of data authentication or data integrity are collision resistant and have appropriate bit-lengths. If collision resistance is required, the output length must be at least 256 bits. If only resistance to second pre-image attacks is required, the output length must be at least 128 bits.",True,True,False,"Questionnaire"),
    ("ASVS-292","V11","Cryptography","V11.4","Hashing and Hash-based Functions","V11.4.4","Verify that the application uses approved key derivation functions with key stretching parameters when deriving secret keys from passwords. The parameters in use must balance security and performance to prevent brute-force attacks from compromising the resulting cryptographic key.",True,True,False,"Questionnaire"),
    ("ASVS-293","V11","Cryptography","V11.5","Random Values","V11.5.2","Verify that the random number generation mechanism in use is designed to work securely, even under heavy demand.",True,True,True,"Questionnaire"),
    ("ASVS-294","V11","Cryptography","V11.6","Public Key Cryptography","V11.6.1","Verify that only approved cryptographic algorithms and modes of operation are used for key generation and seeding, and digital signature generation and verification. Key generation algorithms must not generate insecure keys vulnerable to known attacks, for example, RSA keys which are vulnerable to Fermat factorization.",True,True,False,"Questionnaire"),
    ("ASVS-295","V11","Cryptography","V11.6","Public Key Cryptography","V11.6.2","Verify that approved cryptographic algorithms are used for key exchange (such as Diffie-Hellman) with a focus on ensuring that key exchange mechanisms use secure parameters. This will prevent attacks on the key establishment process which could lead to adversary-in-the-middle attacks or cryptographic breaks.",True,True,True,"Questionnaire"),
    ("ASVS-296","V11","Cryptography","V11.7","In-Use Data Cryptography","V11.7.1","Verify that full memory encryption is in use that protects sensitive data while it is in use, preventing access by unauthorized users or processes.",True,True,True,"Questionnaire"),
    ("ASVS-297","V11","Cryptography","V11.7","In-Use Data Cryptography","V11.7.2","Verify that data minimization ensures the minimal amount of data is exposed during processing, and ensure that data is encrypted immediately after use or as soon as feasible.",True,True,True,"Questionnaire"),
    ("ASVS-298","V12","Secure Communication","V12.3","General Service to Service Communication Security","V12.3.1","Verify that an encrypted protocol such as TLS is used for all inbound and outbound connections to and from the application, including monitoring systems, management tools, remote access and SSH, middleware, databases, mainframes, partner systems, or external APIs. The server must not fall back to insecure or unencrypted protocols.",True,True,False,"Questionnaire"),
    ("ASVS-299","V12","Secure Communication","V12.3","General Service to Service Communication Security","V12.3.2","Verify that TLS clients validate certificates received before communicating with a TLS server.",True,True,False,"Questionnaire"),
    ("ASVS-300","V12","Secure Communication","V12.3","General Service to Service Communication Security","V12.3.3","Verify that TLS or another appropriate transport encryption mechanism used for all connectivity between internal, HTTP-based services within the application, and does not fall back to insecure or unencrypted communications.",True,True,False,"Questionnaire"),
    ("ASVS-301","V12","Secure Communication","V12.3","General Service to Service Communication Security","V12.3.4","Verify that TLS connections between internal services use trusted certificates. Where internally generated or self-signed certificates are used, the consuming service must be configured to only trust specific internal CAs and specific self-signed certificates.",True,True,False,"Questionnaire"),
    ("ASVS-302","V12","Secure Communication","V12.3","General Service to Service Communication Security","V12.3.5","Verify that services communicating internally within a system (intra-service communications) use strong authentication to ensure that each endpoint is verified. Strong authentication methods, such as TLS client authentication, must be employed to ensure identity, using public-key infrastructure and mechanisms that are resistant to replay attacks. For microservice architectures, consider using a service mesh to simplify certificate management and enhance security.",True,True,True,"Questionnaire"),
    ("ASVS-303","V13","Configuration","V13.1","Configuration Documentation","V13.1.1","Verify that all communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect.",True,True,False,"Questionnaire"),
    ("ASVS-304","V13","Configuration","V13.1","Configuration Documentation","V13.1.2","Verify that for each service the application uses, the documentation defines the maximum number of concurrent connections (e.g., connection pool limits) and how the application behaves when that limit is reached, including any fallback or recovery mechanisms, to prevent denial of service conditions.",True,True,True,"Questionnaire"),
    ("ASVS-305","V13","Configuration","V13.1","Configuration Documentation","V13.1.3","Verify that the application documentation defines resource---management strategies for every external system or service it uses (e.g., databases, file handles, threads, HTTP connections). This should include resource---release procedures, timeout settings, failure handling, and where retry logic is implemented, specifying retry limits, delays, and back---off algorithms. For synchronous HTTP request---response operations it should mandate short timeouts and either disable retries or strictly limit retries to prevent cascading delays and resource exhaustion.",True,True,True,"Questionnaire"),
    ("ASVS-306","V13","Configuration","V13.1","Configuration Documentation","V13.1.4","Verify that the application's documentation defines the secrets that are critical for the security of the application and a schedule for rotating them, based on the organization's threat model and business requirements.",True,True,True,"Questionnaire"),
    ("ASVS-307","V13","Configuration","V13.2","Backend Communication Configuration","V13.2.1","Verify that communications between backend application components that don't support the application's standard user session mechanism, including APIs, middleware, and data layers, are authenticated. Authentication must use individual service accounts, short-term tokens, or certificate-based authentication and not unchanging credentials such as passwords, API keys, or shared accounts with privileged access.",True,True,False,"Questionnaire"),
    ("ASVS-308","V13","Configuration","V13.2","Backend Communication Configuration","V13.2.2","Verify that communications between backend application components, including local or operating system services, APIs, middleware, and data layers, are performed with accounts assigned the least necessary privileges.",True,True,False,"Questionnaire"),
    ("ASVS-309","V13","Configuration","V13.2","Backend Communication Configuration","V13.2.4","Verify that an allowlist is used to define the external resources or systems with which the application is permitted to communicate (e.g., for outbound requests, data loads, or file access). This allowlist can be implemented at the application layer, web server, firewall, or a combination of different layers.",True,True,False,"Questionnaire"),
    ("ASVS-310","V13","Configuration","V13.2","Backend Communication Configuration","V13.2.6","Verify that where the application connects to separate services, it follows the documented configuration for each connection, such as maximum parallel connections, behavior when maximum allowed connections is reached, connection timeouts, and retry strategies.",True,True,True,"Questionnaire"),
    ("ASVS-311","V13","Configuration","V13.3","Secret Management","V13.3.1","Verify that a secrets management solution, such as a key vault, is used to securely create, store, control access to, and destroy backend secrets. These could include passwords, key material, integrations with databases and third-party systems, keys and seeds for time-based tokens, other internal secrets, and API keys. Secrets must not be included in application source code or included in build artifacts. For an L3 application, this must involve a hardware-backed solution such as an HSM.",True,True,False,"Questionnaire"),
    ("ASVS-312","V13","Configuration","V13.3","Secret Management","V13.3.2","Verify that access to secret assets adheres to the principle of least privilege.",True,True,False,"Questionnaire"),
    ("ASVS-313","V13","Configuration","V13.3","Secret Management","V13.3.3","Verify that all cryptographic operations are performed using an isolated security module (such as a vault or hardware security module) to securely manage and protect key material from exposure outside of the security module.",True,True,True,"Questionnaire"),
    ("ASVS-314","V13","Configuration","V13.3","Secret Management","V13.3.4","Verify that secrets are configured to expire and be rotated based on the application's documentation.",True,True,True,"Questionnaire"),
    ("ASVS-315","V14","Data Protection","V14.1","Data Protection Documentation","V14.1.1","Verify that all sensitive data created and processed by the application has been identified and classified into protection levels. This includes data that is only encoded and therefore easily decoded, such as Base64 strings or the plaintext payload inside a JWT. Protection levels need to take into account any data protection and privacy regulations and standards which the application is required to comply with.",True,True,False,"Questionnaire"),
    ("ASVS-316","V14","Data Protection","V14.1","Data Protection Documentation","V14.1.2","Verify that all sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements.",True,True,False,"Questionnaire"),
    ("ASVS-317","V14","Data Protection","V14.2","General Data Protection","V14.2.2","Verify that the application prevents sensitive data from being cached in server components, such as load balancers and application caches, or ensures that the data is securely purged after use.",True,True,False,"Questionnaire"),
    ("ASVS-318","V14","Data Protection","V14.2","General Data Protection","V14.2.4","Verify that controls around sensitive data related to encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, privacy and privacy-enhancing technologies, are implemented as defined in the documentation for the specific data's protection level.",True,True,False,"Questionnaire"),
    ("ASVS-319","V14","Data Protection","V14.2","General Data Protection","V14.2.7","Verify that sensitive information is subject to data retention classification, ensuring that outdated or unnecessary data is deleted automatically, on a defined schedule, or as the situation requires.",True,True,True,"Questionnaire"),
    ("ASVS-320","V15","Secure Coding and Architecture","V15.1","Secure Coding and Architecture Documentation","V15.1.1","Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components.",True,False,False,"Questionnaire"),
    ("ASVS-321","V15","Secure Coding and Architecture","V15.1","Secure Coding and Architecture Documentation","V15.1.2","Verify that an inventory catalog, such as software bill of materials (SBOM), is maintained of all third-party libraries in use, including verifying that components come from pre-defined, trusted, and continually maintained repositories.",True,True,False,"Questionnaire"),
    ("ASVS-322","V15","Secure Coding and Architecture","V15.1","Secure Coding and Architecture Documentation","V15.1.3","Verify that the application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer's timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application.",True,True,False,"Questionnaire"),
    ("ASVS-323","V15","Secure Coding and Architecture","V15.1","Secure Coding and Architecture Documentation","V15.1.4","Verify that application documentation highlights third-party libraries which are considered to be 'risky components'.",True,True,True,"Questionnaire"),
    ("ASVS-324","V15","Secure Coding and Architecture","V15.1","Secure Coding and Architecture Documentation","V15.1.5","Verify that application documentation highlights parts of the application where 'dangerous functionality' is being used.",True,True,True,"Questionnaire"),
    ("ASVS-325","V15","Secure Coding and Architecture","V15.2","Security Architecture and Dependencies","V15.2.4","Verify that third-party components and all of their transitive dependencies are included from the expected repository, whether internally owned or an external source, and that there is no risk of a dependency confusion attack.",True,True,True,"Questionnaire"),
    ("ASVS-326","V15","Secure Coding and Architecture","V15.2","Security Architecture and Dependencies","V15.2.5","Verify that the application implements additional protections around parts of the application which are documented as containing 'dangerous functionality' or using third-party libraries considered to be 'risky components'. This could include techniques such as sandboxing, encapsulation, containerization or network level isolation to delay and deter attackers who compromise one part of an application from pivoting elsewhere in the application.",True,True,True,"Questionnaire"),
    ("ASVS-327","V15","Secure Coding and Architecture","V15.3","Defensive Coding","V15.3.5","Verify that the application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations. This is to avoid type juggling or type confusion vulnerabilities caused by the application code making an assumption about a variable type.",True,True,False,"Questionnaire"),
    ("ASVS-328","V15","Secure Coding and Architecture","V15.4","Safe Concurrency","V15.4.1","Verify that shared objects in multi-threaded code (such as caches, files, or in-memory objects accessed by multiple threads) are accessed safely by using thread-safe types and synchronization mechanisms like locks or semaphores to avoid race conditions and data corruption.",True,True,True,"Questionnaire"),
    ("ASVS-329","V15","Secure Coding and Architecture","V15.4","Safe Concurrency","V15.4.3","Verify that locks are used consistently to avoid threads getting stuck, whether by waiting on each other or retrying endlessly, and that locking logic stays within the code responsible for managing the resource to ensure locks cannot be inadvertently or maliciously modified by external classes or code.",True,True,True,"Questionnaire"),
    ("ASVS-330","V15","Secure Coding and Architecture","V15.4","Safe Concurrency","V15.4.4","Verify that resource allocation policies prevent thread starvation by ensuring fair access to resources, such as by leveraging thread pools, allowing lower-priority threads to proceed within a reasonable timeframe.",True,True,True,"Questionnaire"),
    ("ASVS-331","V16","Security Logging and Error Handling","V16.1","Security Logging Documentation","V16.1.1","Verify that an inventory exists documenting the logging performed at each layer of the application's technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept.",True,True,False,"Questionnaire"),
    ("ASVS-332","V16","Security Logging and Error Handling","V16.2","General Logging","V16.2.1","Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens.",True,True,False,"Questionnaire"),
    ("ASVS-333","V16","Security Logging and Error Handling","V16.2","General Logging","V16.2.2","Verify that time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions.",True,True,False,"Questionnaire"),
    ("ASVS-334","V16","Security Logging and Error Handling","V16.2","General Logging","V16.2.3","Verify that the application only stores or broadcasts logs to the files and services that are documented in the log inventory.",True,True,False,"Questionnaire"),
    ("ASVS-335","V16","Security Logging and Error Handling","V16.2","General Logging","V16.2.4","Verify that logs can be read and correlated by the log processor that is in use, preferably by using a common logging format.",True,True,False,"Questionnaire"),
    ("ASVS-336","V16","Security Logging and Error Handling","V16.2","General Logging","V16.2.5","Verify that when logging sensitive data, the application enforces logging based on the data's protection level. For example, it may not be allowed to log certain data, such as credentials or payment details. Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially.",True,True,False,"Questionnaire"),
    ("ASVS-337","V16","Security Logging and Error Handling","V16.3","Security Events","V16.3.1","Verify that all authentication operations are logged, including successful and unsuccessful attempts. Additional metadata, such as the type of authentication or factors used, should also be collected.",True,True,False,"Questionnaire"),
    ("ASVS-338","V16","Security Logging and Error Handling","V16.3","Security Events","V16.3.2","Verify that failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself).",True,True,False,"Questionnaire"),
    ("ASVS-339","V16","Security Logging and Error Handling","V16.3","Security Events","V16.3.3","Verify that the application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation.",True,True,False,"Questionnaire"),
    ("ASVS-340","V16","Security Logging and Error Handling","V16.3","Security Events","V16.3.4","Verify that the application logs unexpected errors and security control failures such as backend TLS failures.",True,True,False,"Questionnaire"),
    ("ASVS-341","V16","Security Logging and Error Handling","V16.4","Log Protection","V16.4.1","Verify that all logging components appropriately encode data to prevent log injection.",True,True,False,"Questionnaire"),
    ("ASVS-342","V16","Security Logging and Error Handling","V16.4","Log Protection","V16.4.2","Verify that logs are protected from unauthorized access and cannot be modified.",True,True,False,"Questionnaire"),
    ("ASVS-343","V16","Security Logging and Error Handling","V16.4","Log Protection","V16.4.3","Verify that logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised.",True,True,False,"Questionnaire"),
    ("ASVS-344","V16","Security Logging and Error Handling","V16.5","Error Handling","V16.5.4","Verify that a 'last resort' error handler is defined which will catch all unhandled exceptions. This is both to avoid losing error details that must go to log files and to ensure that an error does not take down the entire application process, leading to a loss of availability.",True,True,True,"Questionnaire"),
    ("ASVS-345","V17","WebRTC","V17.2","Media","V17.2.1","Verify that the key for the Datagram Transport Layer Security (DTLS) certificate is managed and protected based on the documented policy for management of cryptographic keys.",True,True,False,"Questionnaire"),
]


CONTROL_MAP = {c[0]: {
    "id": c[0], "chapter_id": c[1], "chapter_name": c[2],
    "section_id": c[3], "section_name": c[4],
    "requirement_id": c[5], "description": c[6],
    "l1": c[7], "l2": c[8], "l3": c[9], "assess_type": c[10]}
    for c in ALL_CONTROLS}


# =============================================================================
# Helpers
# =============================================================================
def _get_header(headers, name):
    n = name.lower()
    for h in headers:
        if isinstance(h, str) and ":" in h and h.lower().startswith(n + ":"):
            return h.split(":", 1)[1].strip()
    return None

def _has_header(headers, name):
    return _get_header(headers, name) is not None

def _get_status(resp_headers):
    for h in resp_headers:
        if isinstance(h, str) and h.startswith("HTTP/"):
            parts = h.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except Exception:
                    pass
    return 0

def _finding(asvs_id, title, severity, url, detail, body_snippet=""):
    ctrl = CONTROL_MAP.get(asvs_id, {})
    levels = []
    if ctrl.get("l1"): levels.append("L1")
    if ctrl.get("l2"): levels.append("L2")
    if ctrl.get("l3"): levels.append("L3")
    return {
        "ts":          datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "id":          asvs_id,
        "req_id":      ctrl.get("requirement_id", ""),
        "chapter":     ctrl.get("chapter_name", ""),
        "section":     ctrl.get("section_name", ""),
        "assess_type": ctrl.get("assess_type", "Technical"),
        "levels":      "/".join(levels) if levels else "",
        "title":       title,
        "severity":    severity,
        "url":         str(url),
        "detail":      detail,
        "description": ctrl.get("description", ""),
    }


# =============================================================================
# PASSIVE SCAN CHECK FUNCTIONS
# Each: fn(resp_hdrs, req_hdrs, body, url, messageInfo, helpers, callbacks) -> dict|None
# =============================================================================


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


# Snippet patterns - stored as constants so no inline escaping needed
_PAT_002  = r'(?:href|src|action)\s*=\s*["\']?\s*(?:javascript|data)\s*:'
_PAT_005  = r'you have an error in your sql|ORA-\d{5}|pg_query\(\)|ODBC SQL Server|quoted string'
_PAT_020  = r'<!DOCTYPE[^>]*\['
_PAT_050  = r'<object[^>]+classid|<applet\b|\.swf["\'\s>]|x-shockwave-flash|x-silverlight|vbscript\s*:'
_PAT_064  = r'__schema\s*\{|__type\s*\('
_PAT_065  = r'new\s+WebSocket\s*\(\s*["\']ws://'
_PAT_075  = r'(?:src|href)\s*=\s*["\']?(/[^"\'>\s]*(?:upload|files?|media))'
_PAT_079  = r'<input[^>]+type\s*=\s*["\']?text["\']?[^>]+name\s*=\s*["\']?(password|passwd|pwd)'
_PAT_093  = r'(wrong|invalid|incorrect)\s+password|(user|account|email).{0,30}(not found|does not exist|unknown)'
_PAT_176  = r'werkzeug\s+debugger|django\.debug|flask\s+debug|Traceback \(most recent call last\)|sf-toolbar|Fatal error'
_PAT_177  = r'Index of\s+/|directory\s+listing|Parent Directory'
_PAT_195  = r'Traceback \(most recent call last\)|Exception\b|mysql_|pg_|ORA-\d{5}|Fatal error|inetpub'


def chk_002(rh, qh, body, url, mi, h, cb):
    """ASVS-002/003: Dangerous URI protocol in links"""
    if re.search(r'(?:href|src|action)\s*=\s*["\'\']?\s*(?:javascript|data)\s*:',
                 body, re.IGNORECASE):
        return _finding("ASVS-002", "Dangerous URI Protocol in Page Links",
                        "High", url,
                        "Page contains href/src/action using javascript: or data: protocol.\n"
                        "Only safe URL protocols shall be permitted (ASVS V1.2.2).",
                        body_snippet=_body_snippet(body, _PAT_002))
    return None


def chk_005(rh, qh, body, url, mi, h, cb):
    """ASVS-005: SQL error messages in response"""
    if re.search(r'(you have an error in your sql syntax|warning.*mysql_|'
                 r'unclosed quotation mark|quoted string not properly terminated|'
                 r'ORA-\d{5}|Microsoft OLE DB Provider for SQL|'
                 r'ODBC SQL Server Driver|pg_query\(\))', body, re.IGNORECASE):
        return _finding("ASVS-005", "SQL Error Message Detected in Response",
                        "High", url,
                        "SQL error message found in response - indicates parameterized queries "
                        "may not be in use.\nDatabase queries shall use parameterized queries "
                        "or ORMs to prevent SQL injection (ASVS V1.2.4).",
                        body_snippet=_body_snippet(body, _PAT_005))
    return None


def chk_020(rh, qh, body, url, mi, h, cb):
    """ASVS-020: XXE via DOCTYPE declaration"""
    ct = _get_header(rh, "Content-Type") or ""
    if "xml" in ct.lower():
        if re.search(r'<!DOCTYPE[^>]*\[', body, re.IGNORECASE):
            return _finding("ASVS-020", "XML DOCTYPE Declaration Detected",
                            "High", url,
                            "Response contains an XML DOCTYPE declaration with internal subset.\n"
                            "XML parsers shall disable external entity resolution to prevent XXE "
                            "(ASVS V1.5.1).",
                        body_snippet=_body_snippet(body, _PAT_020))
    return None


def chk_028(rh, qh, body, url, mi, h, cb):
    """ASVS-028: Cookie missing Secure attribute"""
    missing = []
    for hdr in rh:
        if not isinstance(hdr, str):
            continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":", 1)[1]
            m = re.match(r'\s*([^=]+)=', val)
            name = m.group(1).strip() if m else "unknown"
            if "secure" not in val.lower():
                missing.append(name)
    if missing:
        return _finding("ASVS-028", "Cookie Missing Secure Attribute",
                        "High", url,
                        "Cookies without Secure:\n* " + "\n* ".join(missing) +
                        "\n\nCookies shall have the Secure attribute set (ASVS V3.3.1).")
    return None


def chk_029(rh, qh, body, url, mi, h, cb):
    """ASVS-029: Cookie missing SameSite"""
    missing = []
    for hdr in rh:
        if not isinstance(hdr, str):
            continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":", 1)[1]
            m = re.match(r'\s*([^=]+)=', val)
            name = m.group(1).strip() if m else "unknown"
            if "samesite" not in val.lower():
                missing.append(name)
    if missing:
        return _finding("ASVS-029", "Cookie Missing SameSite Attribute",
                        "Medium", url,
                        "Cookies without SameSite:\n* " + "\n* ".join(missing) +
                        "\n\nEach cookie SameSite attribute shall be set (ASVS V3.3.2).")
    return None


def chk_031(rh, qh, body, url, mi, h, cb):
    """ASVS-031: Cookie missing HttpOnly"""
    missing = []
    for hdr in rh:
        if not isinstance(hdr, str):
            continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":", 1)[1]
            m = re.match(r'\s*([^=]+)=', val)
            name = m.group(1).strip() if m else "unknown"
            if "httponly" not in val.lower():
                missing.append(name)
    if missing:
        return _finding("ASVS-031", "Cookie Missing HttpOnly Attribute",
                        "High", url,
                        "Cookies without HttpOnly:\n* " + "\n* ".join(missing) +
                        "\n\nSession cookies shall have HttpOnly set (ASVS V3.3.4).")
    return None


def chk_033(rh, qh, body, url, mi, h, cb):
    """ASVS-033: HSTS header"""
    if str(url.getProtocol()).lower() != "https":
        return None
    if _is_redirect(mi.getStatusCode() if hasattr(mi, "getStatusCode") else 0):
        return None
    hsts = _get_header(rh, "Strict-Transport-Security")
    if not hsts:
        return _finding("ASVS-033", "Missing HSTS Header",
                        "High", url,
                        "Strict-Transport-Security header is absent.\n"
                        "HSTS with max-age of at least 1 year shall be set (ASVS V3.4.1).")
    ma = re.search(r'max-age\s*=\s*(\d+)', hsts, re.IGNORECASE)
    if ma and int(ma.group(1)) < 31536000:
        return _finding("ASVS-033", "HSTS max-age Below 1 Year",
                        "Medium", url,
                        "HSTS max-age=%s. Minimum required is 31536000 (ASVS V3.4.1)." % ma.group(1))
    return None


def chk_034(rh, qh, body, url, mi, h, cb):
    """ASVS-034: CORS wildcard with sensitive data"""
    acao = _get_header(rh, "Access-Control-Allow-Origin")
    if acao and acao.strip() == "*":
        if re.search(r'(token|session|auth|key|secret|password|credential)',
                     body, re.IGNORECASE):
            return _finding("ASVS-034", "CORS Wildcard with Potentially Sensitive Response",
                            "High", url,
                            "Access-Control-Allow-Origin: * is set and response appears to contain "
                            "sensitive data.\nWhen CORS wildcard is used, responses must not "
                            "include sensitive information (ASVS V3.4.2).")
    return None


def chk_035(rh, qh, body, url, mi, h, cb):
    """ASVS-035: Content Security Policy"""
    if not _is_html(rh): return None
    csp = _get_header(rh, "Content-Security-Policy")
    if not csp:
        csp_ro = _get_header(rh, "Content-Security-Policy-Report-Only")
        if csp_ro:
            return _finding("ASVS-035", "CSP in Report-Only Mode (Not Enforced)",
                            "Medium", url,
                            "CSP-Report-Only present but CSP not enforced in production (ASVS V3.4.3).")
        return _finding("ASVS-035", "Missing Content-Security-Policy Header",
                        "High", url,
                        "No CSP header. CSP shall include at minimum object-src none and "
                        "base-uri none (ASVS V3.4.3).")
    weak = []
    if "'unsafe-inline'" in csp: weak.append("unsafe-inline allows inline script execution")
    if "'unsafe-eval'" in csp:   weak.append("unsafe-eval allows eval() and similar")
    if "object-src" not in csp:  weak.append("missing object-src directive (require: none)")
    if "base-uri" not in csp:    weak.append("missing base-uri directive (require: none)")
    if weak:
        return _finding("ASVS-035", "Content-Security-Policy Too Permissive",
                        "Medium", url,
                        "CSP missing required directives or uses unsafe ones:\n* " +
                        "\n* ".join(weak) + "\n\n(ASVS V3.4.3)")
    return None


def chk_036(rh, qh, body, url, mi, h, cb):
    """ASVS-036: X-Content-Type-Options: nosniff"""
    val = _get_header(rh, "X-Content-Type-Options")
    if not val or val.strip().lower() != "nosniff":
        return _finding("ASVS-036", "Missing X-Content-Type-Options: nosniff",
                        "Low", url,
                        "X-Content-Type-Options: nosniff is absent or not set correctly.\n"
                        "This header shall be present on all HTTP responses (ASVS V3.4.4).")
    return None


def chk_037(rh, qh, body, url, mi, h, cb):
    """ASVS-037: Referrer-Policy"""
    if not _is_html_or_json(rh): return None
    rp = _get_header(rh, "Referrer-Policy")
    if not rp:
        return _finding("ASVS-037", "Missing Referrer-Policy Header",
                        "Low", url,
                        "Referrer-Policy header is absent.\n"
                        "A referrer policy shall be set to prevent sensitive data leakage "
                        "via the Referer header (ASVS V3.4.5).")
    return None


def chk_038(rh, qh, body, url, mi, h, cb):
    """ASVS-038: CSP frame-ancestors clickjacking protection"""
    if not _is_html(rh): return None
    csp = _get_header(rh, "Content-Security-Policy") or ""
    xfo = _get_header(rh, "X-Frame-Options")
    if "frame-ancestors" not in csp.lower() and not xfo:
        return _finding("ASVS-038", "Missing Clickjacking Protection (frame-ancestors)",
                        "High", url,
                        "Neither CSP frame-ancestors directive nor X-Frame-Options is set.\n"
                        "The web application shall use CSP frame-ancestors on every response "
                        "(ASVS V3.4.6). Note: X-Frame-Options is considered obsolete.")
    return None


def chk_039(rh, qh, body, url, mi, h, cb):
    """ASVS-039: CSP report-uri / report-to directive"""
    if not _is_html(rh): return None
    csp = _get_header(rh, "Content-Security-Policy") or ""
    if csp and "report-uri" not in csp.lower() and "report-to" not in csp.lower():
        return _finding("ASVS-039", "CSP Missing Violation Reporting Directive",
                        "Low", url,
                        "CSP is present but has no report-uri or report-to directive.\n"
                        "CSP shall specify a location to report violations (ASVS V3.4.7).")
    return None


def chk_040(rh, qh, body, url, mi, h, cb):
    """ASVS-040: Cross-Origin-Opener-Policy"""
    ct = _get_header(rh, "Content-Type") or ""
    if "html" in ct.lower():
        coop = _get_header(rh, "Cross-Origin-Opener-Policy")
        if not coop:
            return _finding("ASVS-040", "Missing Cross-Origin-Opener-Policy Header",
                            "Medium", url,
                            "Cross-Origin-Opener-Policy header absent on HTML response.\n"
                            "Shall be set to same-origin or same-origin-allow-popups "
                            "to prevent tabnabbing attacks (ASVS V3.4.8).")
    return None


def chk_046(rh, qh, body, url, mi, h, cb):
    """ASVS-046: JSONP endpoint"""
    if re.search(r'[?&](callback|jsonp|cb|callbackfn)\s*=', str(url), re.IGNORECASE):
        return _finding("ASVS-046", "Potential JSONP Endpoint Detected",
                        "High", url,
                        "URL contains a JSONP callback parameter.\n"
                        "JSONP functionality must not be enabled to avoid XSSI attacks "
                        "(ASVS V3.5.6).")
    return None


def chk_050(rh, qh, body, url, mi, h, cb):
    """ASVS-050: Deprecated client-side technologies"""
    hits = []
    pats = [
        (r'<object[^>]+classid\s*=\s*["\'\']clsid:', "ActiveX"),
        (r'<applet\b',                                  "Java Applet"),
        (r'\.swf["\'\'\s>]',                              "Flash (SWF)"),
        (r'application/x-shockwave-flash',              "Flash embed"),
        (r'application/x-silverlight',                  "Silverlight"),
        (r'vbscript\s*:',                               "VBScript"),
    ]
    for pat, lbl in pats:
        if re.search(pat, body, re.IGNORECASE):
            hits.append(lbl)
    if hits:
        return _finding("ASVS-050", "Deprecated/Unsupported Client-Side Technology",
                        "High", url,
                        "Detected deprecated technology: " + ", ".join(hits) +
                        "\nOnly supported, secure client-side technologies shall be used "
                        "(ASVS V3.7.1).",
                        body_snippet=_body_snippet(body, _PAT_050))
    return None


def chk_051(rh, qh, body, url, mi, h, cb):
    """ASVS-051: Open redirect"""
    us = str(url)
    m = re.search(r'[?&](redirect|next|return|url|goto|redir|target|dest|destination)'
                  r'\s*=\s*([^&]+)', us, re.IGNORECASE)
    if m:
        try:
                        rval = urllib.unquote(str(m.group(2)))
        except Exception:
            rval = str(m.group(2))
        if rval.startswith("http") or rval.startswith("//"):
            return _finding("ASVS-051", "Potential Open Redirect",
                            "High", url,
                            "Redirect parameter '%s' points to external URL: %s\n"
                            "Redirects shall only go to destinations on an allowlist "
                            "(ASVS V3.7.2)." % (m.group(1), rval[:120]))
    return None


def chk_054(rh, qh, body, url, mi, h, cb):
    """ASVS-054: Content-Type on responses"""
    ct = _get_header(rh, "Content-Type")
    if not ct:
        return _finding("ASVS-054", "Missing Content-Type Header",
                        "Medium", url,
                        "HTTP response has no Content-Type header.\n"
                        "Every response with a body shall contain Content-Type "
                        "matching actual content (ASVS V4.1.1).")
    if ct.startswith("text/") and "charset" not in ct.lower():
        return _finding("ASVS-054", "Content-Type Missing Charset Parameter",
                        "Low", url,
                        "Content-Type '%s' missing charset.\n"
                        "A safe character encoding shall be specified (ASVS V4.1.1)." % ct)
    return None


def chk_057(rh, qh, body, url, mi, h, cb):
    """ASVS-057: Non-standard HTTP methods"""
    allow = _get_header(rh, "Allow") or ""
    dangerous = ["TRACE", "TRACK", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL"]
    found = [x for x in dangerous if re.search(r'\b' + x + r'\b', allow.upper())]
    if found:
        return _finding("ASVS-057", "Dangerous HTTP Methods Allowed",
                        "Medium", url,
                        "Allow header permits: " + ", ".join(found) +
                        "\nOnly explicitly supported HTTP methods shall be enabled (ASVS V4.1.4).")
    return None


def chk_064(rh, qh, body, url, mi, h, cb):
    """ASVS-064: GraphQL introspection in production"""
    if re.search(r'__schema\s*\{|__type\s*\(', body, re.IGNORECASE):
        return _finding("ASVS-064", "GraphQL Introspection Enabled",
                        "Medium", url,
                        "GraphQL introspection query response detected in production.\n"
                        "Introspection shall be disabled in production (ASVS V4.3.2).",
                        body_snippet=_body_snippet(body, _PAT_064))
    return None


def chk_065(rh, qh, body, url, mi, h, cb):
    """ASVS-065: Insecure WebSocket (ws://)"""
    if re.search(r'new\s+WebSocket\s*\(\s*["\'\']ws://', body, re.IGNORECASE):
        return _finding("ASVS-065", "Insecure WebSocket Connection (ws://)",
                        "High", url,
                        "Page contains WebSocket connection over ws:// (unencrypted).\n"
                        "WebSocket over TLS (WSS) shall be used for all WebSocket connections "
                        "(ASVS V4.4.1).",
                        body_snippet=_body_snippet(body, _PAT_065))
    return None


def chk_075(rh, qh, body, url, mi, h, cb):
    """ASVS-075: Uploaded file accessible from webroot"""
    us = str(url).lower()
    if "upload" in us or "file" in us:
        m = re.search(r'(?:src|href)\s*=\s*["\'\']?(/[^"\'\'>\s]*(?:upload|files?|media)[^"\'\'>\s]*)',
                      body, re.IGNORECASE)
        if m:
            return _finding("ASVS-075", "Uploaded File Accessible Under Webroot",
                            "High", url,
                            "Response references uploaded file at webroot path: " + m.group(1) +
                            "\nUploaded files shall not be stored or served directly from the "
                            "webroot (ASVS V5.3.1).",
                        body_snippet=_body_snippet(body, _PAT_075))
    return None


def chk_079(rh, qh, body, url, mi, h, cb):
    """ASVS-079/084: Password field not masked"""
    if re.search(r'<input[^>]+type\s*=\s*["\'\']?text["\'\']?[^>]+'
                 r'name\s*=\s*["\'\']?(password|passwd|pwd)["\'\']?',
                 body, re.IGNORECASE):
        return _finding("ASVS-079", "Password Field Using type=text",
                        "Medium", url,
                        "Password input field uses type='text' instead of type='password'.\n"
                        "Password input fields shall use type=password to mask entry (ASVS V6.2.6).",
                        body_snippet=_body_snippet(body, _PAT_079))
    return None


def chk_093(rh, qh, body, url, mi, h, cb):
    """ASVS-093: User enumeration via auth error messages"""
    us = str(url).lower()
    if not any(k in us for k in ["login","auth","signin","password","logon","register"]):
        return None
    hits = []
    if re.search(r'(wrong|invalid|incorrect)\s+password', body, re.IGNORECASE):
        hits.append("Response distinguishes wrong password from unknown account")
    if re.search(r'(user|account|email).{0,30}(not found|does not exist|unknown)',
                 body, re.IGNORECASE):
        hits.append("Response reveals account non-existence")
    if hits:
        return _finding("ASVS-093", "User Enumeration via Auth Error Messages",
                        "Medium", url,
                        "\n".join(["* " + x for x in hits]) +
                        "\n\nValid users shall not be deducible from failed auth responses "
                        "(ASVS V6.3.8).",
                        body_snippet=_body_snippet(body, _PAT_093))
    return None


def chk_110(rh, qh, body, url, mi, h, cb):
    """ASVS-110/111: Session token entropy"""
    hits = []
    for hdr in rh:
        if not isinstance(hdr, str):
            continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":", 1)[1]
            m = re.match(r'\s*([^=]+)=([^;]*)', val)
            if not m:
                continue
            name, value = m.group(1).strip(), m.group(2).strip()
            is_sess = any(s in name.lower() for s in
                         ["sess","sid","session","token","auth"])
            if is_sess and len(value) < 16:
                hits.append("Session cookie '%s' value too short (%d chars)" % (name, len(value)))
    if hits:
        return _finding("ASVS-110", "Session Token May Have Insufficient Entropy",
                        "High", url,
                        "\n".join(["* " + x for x in hits]) +
                        "\n\nReference tokens shall be generated using a CSPRNG with at least "
                        "128 bits of entropy (ASVS V7.2.3).")
    return None


def chk_114(rh, qh, body, url, mi, h, cb):
    """ASVS-114: Session cookie persists after browser close"""
    hits = []
    for hdr in rh:
        if not isinstance(hdr, str):
            continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":", 1)[1]
            m = re.match(r'\s*([^=]+)=', val)
            name = m.group(1).strip() if m else "unknown"
            is_sess = any(s in name.lower() for s in ["sess","sid","session","token"])
            if is_sess:
                if re.search(r'max-age\s*=\s*[1-9]', val, re.IGNORECASE) or \
                   re.search(r'expires\s*=', val, re.IGNORECASE):
                    hits.append("Session cookie '%s' has Max-Age/Expires" % name)
    if hits:
        return _finding("ASVS-114", "Session Cookie Has Persistent Expiry",
                        "Medium", url,
                        "\n".join(["* " + x for x in hits]) +
                        "\n\nSession tokens shall be invalidated when the session terminates "
                        "(ASVS V7.4.1).")
    return None


def chk_168(rh, qh, body, url, mi, h, cb):
    """ASVS-168: Deprecated TLS indicated in Server header"""
    srv = _get_header(rh, "Server") or ""
    if re.search(r'(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)', srv, re.IGNORECASE):
        return _finding("ASVS-168", "Deprecated TLS Version Indicated",
                        "High", url,
                        "Server header indicates deprecated TLS/SSL: " + srv +
                        "\nOnly TLS 1.2 and TLS 1.3 shall be used (ASVS V12.1.1).")
    return None


def chk_175(rh, qh, body, url, mi, h, cb):
    """ASVS-175: Source control metadata accessible"""
    us = str(url).lower()
    if re.search(r'/\.(git|svn|hg|bzr)(/|$)', us):
        return _finding("ASVS-175", "Source Control Metadata Folder Accessible",
                        "High", url,
                        "Request to source control metadata path: " + str(url) +
                        "\nSource control metadata shall not be accessible (ASVS V13.4.1).")
    return None


def chk_176(rh, qh, body, url, mi, h, cb):
    """ASVS-176: Debug mode enabled in production"""
    hits = []
    if re.search(r'(werkzeug\s+debugger|django\.debug|flask\s+debug)', body, re.IGNORECASE):
        hits.append("Python/Django/Flask debug UI detected")
    if _get_header(rh, "X-Debug-Token") or _get_header(rh, "X-Debug-Token-Link"):
        hits.append("Symfony Profiler debug headers present")
    if re.search(r'<div\s+id=["\'\']sf-toolbar', body, re.IGNORECASE):
        hits.append("Symfony debug toolbar detected")
    if re.search(r'Traceback \(most recent call last\)', body):
        hits.append("Python traceback in response body")
    if re.search(r'<b>(?:Fatal error|Warning)</b>.*?on line \d+', body):
        hits.append("PHP error/debug output in response")
    if hits:
        return _finding("ASVS-176", "Debug Mode Enabled in Production",
                        "High", url,
                        "\n".join(["* " + x for x in hits]) +
                        "\n\nDebug modes shall be disabled for all components in production "
                        "(ASVS V13.4.2).",
                        body_snippet=_body_snippet(body, _PAT_176))
    return None


def chk_177(rh, qh, body, url, mi, h, cb):
    """ASVS-177: Directory listing"""
    if not _is_html(rh): return None
    if (re.search(r'Index of\s+/', body) or
            re.search(r'<title>[^<]*directory\s+listing', body, re.IGNORECASE) or
            re.search(r'Parent Directory</a>', body)):
        return _finding("ASVS-177", "Directory Listing Exposed",
                        "High", url,
                        "Server exposes directory listing.\n"
                        "Directory listings shall not be exposed (ASVS V13.4.3).",
                        body_snippet=_body_snippet(body, _PAT_177))
    return None


def chk_178(rh, qh, body, url, mi, h, cb):
    """ASVS-178: HTTP TRACE method"""
    allow = _get_header(rh, "Allow") or ""
    if re.search(r'\bTRACE\b', allow.upper()):
        return _finding("ASVS-178", "HTTP TRACE Method Enabled",
                        "Medium", url,
                        "Allow header includes TRACE method.\n"
                        "HTTP TRACE must not be supported in production (ASVS V13.4.4).")
    return None


def chk_180(rh, qh, body, url, mi, h, cb):
    """ASVS-180: Version information in headers"""
    disc = []
    for hn in ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
               "X-Generator", "X-Runtime", "X-Version"]:
        val = _get_header(rh, hn)
        if val:
            disc.append("%s: %s" % (hn, val))
    if disc:
        return _finding("ASVS-180", "Backend Version Information Disclosed in Headers",
                        "Low", url,
                        "Response headers reveal server/framework version:\n* " +
                        "\n* ".join(disc) +
                        "\n\nDetailed version information shall not be exposed (ASVS V13.4.6).")
    return None


def chk_182(rh, qh, body, url, mi, h, cb):
    """ASVS-182: Sensitive data in URL query string"""
    us = str(url)
    params = us.split("?", 1)[1] if "?" in us else ""
    if not params:
        return None
    sensitive = ["password","passwd","pwd","secret","token","api_key",
                 "apikey","access_token","private_key","ssn","creditcard"]
    found = [k for k in sensitive
             if re.search(r'\b' + k + r'\b', params, re.IGNORECASE)]
    if found:
        return _finding("ASVS-182", "Sensitive Data in URL Query String",
                        "High", url,
                        "Sensitive parameter(s) in URL: " + ", ".join(found) +
                        "\n\nSensitive data shall only be sent in HTTP body or headers "
                        "(ASVS V14.2.1).")
    return None


def chk_186(rh, qh, body, url, mi, h, cb):
    """ASVS-186: Anti-caching headers for sensitive pages"""
    if _is_static_path(url): return None
    us = str(url).lower()
    if any(k in us for k in ["account","profile","admin","dashboard",
                              "payment","personal","private","secure"]):
        cc = _get_header(rh, "Cache-Control") or ""
        if "no-store" not in cc.lower():
            return _finding("ASVS-186", "Sensitive Page Missing Cache-Control: no-store",
                            "Medium", url,
                            "Sensitive page missing Cache-Control: no-store. Current: '%s'\n"
                            "Anti-caching headers shall prevent sensitive data caching in browsers "
                            "(ASVS V14.3.2)." % cc)
    return None


def chk_195(rh, qh, body, url, mi, h, cb):
    """ASVS-195: Generic error messages - no technical detail"""
    st = _get_status(rh)
    if st < 400:
        return None
    hits = []
    if re.search(r'Traceback \(most recent call last\)', body):
        hits.append("Python stack trace exposed")
    if re.search(r'[A-Za-z]+Exception\b', body):
        hits.append("Exception class name exposed")
    if re.search(r'(mysql_|pg_|mysqli_|ORA-\d{5}|SQLSTATE\[)', body, re.IGNORECASE):
        hits.append("Database error detail exposed")
    if re.search(r'(/home/[a-z]+/|/var/www/|C:\\\\inetpub)', body):
        hits.append("Server filesystem path exposed")
    if re.search(r'<b>(?:Fatal error|Warning)</b>.*?on line \d+', body):
        hits.append("PHP error output exposed")
    if hits:
        return _finding("ASVS-195", "Error Response Reveals Technical Details",
                        "Medium", url,
                        "HTTP %d response reveals internal details:\n* " % st +
                        "\n* ".join(hits) +
                        "\n\nA generic message shall be returned when unexpected errors occur "
                        "(ASVS V16.5.1).",
                        body_snippet=_body_snippet(body, _PAT_195))
    return None


# =============================================================================
# ADDITIONAL PASSIVE CHECKS (v2 additions)
# =============================================================================

def chk_perm_policy(rh, qh, body, url, mi, h, cb):
    """Permissions-Policy header missing"""
    if not _is_html(rh): return None
    pp = _get_header(rh, "Permissions-Policy")
    fp = _get_header(rh, "Feature-Policy")
    if not pp and not fp:
        return _finding("ASVS-035", "Missing Permissions-Policy Header",
                        "Low", url,
                        "Neither Permissions-Policy nor Feature-Policy header is set.\n"
                        "Permissions-Policy controls access to browser features such as camera, "
                        "microphone, and geolocation (ASVS V3.4.3 supplementary).")
    return None

def chk_sri(rh, qh, body, url, mi, h, cb):
    """ASVS-049: External scripts/styles missing Subresource Integrity"""
    if not _is_html(rh): return None
    missing = []
    # Look for external scripts/links missing integrity attribute
    # Split on < and check each potential tag fragment
    for frag in body.split("<"):
        tag = frag[:300].lower()
        if tag.startswith("script ") or tag.startswith("script>"):
            if "src=" in tag and "integrity" not in tag:
                idx = frag.lower().find("src=")
                sub = frag[idx+4:].lstrip(" \"'")
                if sub.startswith("http"):
                    end_idx = sub.find('"')
                    if end_idx < 0: end_idx = sub.find("'")
                    if end_idx < 0: end_idx = sub.find(" ")
                    if end_idx < 0: end_idx = min(80, len(sub))
                    missing.append(sub[:end_idx][:80])
        elif tag.startswith("link "):
            if "stylesheet" in tag and "href=" in tag and "integrity" not in tag:
                idx = frag.lower().find("href=")
                sub = frag[idx+5:].lstrip(" \"'")
                if sub.startswith("http"):
                    end_idx = sub.find('"')
                    if end_idx < 0: end_idx = sub.find("'")
                    if end_idx < 0: end_idx = sub.find(" ")
                    if end_idx < 0: end_idx = min(80, len(sub))
                    missing.append(sub[:end_idx][:80])
    if missing:
        return _finding("ASVS-049", "External Resource Missing Subresource Integrity",
                        "Medium", url,
                        "External resources without integrity= attribute:\n* " +
                        "\n* ".join(missing[:6]) +
                        "\n\nExternal assets shall use SRI to prevent supply-chain attacks (ASVS V3.6.1).",
                        body_snippet=missing[0] if missing else "")
    return None


def chk_sensitive_json(rh, qh, body, url, mi, h, cb):
    """Sensitive field names exposed in JSON API response"""
    ct = _get_header(rh, "Content-Type") or ""
    if "json" not in ct.lower(): return None
    hits = []
    sensitive_keys = [
        r'"password"\s*:', r'"passwd"\s*:', r'"secret"\s*:',
        r'"private_key"\s*:', r'"api_key"\s*:', r'"apikey"\s*:',
        r'"cvv"\s*:', r'"ssn"\s*:', r'"credit_card"\s*:',
        r'"access_token"\s*:', r'"refresh_token"\s*:',
    ]
    for pat in sensitive_keys:
        if re.search(pat, body, re.IGNORECASE):
            key = re.sub(r'[\\"\'\s:]', "", pat.split("\\")[0])
            hits.append(key.strip('"'))
    if hits:
        return _finding("ASVS-182", "Sensitive Field Names in JSON API Response",
                        "High", url,
                        "API response contains sensitive field names: " + ", ".join(hits) +
                        "\nSensitive data shall not be returned unnecessarily in API responses (ASVS V14.2.1).",
                        body_snippet=_body_snippet(body,
                            r'"(?:password|passwd|secret|private_key|api_key|cvv|ssn|access_token|refresh_token)"\s*:'))
    return None

def chk_jwt_in_body(rh, qh, body, url, mi, h, cb):
    """JWT token returned in response body"""
    ct = _get_header(rh, "Content-Type") or ""
    if "json" not in ct.lower() and "html" not in ct.lower(): return None
    # JWTs: three base64url parts separated by dots, first part decodes to {"alg":...}
    m = re.search(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', body)
    if m:
        snippet = m.group(0)[:60] + ("..." if len(m.group(0)) > 60 else "")
        return _finding("ASVS-127", "JWT Token Exposed in Response Body",
                        "Medium", url,
                        "A JWT token was found in the response body.\n"
                        "Tokens: " + snippet +
                        "\nTokens returned in body may be stored insecurely (localStorage, logs).\n"
                        "Prefer HttpOnly cookies for sensitive tokens (ASVS V9.1.1).",
                        body_snippet=_body_snippet(body,
                            r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'))
    return None

def chk_corp(rh, qh, body, url, mi, h, cb):
    """Cross-Origin-Resource-Policy header missing on sensitive responses"""
    ct = _get_header(rh, "Content-Type") or ""
    # Only flag API/JSON and HTML endpoints, not generic assets
    if not ("json" in ct.lower() or "html" in ct.lower()): return None
    corp = _get_header(rh, "Cross-Origin-Resource-Policy")
    if not corp:
        return _finding("ASVS-048", "Missing Cross-Origin-Resource-Policy Header",
                        "Low", url,
                        "Cross-Origin-Resource-Policy header is absent.\n"
                        "CORP prevents other origins from reading this response via <img> or fetch.\n"
                        "Recommended value: same-origin or same-site (ASVS V3.5.8).")
    return None

def chk_samesite_none(rh, qh, body, url, mi, h, cb):
    """Cookie SameSite=None without Secure flag"""
    issues = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":", 1)[1]
            m = re.match(r"\s*([^=]+)=", val)
            name = m.group(1).strip() if m else "unknown"
            if re.search(r"samesite\s*=\s*none", val, re.IGNORECASE):
                if "secure" not in val.lower():
                    issues.append("Cookie '%s': SameSite=None without Secure" % name)
    if issues:
        return _finding("ASVS-029", "Cookie SameSite=None Without Secure Flag",
                        "Medium", url,
                        "\n".join(issues) +
                        "\nSameSite=None is only meaningful when combined with the Secure flag.\n"
                        "Without Secure, SameSite=None provides no cross-site protection (ASVS V3.3.2).")
    return None

def chk_large_cookie(rh, qh, body, url, mi, h, cb):
    """Cookie value suspiciously large (> 512 bytes = likely serialised data)"""
    hits = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":", 1)[1]
            m = re.match(r"\s*([^=]+)=([^;]*)", val)
            if not m: continue
            name, value = m.group(1).strip(), m.group(2).strip()
            if len(value) > 512:
                hits.append("Cookie '%s': %d bytes" % (name, len(value)))
    if hits:
        return _finding("ASVS-028", "Unusually Large Cookie Value",
                        "Low", url,
                        "Large cookie values may indicate sensitive data stored client-side:\n* " +
                        "\n* ".join(hits) +
                        "\nSensitive data shall be stored server-side, not in cookies (ASVS V3.3).")
    return None


# =============================================================================
# ADDITIONAL CHECKS v3 -- new control detections
# =============================================================================
# New ASVS checks - v3 additions
# Each function: (rh, qh, body, url, mi, h, cb) -> dict|None

def chk_030(rh, qh, body, url, mi, h, cb):
    """ASVS-030: __Host- or __Secure- prefix missing on session cookies"""
    missing = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":", 1)[1]
            m = re.match(r'\s*([^=]+)=', val)
            if not m: continue
            name = m.group(1).strip()
            is_sess = any(s in name.lower() for s in
                          ["sess","sid","session","token","auth","jsessionid","phpsessid"])
            if is_sess and "secure" in val.lower():
                if not name.startswith("__Host-") and not name.startswith("__Secure-"):
                    missing.append(name)
    if missing:
        return _finding("ASVS-030", "Session Cookie Missing __Host- or __Secure- Prefix",
                        "Low", url,
                        "Session cookies without required prefix:\n* " + "\n* ".join(missing) +
                        "\n\nCookies shall use __Host- prefix (or at minimum __Secure-) "
                        "to prevent subdomain cookie injection (ASVS V3.3.3).")
    return None


def chk_032(rh, qh, body, url, mi, h, cb):
    """ASVS-032: Cookie name+value combined length > 4096 bytes"""
    over = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if hdr.lower().startswith("set-cookie:"):
            val = hdr.split(":", 1)[1]
            m = re.match(r'\s*([^=]+)=([^;]*)', val)
            if not m: continue
            name, value = m.group(1).strip(), m.group(2).strip()
            total = len(name) + len(value) + 1
            if total > 4096:
                over.append("Cookie '%s': %d bytes combined" % (name, total))
    if over:
        return _finding("ASVS-032", "Cookie Name+Value Exceeds 4096 Bytes",
                        "Medium", url,
                        "Oversized cookies may not be stored by browsers:\n* " +
                        "\n* ".join(over) +
                        "\n\nCookie name and value combined must not exceed 4096 bytes (ASVS V3.3.5).")
    return None


def chk_055(rh, qh, body, url, mi, h, cb):
    """ASVS-055: Transparent HTTP->HTTPS redirect on non-browser API endpoints"""
    st = _get_status(rh)
    if str(url.getProtocol()).lower() != "http": return None
    if st not in [301, 302, 307, 308]: return None
    us = str(url.getPath()).lower()
    api_paths = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/",
                 "/service/", "/services/", "/rpc/", "/ws/", "/grpc/"]
    if any(us.startswith(p) or us == p.rstrip("/") for p in api_paths):
        loc = _get_header(rh, "Location") or ""
        if loc.startswith("https://"):
            return _finding("ASVS-055", "API Endpoint Silently Redirects HTTP to HTTPS",
                            "Medium", url,
                            "API path '%s' responds to HTTP with %d redirect to HTTPS.\n"
                            "Non-browser API endpoints should not transparently redirect - "
                            "clients may have already sent credentials over HTTP (ASVS V4.1.2)."
                            % (us, st))
    return None


def chk_085(rh, qh, body, url, mi, h, cb):
    """ASVS-085: Paste disabled on password fields"""
    if not _is_html(rh): return None
    if re.search(r'<input[^>]+type\s*=\s*["\']?password["\']?[^>]+onpaste\s*=\s*["\'][^"\']*return\s+false',
                 body, re.IGNORECASE):
        return _finding("ASVS-085", "Paste Disabled on Password Field",
                        "Low", url,
                        "Password input has onpaste='return false' blocking paste.\n"
                        "Paste functionality, browser password helpers, and external password "
                        "managers shall be permitted (ASVS V6.2.7).",
                        body_snippet=_body_snippet(body,
                            r'<input[^>]+type\s*=\s*["\']?password["\']?[^>]+onpaste'))
    return None


def chk_094(rh, qh, body, url, mi, h, cb):
    """ASVS-094: Secret/knowledge-based questions in forms"""
    if not _is_html(rh): return None
    patterns = [
        r"mother.{0,10}(maiden|birth)",
        r"pet.{0,10}name",
        r"first.{0,10}(school|car|pet|teacher|job)",
        r"secret.{0,10}question",
        r"security.{0,10}question",
        r"name.{0,10}your.{0,10}(mother|father|pet|school)",
        r"childhood.{0,10}(friend|nickname|street|city)",
    ]
    for pat in patterns:
        if re.search(pat, body, re.IGNORECASE):
            return _finding("ASVS-094", "Knowledge-Based Authentication Question Detected",
                            "Medium", url,
                            "Page contains what appears to be a knowledge-based security question.\n"
                            "Password hints or knowledge-based authentication (secret questions) "
                            "shall not be used (ASVS V6.4.2).",
                            body_snippet=_body_snippet(body, pat))
    return None


def chk_109(rh, qh, body, url, mi, h, cb):
    """ASVS-109: Static/non-JWT Bearer token as session"""
    auth = _get_header(qh, "Authorization") or ""
    if not auth.lower().startswith("bearer "): return None
    token = auth[7:].strip()
    # A JWT has 3 base64url sections separated by dots
    if not re.match(r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', token):
        # Not a JWT - check if it looks like a static API key (short, no structure)
        if len(token) < 64 and "." not in token:
            return _finding("ASVS-109", "Possible Static API Key Used as Bearer Token",
                            "Medium", url,
                            "Authorization: Bearer token does not appear to be a JWT and is "
                            "short (%d chars). Static API keys shall not be used for session "
                            "management - dynamically generated tokens shall be used instead "
                            "(ASVS V7.2.2)." % len(token))
    return None


def chk_116(rh, qh, body, url, mi, h, cb):
    """ASVS-116: No logout link visible on authenticated HTML pages"""
    if not _is_html(rh): return None
    # Only check if request carries a session cookie
    has_session = False
    for hdr in qh:
        if isinstance(hdr, str) and hdr.lower().startswith("cookie:"):
            cv = hdr.lower()
            if any(s in cv for s in ["session","sess","sid","token","auth","jsessionid"]):
                has_session = True
                break
    if not has_session: return None
    # Skip non-authenticated paths
    us = str(url.getPath()).lower()
    if any(k in us for k in ["login","signin","logout","register","forgot","reset",
                               "static","assets","api",".js",".css"]):
        return None
    has_logout = re.search(
        r'href\s*=\s*["\'][^"\']*(?:logout|signout|log-out|sign-out)[^"\']*["\']',
        body, re.IGNORECASE)
    if not has_logout:
        return _finding("ASVS-116", "No Logout Link Found on Authenticated Page",
                        "Low", url,
                        "An authenticated page (session cookie present) does not appear to "
                        "contain a visible logout/signout link.\n"
                        "All pages requiring authentication shall have easy access to logout "
                        "(ASVS V7.4.4).")
    return None


def chk_127_alg(rh, qh, body, url, mi, h, cb):
    """ASVS-127/128: JWT with alg:none or weak algorithm in response body"""
    import base64
    ct = _get_header(rh, "Content-Type") or ""
    if "json" not in ct.lower() and "html" not in ct.lower(): return None
    for m in re.finditer(r'eyJ[A-Za-z0-9_-]+', body):
        token_start = m.start()
        # Check it's a full JWT (3 parts)
        rest = body[token_start:]
        parts = rest.split(".")
        if len(parts) < 2: continue
        try:
            header_b64 = parts[0]
            # Add padding
            header_b64 += "=" * (4 - len(header_b64) % 4)
            header_json = base64.urlsafe_b64decode(header_b64).lower()
            if b'"alg"' in header_json:
                if b'"none"' in header_json or b"'none'" in header_json:
                    return _finding("ASVS-128", "JWT with alg:none Detected in Response",
                                    "High", url,
                                    "Response contains a JWT token using alg:none which disables "
                                    "signature verification.\n"
                                    "Only algorithms on an allowlist shall be used; the None "
                                    "algorithm must not be permitted (ASVS V9.1.2).",
                                    body_snippet=rest[:100])
                weak_algs = [b'"hs256"', b'"hs1"', b'"rs1"']
                if any(a in header_json for a in weak_algs):
                    return _finding("ASVS-128", "JWT with Weak Algorithm Detected",
                                    "Medium", url,
                                    "Response contains a JWT using a weak signing algorithm.\n"
                                    "Only strong, approved algorithms shall be permitted "
                                    "(ASVS V9.1.2).",
                                    body_snippet=rest[:100])
        except Exception:
            continue
    return None


def chk_173_creds(rh, qh, body, url, mi, h, cb):
    """ASVS-173: Default credentials in Authorization header"""
    import base64
    auth = _get_header(qh, "Authorization") or ""
    if not auth.lower().startswith("basic "): return None
    try:
        decoded = base64.b64decode(auth[6:].strip() + "==").decode("utf-8", errors="replace")
    except Exception:
        return None
    defaults = [
        "admin:admin", "admin:password", "admin:1234", "admin:12345",
        "admin:123456", "root:root", "root:toor", "root:password",
        "admin:admin123", "administrator:administrator", "test:test",
        "guest:guest", "admin:pass", "sa:sa", "admin:", "admin:admin1",
        "user:user", "admin:changeme", "admin:secret",
    ]
    for d in defaults:
        if decoded.lower() == d:
            return _finding("ASVS-173", "Default Credentials Detected in Request",
                            "High", url,
                            "Request uses well-known default Basic Auth credentials: '%s'\n"
                            "Default credentials shall not be used for service authentication "
                            "(ASVS V13.2.3)." % decoded)
    return None


def chk_179(rh, qh, body, url, mi, h, cb):
    """ASVS-179: Monitoring/actuator endpoints exposed"""
    st = _get_status(rh)
    if st not in [200, 401, 403]: return None
    us = str(url.getPath()).lower()
    monitoring_paths = [
        "/actuator", "/actuator/", "/actuator/health", "/actuator/env",
        "/actuator/metrics", "/actuator/info", "/actuator/beans",
        "/actuator/mappings", "/actuator/trace", "/actuator/dump",
        "/metrics", "/health", "/health/", "/info", "/env",
        "/debug", "/_debug", "/status", "/ping", "/monitor",
        "/.well-known/security.txt",
        "/jolokia", "/hawtio", "/console",
        "/server-status", "/server-info",
    ]
    if any(us == p or us.startswith(p + "/") for p in monitoring_paths):
        ct = _get_header(rh, "Content-Type") or ""
        if st == 200 and ("json" in ct.lower() or "html" in ct.lower() or "text" in ct.lower()):
            return _finding("ASVS-179", "Monitoring/Management Endpoint Exposed",
                            "High", url,
                            "Monitoring or management endpoint is publicly accessible: %s "
                            "(HTTP %d)\nDocumentation and monitoring endpoints shall not be "
                            "exposed unless explicitly intended (ASVS V13.4.5)." % (us, st))
        elif st in [401, 403]:
            return _finding("ASVS-179", "Monitoring Endpoint Exists (Auth Required)",
                            "Low", url,
                            "Monitoring endpoint %s exists and requires authentication (HTTP %d).\n"
                            "Confirm this endpoint is intentionally exposed and properly "
                            "protected (ASVS V13.4.5)." % (us, st))
    return None


def chk_181(rh, qh, body, url, mi, h, cb):
    """ASVS-181: Sensitive file types accessible from webroot"""
    st = _get_status(rh)
    if st != 200: return None
    us = str(url.getPath()).lower().split("?")[0]
    sensitive_exts = [
        ".bak", ".old", ".orig", ".backup", ".sql", ".dump",
        ".conf", ".config", ".cfg", ".ini", ".env", ".local",
        ".log", ".logs", ".xml", ".yaml", ".yml", ".json.bak",
        ".php.bak", ".asp.bak", ".aspx.bak", ".jsp.bak",
        ".git", ".svn", ".htpasswd", ".htaccess", ".DS_Store",
        "web.config.bak", ".pem", ".key", ".cert", ".crt",
    ]
    for ext in sensitive_exts:
        if us.endswith(ext):
            return _finding("ASVS-181", "Sensitive File Type Accessible from Webroot",
                            "High", url,
                            "File with sensitive extension '%s' is accessible: %s\n"
                            "The web tier shall be configured to only serve expected file "
                            "extensions (ASVS V13.4.7)." % (ext, us))
    return None


def chk_185(rh, qh, body, url, mi, h, cb):
    """ASVS-185: No Clear-Site-Data header on logout endpoint"""
    us = str(url.getPath()).lower()
    is_logout = any(k in us for k in ["logout","signout","log-out","sign-out","logoff"])
    if not is_logout: return None
    st = _get_status(rh)
    if st not in [200, 302, 303]: return None
    csd = _get_header(rh, "Clear-Site-Data")
    if not csd:
        return _finding("ASVS-185", "Logout Response Missing Clear-Site-Data Header",
                        "Medium", url,
                        "Logout endpoint '%s' does not set the Clear-Site-Data header.\n"
                        "Authenticated data shall be cleared from client storage on logout. "
                        "Consider: Clear-Site-Data: \"cache\", \"cookies\", \"storage\" "
                        "(ASVS V14.3.1)." % us)
    return None


def chk_187(rh, qh, body, url, mi, h, cb):
    """ASVS-187: Sensitive data written to localStorage/sessionStorage in JS"""
    ct = _get_header(rh, "Content-Type") or ""
    if "javascript" not in ct.lower() and "html" not in ct.lower(): return None
    sensitive_keys = [
        "password", "passwd", "secret", "api_key", "apikey",
        "access_token", "refresh_token", "private_key", "ssn",
        "credit_card", "creditcard", "cvv", "pin", "auth_token",
    ]
    for key in sensitive_keys:
        pattern = r'(?:localStorage|sessionStorage)\.setItem\s*\(\s*["\']' + key
        if re.search(pattern, body, re.IGNORECASE):
            return _finding("ASVS-187", "Sensitive Data Written to Browser Storage",
                            "High", url,
                            "JavaScript writes sensitive key '%s' to localStorage or "
                            "sessionStorage.\nBrowser storage shall not contain sensitive data "
                            "- session tokens are the only exception (ASVS V14.3.3)." % key,
                            body_snippet=_body_snippet(body, pattern))
    return None


# Tier 2 heuristics

def chk_025_ratelimit(rh, qh, body, url, mi, h, cb):
    """ASVS-025: No rate-limiting headers on auth/API endpoints"""
    us = str(url.getPath()).lower()
    is_sensitive = any(k in us for k in ["login","auth","signin","register",
                                          "password","api/","token","oauth"])
    if not is_sensitive: return None
    st = _get_status(rh)
    if st not in [200, 201, 400, 401, 403]: return None
    rl_headers = ["X-RateLimit-Limit", "X-RateLimit-Remaining", "RateLimit-Limit",
                  "Retry-After", "X-Rate-Limit"]
    has_rl = any(_get_header(rh, h2) for h2 in rl_headers)
    if not has_rl:
        return _finding("ASVS-025", "No Rate-Limiting Headers on Sensitive Endpoint",
                        "Medium", url,
                        "No rate-limiting headers (X-RateLimit-*, Retry-After) detected on "
                        "sensitive endpoint '%s'.\nThis is a heuristic - rate limiting may be "
                        "enforced at a different layer. Anti-automation controls shall be in "
                        "place to protect against credential stuffing and brute force "
                        "(ASVS V2.4.1)." % us)
    return None


def chk_083_maxlen(rh, qh, body, url, mi, h, cb):
    """ASVS-083: Password field with restrictive maxlength < 64"""
    if not _is_html(rh): return None
    for m in re.finditer(r'<input[^>]+type\s*=\s*["\']?password["\']?[^>]*>', body, re.IGNORECASE):
        tag = m.group(0)
        ml = re.search(r'maxlength\s*=\s*["\']?(\d+)', tag, re.IGNORECASE)
        if ml:
            length = int(ml.group(1))
            if length < 64:
                return _finding("ASVS-083", "Password Field Has Restrictive maxlength",
                                "Low", url,
                                "Password input has maxlength=%d (minimum should be 64).\n"
                                "Passwords of at least 64 characters shall be permitted "
                                "(ASVS V6.2.9)." % length,
                                body_snippet=tag[:200])
    return None


def chk_095_reset(rh, qh, body, url, mi, h, cb):
    """ASVS-095: Password reset token exposed in URL"""
    us = str(url)
    us_lower = us.lower()
    if not any(k in us_lower for k in ["reset","forgot","recover","password"]):
        return None
    token_params = ["token","reset_token","key","code","t","hash"]
    for param in token_params:
        m = re.search(r'[?&]' + param + r'=([^&]{8,})', us, re.IGNORECASE)
        if m:
            token_val = m.group(1)
            # Only flag if it looks like a real token (alphanumeric, not just a page ID)
            if re.match(r'^[A-Za-z0-9+/=_-]{16,}$', token_val):
                return _finding("ASVS-095", "Password Reset Token Exposed in URL",
                                "High", url,
                                "Password reset/recovery URL contains token in query string: "
                                "?%s=%s...\nTokens in URLs are logged by servers, proxies, "
                                "and browsers. Reset tokens shall be sent via POST body or "
                                "handled server-side (ASVS V6.4.3)." % (param, token_val[:20]))
    return None

# =============================================================================
# ADDITIONAL CHECKS v4 -- extended control coverage
# =============================================================================
# =============================================================================
# ASVS v4 additional checks
# =============================================================================

def chk_027(rh, qh, body, url, mi, h, cb):
    """ASVS-027: Content-Disposition missing on direct API/file resource responses"""
    ct = _get_header(rh, "Content-Type") or ""
    us = str(url.getPath()).lower()
    # Only flag API or file endpoints where browser rendering would be wrong context
    is_api = any(us.startswith(p) for p in ["/api/","/v1/","/v2/","/v3/","/rest/","/graphql"])
    is_file = any(us.endswith(e) for e in [".pdf",".docx",".xlsx",".csv",".xml",".json"])
    if not (is_api or is_file): return None
    cd = _get_header(rh, "Content-Disposition")
    sf = _get_header(rh, "X-Content-Type-Options") or ""
    if not cd and "nosniff" not in sf.lower():
        return _finding("ASVS-027", "Missing Content-Disposition on API/File Response",
                        "Low", url,
                        "Response from '%s' lacks Content-Disposition and X-Content-Type-Options: nosniff.\n"
                        "Controls shall prevent browsers from rendering API or file responses in "
                        "an incorrect context (ASVS V3.2.1)." % us)
    return None


def chk_041_csrf(rh, qh, body, url, mi, h, cb):
    """ASVS-041/042: POST form without CSRF protection and without SameSite=Strict/Lax"""
    if not _is_html(rh): return None
    if not re.search(r'<form\b[^>]*method\s*=\s*["\']?post', body, re.IGNORECASE): return None
    # Check for CSRF token in form
    has_csrf = bool(re.search(r'(?:csrf|_token|xsrf|authenticity_token|__RequestVerification)',
                               body, re.IGNORECASE))
    if has_csrf: return None
    # Check cookies for SameSite=Strict or Lax (either on request or response)
    all_cookies = []
    for hdr in list(rh) + list(qh):
        if isinstance(hdr, str) and (hdr.lower().startswith("set-cookie:") or
                                      hdr.lower().startswith("cookie:")):
            all_cookies.append(hdr.lower())
    has_samesite = any("samesite=strict" in c or "samesite=lax" in c for c in all_cookies)
    if not has_samesite:
        return _finding("ASVS-041", "POST Form Lacks CSRF Token and SameSite Cookie Protection",
                        "High", url,
                        "Page has a POST form with no CSRF token and no SameSite=Strict/Lax "
                        "cookie detected.\nCross-origin requests to sensitive functionality "
                        "shall be validated using anti-forgery tokens or SameSite cookies "
                        "(ASVS V3.5.1/V3.5.2).")
    return None


def chk_043_method(rh, qh, body, url, mi, h, cb):
    """ASVS-043: Sensitive functionality reachable via GET"""
    if not _is_html(rh): return None
    # Flag forms that perform state-changing actions via GET
    get_forms = re.findall(r'<form\b[^>]*method\s*=\s*["\']?get["\']?[^>]*>', body, re.IGNORECASE)
    for form in get_forms:
        action = re.search(r'action\s*=\s*["\']([^"\']+)', form, re.IGNORECASE)
        if action:
            act = action.group(1).lower()
            if any(k in act for k in ["delete","remove","update","edit","transfer",
                                       "pay","purchase","admin","modify","create"]):
                return _finding("ASVS-043", "State-Changing Action Via GET Form",
                                "Medium", url,
                                "Form action '%s' uses GET method for what appears to be a "
                                "state-changing operation.\nHTTP requests to sensitive functionality "
                                "shall use POST, PUT, PATCH, or DELETE (ASVS V3.5.3)." % act[:80])
    return None


def chk_045_postmsg(rh, qh, body, url, mi, h, cb):
    """ASVS-045: postMessage without origin validation"""
    if not _is_html(rh): return None
    # Check for addEventListener('message',...) without origin check
    if not re.search(r'addEventListener\s*\(\s*["\']message["\']', body, re.IGNORECASE):
        return None
    # Look for origin validation near the message listener
    has_origin_check = bool(re.search(
        r'(?:event|e|msg)\.origin\s*[!=]=|origin\s*!==?\s*["\']|'
        r'allowedOrigins|trustedOrigins|checkOrigin', body, re.IGNORECASE))
    if not has_origin_check:
        return _finding("ASVS-045", "postMessage Listener Without Origin Validation",
                        "Medium", url,
                        "Page uses addEventListener('message') but no origin validation "
                        "(event.origin check) was detected nearby.\n"
                        "postMessage handlers shall discard messages from untrusted origins "
                        "(ASVS V3.5.5).",
                        body_snippet=_body_snippet(body,
                            r'addEventListener\s*\(\s*["\']message["\']'))
    return None


def chk_047_js_auth(rh, qh, body, url, mi, h, cb):
    """ASVS-047: Authorization-required data returned in JS file response"""
    ct = _get_header(rh, "Content-Type") or ""
    if "javascript" not in ct.lower(): return None
    # Detect patterns that look like inline auth data in JS
    hits = []
    if re.search(r'(?:apiKey|api_key|authToken|auth_token|accessToken|'
                 r'bearerToken|privateKey)\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{16,}',
                 body, re.IGNORECASE):
        hits.append("Hardcoded auth key/token value in JS")
    if re.search(r'(?:userId|user_id|accountId|account_id)\s*[:=]\s*\d{4,}',
                 body, re.IGNORECASE):
        hits.append("User/account ID embedded in JS")
    if hits:
        return _finding("ASVS-047", "Authorization-Required Data in JavaScript Response",
                        "High", url,
                        "\n".join(hits) +
                        "\nData requiring authorization shall not be included in script "
                        "resource responses (ASVS V3.5.7).",
                        body_snippet=_body_snippet(body,
                            r'(?:apiKey|authToken|accessToken|bearerToken)\s*[:=]\s*["\']'))
    return None


def chk_053_preload(rh, qh, body, url, mi, h, cb):
    """ASVS-053: HSTS missing preload directive"""
    if str(url.getProtocol()).lower() != "https": return None
    hsts = _get_header(rh, "Strict-Transport-Security") or ""
    if not hsts: return None  # chk_033 covers missing HSTS
    if "preload" not in hsts.lower():
        return _finding("ASVS-053", "HSTS Missing preload Directive",
                        "Low", url,
                        "HSTS header is present but lacks the 'preload' directive: %s\n"
                        "Adding 'preload' and submitting to the HSTS preload list ensures "
                        "browsers enforce HTTPS before the first connection (ASVS V3.7.4)." % hsts)
    return None


def chk_056_proxy_hdrs(rh, qh, body, url, mi, h, cb):
    """ASVS-056: Proxy/intermediary headers present in response (may be overridable)"""
    proxy_hdrs = ["X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host",
                  "X-Forwarded-Proto", "X-Original-IP", "CF-Connecting-IP",
                  "True-Client-IP", "X-Client-IP"]
    found = []
    for hn in proxy_hdrs:
        v = _get_header(rh, hn)
        if v: found.append("%s: %s" % (hn, v))
    if found:
        return _finding("ASVS-056", "Proxy Headers Reflected in Response",
                        "Low", url,
                        "Response reflects proxy/intermediary headers:\n* " +
                        "\n* ".join(found) +
                        "\nVerify these headers cannot be injected by end-users. "
                        "Proxy headers used for IP resolution or auth shall not be "
                        "user-overridable (ASVS V4.1.3).")
    return None


def chk_058_smuggling(rh, qh, body, url, mi, h, cb):
    """ASVS-058/059: Both Transfer-Encoding and Content-Length present (smuggling risk)"""
    te = _get_header(rh, "Transfer-Encoding")
    cl = _get_header(rh, "Content-Length")
    if te and cl:
        return _finding("ASVS-058", "Both Transfer-Encoding and Content-Length in Response",
                        "Medium", url,
                        "Response contains both Transfer-Encoding (%s) and Content-Length (%s).\n"
                        "This ambiguity can enable HTTP request smuggling attacks.\n"
                        "Boundaries shall be determined by one mechanism only (ASVS V4.2.1/V4.2.2)."
                        % (te, cl))
    return None


def chk_060_http2_conn(rh, qh, body, url, mi, h, cb):
    """ASVS-060: HTTP/2 response with forbidden connection-specific headers"""
    # Detect HTTP/2 from status line
    is_h2 = False
    for hdr in rh:
        if isinstance(hdr, str) and hdr.upper().startswith("HTTP/2"):
            is_h2 = True
            break
    if not is_h2: return None
    forbidden = []
    for fn in ["Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade"]:
        if _get_header(rh, fn):
            forbidden.append(fn)
    if forbidden:
        return _finding("ASVS-060", "Connection-Specific Headers in HTTP/2 Response",
                        "Medium", url,
                        "HTTP/2 response contains connection-specific headers that are "
                        "forbidden in HTTP/2: " + ", ".join(forbidden) +
                        "\nHTTP/2 responses shall not use connection-specific headers "
                        "(ASVS V4.2.3).")
    return None


def chk_063_graphql_depth(rh, qh, body, url, mi, h, cb):
    """ASVS-063: GraphQL error suggests no depth/complexity limiting"""
    ct = _get_header(rh, "Content-Type") or ""
    if "json" not in ct.lower(): return None
    if "errors" not in body.lower(): return None
    # GraphQL errors containing 'depth', 'complexity', 'cost' suggest limits exist
    # Absence of these + nested query errors suggests no limiting
    if re.search(r'"errors"\s*:\s*\[', body, re.IGNORECASE):
        if not re.search(r'(?:depth|complexity|cost|throttl|limit)', body, re.IGNORECASE):
            if re.search(r'(?:field|selection|fragment)', body, re.IGNORECASE):
                return _finding("ASVS-063", "GraphQL Error Without Depth/Complexity Information",
                                "Low", url,
                                "GraphQL error response detected with no mention of depth, "
                                "complexity, or cost limiting.\nGraphQL endpoints shall implement "
                                "query depth limiting or cost analysis to prevent DoS "
                                "(ASVS V4.3.1).",
                                body_snippet=_body_snippet(body, r'"errors"\s*:\s*\['))
    return None


def chk_066_websocket_origin(rh, qh, body, url, mi, h, cb):
    """ASVS-066: WebSocket upgrade response without Origin restriction"""
    # Detect WebSocket upgrade response
    upgrade = _get_header(rh, "Upgrade") or ""
    if "websocket" not in upgrade.lower(): return None
    # Check if CORS is wildcard on the upgrade response
    acao = _get_header(rh, "Access-Control-Allow-Origin") or ""
    if acao.strip() == "*":
        return _finding("ASVS-066", "WebSocket Upgrade with Wildcard CORS Origin",
                        "High", url,
                        "WebSocket handshake response allows all origins "
                        "(Access-Control-Allow-Origin: *).\nThe Origin header shall be "
                        "validated against an allowlist during the WebSocket handshake "
                        "(ASVS V4.4.2).")
    # Also flag if no Sec-WebSocket-Protocol header on upgrade
    swp = _get_header(rh, "Sec-WebSocket-Protocol")
    if not swp and _get_status(rh) == 101:
        return _finding("ASVS-067", "WebSocket Upgrade Missing Sec-WebSocket-Protocol",
                        "Low", url,
                        "WebSocket upgrade response (101) does not include "
                        "Sec-WebSocket-Protocol header.\nDedicated session tokens complying "
                        "with session management requirements shall be used for WebSocket "
                        "connections (ASVS V4.4.3).")
    return None


def chk_077_content_disp(rh, qh, body, url, mi, h, cb):
    """ASVS-077/078: File download response missing Content-Disposition or unsafe filename"""
    us = str(url.getPath()).lower()
    ct = _get_header(rh, "Content-Type") or ""
    # Only check responses that look like downloads
    download_types = ["application/octet-stream", "application/pdf",
                      "application/zip", "text/csv", "application/msword"]
    if not any(dt in ct.lower() for dt in download_types): return None
    cd = _get_header(rh, "Content-Disposition") or ""
    if not cd:
        return _finding("ASVS-077", "File Download Missing Content-Disposition Header",
                        "Medium", url,
                        "Response appears to be a file download (Content-Type: %s) but "
                        "lacks a Content-Disposition header.\nThe filename shall be "
                        "specified in Content-Disposition to prevent injection attacks "
                        "(ASVS V5.4.1)." % ct)
    # Check for unencoded special chars in filename
    fn_m = re.search(r'filename\s*=\s*["\']?([^"\';\r\n]+)', cd, re.IGNORECASE)
    if fn_m:
        fn = fn_m.group(1).strip()
        if re.search(r'[<>:"/\\|?*\x00-\x1f]', fn):
            return _finding("ASVS-078", "Content-Disposition Filename Contains Special Characters",
                            "Medium", url,
                            "Content-Disposition filename contains potentially dangerous "
                            "characters: %s\nFilenames shall be sanitized to prevent "
                            "injection attacks (ASVS V5.4.2)." % fn[:80])
    return None


def chk_174_ssrf(rh, qh, body, url, mi, h, cb):
    """ASVS-174: SSRF indicators - internal IP in error or redirect"""
    # Check Location header for internal IP redirect
    loc = _get_header(rh, "Location") or ""
    internal_ip = re.search(
        r'https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|localhost)',
        loc, re.IGNORECASE)
    if internal_ip:
        return _finding("ASVS-174", "Redirect to Internal/Private IP Address",
                        "High", url,
                        "Response redirects to an internal/private address: %s\n"
                        "This may indicate an SSRF vulnerability. The server shall only "
                        "communicate with allowlisted external resources (ASVS V13.2.5)." % loc[:100])
    # Check body for internal IP disclosure in error messages
    if _get_status(rh) >= 400:
        ip_leak = re.search(
            r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
            r'192\.168\.\d{1,3}\.\d{1,3})', body)
        if ip_leak:
            return _finding("ASVS-174", "Internal IP Address Disclosed in Error Response",
                            "Medium", url,
                            "Error response reveals internal IP address: %s\n"
                            "Internal network topology shall not be exposed in error "
                            "responses (ASVS V13.2.5)." % ip_leak.group(0))
    return None


def chk_183_cache_api(rh, qh, body, url, mi, h, cb):
    """ASVS-183: Authenticated/dynamic JSON API response missing cache control"""
    ct = _get_header(rh, "Content-Type") or ""
    if "json" not in ct.lower(): return None
    # Only flag if request has session/auth credentials
    auth_hdr = _get_header(qh, "Authorization") or ""
    req_cookie = _get_header(qh, "Cookie") or ""
    has_auth = bool(auth_hdr) or any(s in req_cookie.lower()
                                      for s in ["session","token","auth","sess","sid"])
    if not has_auth: return None
    cc = _get_header(rh, "Cache-Control") or ""
    if "no-store" not in cc.lower() and "private" not in cc.lower():
        return _finding("ASVS-183", "Authenticated API Response Missing Cache Restriction",
                        "Medium", url,
                        "Authenticated JSON API response lacks Cache-Control: no-store or private. "
                        "Current: '%s'\nCaching mechanisms shall be configured to not cache "
                        "responses that contain sensitive or dynamic content (ASVS V14.2.5)." % cc)
    return None


def chk_189_excess_fields(rh, qh, body, url, mi, h, cb):
    """ASVS-189: API response returns excessive top-level fields (over-exposure)"""
    ct = _get_header(rh, "Content-Type") or ""
    if "json" not in ct.lower(): return None
    if len(body) < 100: return None
    # Count top-level keys in JSON object
    top_keys = re.findall(r'^\s*"([^"]+)"\s*:', body, re.MULTILINE)
    if len(top_keys) > 30:
        # Check for sensitive field names in those keys
        sensitive_found = [k for k in top_keys if any(s in k.lower() for s in
                           ["password","secret","key","token","ssn","salary",
                            "internal","private","hash","credit","admin"])]
        if sensitive_found:
            return _finding("ASVS-189", "API Response May Expose Excessive/Sensitive Fields",
                            "Medium", url,
                            "JSON response has %d top-level fields including potentially "
                            "sensitive: %s\nThe application shall only return the required "
                            "subset of data fields (ASVS V15.3.1)." % (
                                len(top_keys), ", ".join(sensitive_found[:5])),
                            body_snippet=_body_snippet(body,
                                r'"(?:password|secret|key|token|ssn|salary|private|hash)"\s*:'))
    return None


def chk_190_open_redirect_internal(rh, qh, body, url, mi, h, cb):
    """ASVS-190: Server-side redirect to internal/private address"""
    st = _get_status(rh)
    if st not in [301, 302, 307, 308]: return None
    loc = _get_header(rh, "Location") or ""
    # Internal IP redirect
    if re.search(r'https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.)',
                 loc, re.IGNORECASE):
        return _finding("ASVS-190", "Backend Redirect to Internal Network Address",
                        "High", url,
                        "Server issues %d redirect to internal address: %s\n"
                        "Backend calls to external URLs shall be configured to not follow "
                        "redirects to internal resources (ASVS V15.3.2)." % (st, loc[:100]))
    return None


def chk_191_mass_assign(rh, qh, body, url, mi, h, cb):
    """ASVS-191: Mass assignment risk - privileged fields in API response"""
    ct = _get_header(rh, "Content-Type") or ""
    if "json" not in ct.lower(): return None
    priv_fields = ["isAdmin", "is_admin", "role", "roles", "permissions",
                   "privilege", "isStaff", "is_staff", "isModerator",
                   "is_moderator", "group", "groups", "scope", "scopes",
                   "verified", "isVerified", "is_verified", "approved"]
    found = [f for f in priv_fields
             if re.search(r'"' + re.escape(f) + r'"\s*:', body, re.IGNORECASE)]
    if found:
        return _finding("ASVS-191", "Privileged Fields Exposed in API Response",
                        "Medium", url,
                        "API response contains privileged/role fields that could enable "
                        "mass assignment: " + ", ".join(found) +
                        "\nVerify these fields cannot be submitted by clients to escalate "
                        "privileges. Controllers shall limit allowed fields (ASVS V15.3.3).",
                        body_snippet=_body_snippet(body,
                            r'"(?:isAdmin|is_admin|role|roles|permissions|privilege)"\s*:'))
    return None


def chk_192_proto_pollution(rh, qh, body, url, mi, h, cb):
    """ASVS-192: Prototype pollution indicators in URL params or response"""
    us = str(url)
    params = us.split("?", 1)[1] if "?" in us else ""
    # Check for __proto__ or constructor.prototype in URL
    if re.search(r'(?:__proto__|constructor\.prototype|Object\.prototype)',
                 params, re.IGNORECASE):
        return _finding("ASVS-192", "Prototype Pollution Attempt in URL Parameters",
                        "High", url,
                        "URL parameters contain prototype pollution payload: %s\n"
                        "JavaScript code shall be written to prevent prototype pollution "
                        "(ASVS V15.3.6)." % params[:120])
    # Check response body for reflected proto pollution indicators
    if _is_html(rh) or "javascript" in (_get_header(rh, "Content-Type") or "").lower():
        if re.search(r'__proto__\s*[=:]|constructor\.prototype\s*[=:]',
                     body, re.IGNORECASE):
            return _finding("ASVS-192", "Prototype Pollution Pattern in Response",
                            "Medium", url,
                            "Response body contains prototype pollution pattern.\n"
                            "JavaScript shall use Set() or Map() instead of object literals "
                            "to prevent prototype pollution (ASVS V15.3.6).",
                            body_snippet=_body_snippet(body, r'__proto__\s*[=:]'))
    return None


def chk_193_param_pollution(rh, qh, body, url, mi, h, cb):
    """ASVS-193: HTTP parameter pollution - duplicate param names in URL"""
    us = str(url)
    params = us.split("?", 1)[1] if "?" in us else ""
    if not params: return None
    param_names = [p.split("=")[0].lower() for p in params.split("&") if "=" in p]
    seen = set()
    dupes = []
    for p in param_names:
        if p in seen and p not in dupes:
            dupes.append(p)
        seen.add(p)
    if dupes:
        return _finding("ASVS-193", "Duplicate Parameter Names in URL (HPP)",
                        "Medium", url,
                        "URL contains duplicate parameter names: %s\nDuplicate parameters "
                        "can cause inconsistent parsing across components and enable HTTP "
                        "parameter pollution attacks (ASVS V15.3.7)." % ", ".join(dupes))
    return None


def chk_022_server_val(rh, qh, body, url, mi, h, cb):
    """ASVS-022/023: Forms with only client-side validation"""
    if not _is_html(rh): return None
    if not re.search(r'<form\b', body, re.IGNORECASE): return None
    # Flag if novalidate with no server-side error message on error response
    st = _get_status(rh)
    if st in [200] and re.search(r'\bnovalidate\b', body, re.IGNORECASE):
        has_pattern  = re.search(r'\bpattern\s*=', body, re.IGNORECASE)
        has_required = re.search(r'\brequired\b', body, re.IGNORECASE)
        has_min      = re.search(r'\b(?:min|max|minlength|maxlength)\s*=', body, re.IGNORECASE)
        if not has_pattern and not has_required and not has_min:
            return _finding("ASVS-022", "Form Uses novalidate with No Constraints",
                            "Low", url,
                            "Form uses novalidate attribute with no pattern/required/min/max "
                            "constraints detected.\nInput validation shall be enforced at the "
                            "server-side trusted service layer (ASVS V2.2.1/V2.2.2).")
    return None


def chk_069_upload_size(rh, qh, body, url, mi, h, cb):
    """ASVS-069/070/071/072: File upload form checks"""
    if not _is_html(rh): return None
    file_inputs = re.findall(r'<input[^>]+type\s*=\s*["\']?file["\']?[^>]*>',
                              body, re.IGNORECASE)
    if not file_inputs: return None
    issues = []
    for inp in file_inputs:
        # No accept attribute means any file type accepted (ASVS-070)
        if not re.search(r'\baccept\s*=', inp, re.IGNORECASE):
            issues.append("File input without 'accept' attribute (any file type accepted)")
    # Check form for max size indicator
    form_ctx = body[:5000]
    has_size_limit = re.search(r'(?:max.?size|maxsize|file.?size|MAX_FILE_SIZE)',
                                form_ctx, re.IGNORECASE)
    if not has_size_limit:
        issues.append("No file size limit indicator found near upload form")
    if issues:
        return _finding("ASVS-069", "File Upload Form Lacks Type/Size Restrictions",
                        "Medium", url,
                        "\n".join(issues) +
                        "\nUpload controls shall restrict file type (ASVS-070) and size "
                        "(ASVS-069) to prevent DoS and malicious file upload.",
                        body_snippet=file_inputs[0][:200] if file_inputs else "")
    return None


def chk_196_error_handling(rh, qh, body, url, mi, h, cb):
    """ASVS-196/197: Error responses leaking system state or failing open"""
    st = _get_status(rh)
    if st < 500: return None
    issues = []
    # Fail-open indicators: 500 response that still contains form/action data
    if re.search(r'<form\b', body, re.IGNORECASE) and st == 500:
        issues.append("HTTP 500 response still contains functional form elements (possible fail-open)")
    # Cascading failure indicators
    if re.search(r'(?:connection refused|ECONNREFUSED|upstream connect error|'
                 r'backend unavailable|circuit.?break)', body, re.IGNORECASE):
        issues.append("Backend connection failure detail exposed in error response")
    if issues:
        return _finding("ASVS-196", "Error Handling Deficiency Detected",
                        "Medium", url,
                        "\n".join(issues) +
                        "\nThe application shall continue to operate securely when external "
                        "resources fail and shall not fail open (ASVS V16.5.2/V16.5.3).",
                        body_snippet=_body_snippet(body,
                            r'(?:connection refused|ECONNREFUSED|upstream connect error)'))
    return None

# =============================================================================
# Manual testing guidance
# =============================================================================
# Manual testing guidance map: ASVS-ID -> (title, tool, steps)
# tool: R=Repeater, P=Proxy, S=Sequencer, I=Intruder, C=Comparer, T=Target/manual
_MANUAL_GUIDE = {
    # -- API and Web Service ---------------------------------------------------
    "ASVS-061": ("HTTP Header Injection in HTTP/2", "Repeater",
        "1. In Proxy history, find an HTTP/2 request (check Protocol column).\n"
        "2. Send to Repeater. In the request headers, try injecting CRLF:\n"
        "   Add header: foo: bar\\r\\nInjected: evil\n"
        "3. Send. If the response reflects 'Injected: evil' as a separate header,\n"
        "   or the server returns a 400, note whether the CR/LF was accepted.\n"
        "PASS: Server rejects requests containing CR/LF in header values.\n"
        "FAIL: Server accepts or reflects the injected header."),
    "ASVS-062": ("Oversized URI/Cookie DoS Protection", "Repeater",
        "1. In Repeater, find any authenticated request with a Cookie header.\n"
        "2. Extend the Cookie header value to 8192+ bytes (use 'A' * 8192).\n"
        "   Similarly test with an extremely long URL path or query string.\n"
        "3. Also test an Authorization header with a 64KB value.\n"
        "PASS: Server returns 400/413/414 and does not crash or hang.\n"
        "FAIL: Server accepts, returns 5xx, or times out."),
    "ASVS-068": ("WebSocket Session Token Validation", "Repeater",
        "1. Find a WebSocket connection in Proxy > WebSockets history.\n"
        "2. Send the upgrade request to Repeater.\n"
        "3. Modify the session cookie to an invalid value and re-send the upgrade.\n"
        "4. If upgrade succeeds (101), try sending authenticated WebSocket messages.\n"
        "PASS: Invalid/no session token causes upgrade rejection (401/403).\n"
        "FAIL: WebSocket accepts connections without valid session tokens."),
    # -- Authentication --------------------------------------------------------
    "ASVS-080": ("Password Change Functionality Exists", "Proxy/Manual",
        "1. Log in and navigate to account settings.\n"
        "2. Verify a 'Change Password' option exists and is accessible.\n"
        "PASS: Password change functionality exists.\n"
        "FAIL: No password change functionality is available."),
    "ASVS-081": ("Password Change Requires Current Password", "Repeater",
        "1. Capture the password change request in Proxy.\n"
        "2. Send to Repeater. Remove the current_password parameter or set it blank.\n"
        "3. Send. Also try setting current_password to an incorrect value.\n"
        "PASS: Server rejects the request when current password is wrong/missing.\n"
        "FAIL: Server accepts password change without current password."),
    "ASVS-082": ("Pwned Password Check on Registration", "Repeater",
        "1. Capture account registration or password change request.\n"
        "2. In Repeater, set the password to common known-breached passwords:\n"
        "   'Password1!', 'Summer2024!', 'Welcome1!', 'P@ssw0rd'\n"
        "3. Send each. Check if any are rejected.\n"
        "PASS: Server rejects passwords found in breach databases.\n"
        "FAIL: Common/known-breached passwords are accepted."),
    "ASVS-086": ("Password Not Pre-processed Before Verification", "Manual",
        "1. Register/change password to exactly: 'TestPass123!' (12 chars).\n"
        "2. Log out. Try logging in with: 'TestPass123!EXTRAEXTRA' (same prefix, extra suffix).\n"
        "3. Also try logging in with the password truncated to 8 chars: 'TestPass'\n"
        "PASS: Only the exact password works.\n"
        "FAIL: Truncated or padded passwords also authenticate (indicates hashing truncation)."),
    "ASVS-087": ("Passwords of 64+ Characters Permitted", "Repeater",
        "1. Capture a registration or password change request.\n"
        "2. In Repeater, set the password field to a 64-character string:\n"
        "   'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\n"
        "3. Also test 65, 128, and 256 characters.\n"
        "PASS: All lengths up to 64+ are accepted.\n"
        "FAIL: Server rejects or truncates passwords above a threshold."),
    "ASVS-088": ("Password Complexity Rules Not Overly Restrictive", "Repeater",
        "1. Capture a registration or password change request.\n"
        "2. Test a long passphrase with only lowercase: 'correcthorsebatterystaple'\n"
        "3. Test a password with only numbers: '12345678901234567890'\n"
        "4. Test unicode characters: 'Pass\\u00e9w\\u00f6rd!'\n"
        "PASS: All valid-length strings are accepted regardless of character composition.\n"
        "FAIL: Server enforces specific character class rules beyond minimum length."),
    "ASVS-089": ("Multi-Factor Authentication Available", "Manual",
        "1. Log in to the application.\n"
        "2. Navigate to security/account settings.\n"
        "3. Check if MFA enrollment (TOTP, push, SMS, hardware key) is available.\n"
        "4. If MFA exists, verify it is enforced for sensitive actions (account changes).\n"
        "PASS: MFA mechanism exists and is enforced.\n"
        "FAIL: No MFA option is available OR MFA exists but is not enforced."),
    "ASVS-090": ("No Undocumented Alternative Auth Paths", "Target/Manual",
        "1. In Target > Site map, review all paths related to authentication:\n"
        "   /login, /auth, /api/auth, /api/login, /oauth, /sso, /saml\n"
        "2. For each, verify it uses the same authentication mechanism.\n"
        "3. Check for developer/debug endpoints: /dev-login, /admin-login, /bypass\n"
        "PASS: All auth paths require the same MFA level and strength.\n"
        "FAIL: An alternative path allows weaker or no authentication."),
    "ASVS-091": ("Email Not Used as Single Auth Factor", "Manual",
        "1. Review the login flow. Does it accept email link (magic link) alone?\n"
        "2. Check if email is a standalone auth mechanism (no password).\n"
        "3. If magic link is used, verify it requires a second factor.\n"
        "PASS: Email alone cannot authenticate (must be combined with another factor).\n"
        "FAIL: Clicking an email link alone grants full access."),
    "ASVS-092": ("Auth Change Notification Sent", "Manual",
        "1. Change your account password.\n"
        "2. Change your email address.\n"
        "3. Add or remove an MFA method.\n"
        "4. Check if a notification email/SMS is sent to the original address.\n"
        "PASS: Notification is sent to the original contact for each change.\n"
        "FAIL: No notification is sent for authentication detail changes."),
    "ASVS-096": ("OTP/Lookup Codes Single-Use", "Repeater",
        "1. Trigger an OTP or lookup code to be sent (password reset, MFA).\n"
        "2. Capture the form submission that uses the code.\n"
        "3. In Repeater, send the same code submission a second time.\n"
        "PASS: Second use of the same code is rejected.\n"
        "FAIL: Code can be reused (replay attack possible)."),
    "ASVS-097": ("OTP Entropy >= 20 bits", "Manual",
        "1. Request multiple OTP codes (password reset codes, verification codes).\n"
        "2. Record at least 20 codes. Check their length and character space:\n"
        "   - 6 numeric digits = ~20 bits (borderline)\n"
        "   - 4 numeric digits = ~13 bits (FAIL)\n"
        "3. In Intruder, attempt to brute-force a valid code with a numeric range.\n"
        "PASS: Codes are >= 6 digits, rate-limited, and single-use.\n"
        "FAIL: Codes are short (4 digits), predictable, or not rate-limited."),
    "ASVS-098": ("OTP Expiry Enforced", "Repeater",
        "1. Request a one-time code (password reset, OTP).\n"
        "2. Wait for the stated expiry period (or 10 minutes if unstated).\n"
        "3. In Repeater, attempt to use the expired code.\n"
        "PASS: Expired code is rejected.\n"
        "FAIL: Expired code is accepted."),
    "ASVS-099": ("MFA Factor Revocation Available", "Manual",
        "1. In account security settings, locate the MFA management page.\n"
        "2. Verify there is an option to remove/revoke individual MFA devices.\n"
        "3. Verify there is an option to revoke all active sessions when revoking.\n"
        "PASS: MFA factors can be revoked and sessions are invalidated.\n"
        "FAIL: No revocation option exists or revoking MFA does not end active sessions."),
    "ASVS-100": ("Biometrics Used as Secondary Factor Only", "Manual",
        "1. If the application uses biometrics, verify it requires a first factor\n"
        "   (password/PIN) in addition to biometric verification.\n"
        "2. Attempt to access the application with biometrics only (no password).\n"
        "PASS: Biometric alone does not grant access; requires additional factor.\n"
        "FAIL: Biometric alone is sufficient to authenticate."),
    "ASVS-101": ("PSTN MFA Downgrade Path Disclosed", "Manual",
        "1. Enroll SMS-based MFA.\n"
        "2. During MFA challenge, check if there is a 'use another method' option.\n"
        "3. Verify SMS/phone is documented as a weaker fallback, not the primary method.\n"
        "PASS: Application discloses PSTN risk or uses it only as last-resort fallback.\n"
        "FAIL: SMS OTP is the primary/only MFA option with no disclosure of risks."),
    "ASVS-102": ("OTP Bound to Session", "Repeater",
        "1. Start an authentication session in browser A, receive OTP.\n"
        "2. In Repeater, submit the OTP but with the session cookie from browser B.\n"
        "PASS: OTP is rejected when submitted from a different session.\n"
        "FAIL: OTP from one session can be used in another."),
    "ASVS-103": ("OTP Brute-Force Protection", "Intruder",
        "1. Trigger an OTP send (password reset or MFA challenge).\n"
        "2. Capture the OTP submission request and send to Intruder.\n"
        "3. Set the OTP field as payload, use numeric range 000000-999999.\n"
        "4. Send 10-20 requests rapidly. Check if account is locked or throttled.\n"
        "PASS: Account is locked or rate-limited after 5-10 failed attempts.\n"
        "FAIL: Intruder can iterate through all possible OTP values without throttling."),
    "ASVS-104": ("Push Notification MFA Rate-Limited", "Manual",
        "1. Enroll push notification MFA (e.g. Duo, Okta Verify).\n"
        "2. Attempt to log in repeatedly, triggering multiple push notifications.\n"
        "3. Verify the application stops sending after a threshold (e.g. 5 pushes).\n"
        "PASS: Push notification rate is throttled and account is locked after threshold.\n"
        "FAIL: Unlimited push notifications can be sent (MFA fatigue attack possible)."),
    "ASVS-105": ("IdP Identity Binding Secure", "Proxy/Manual",
        "1. If the application uses SSO (SAML, OIDC), intercept the auth assertion.\n"
        "2. Modify the 'sub', 'email', or 'nameID' claim to another user's identifier.\n"
        "3. Forward the modified assertion to the application.\n"
        "PASS: Application validates the assertion signature and rejects tampering.\n"
        "FAIL: Application accepts a modified assertion and logs in as another user."),
    "ASVS-106": ("Auth Assertion Signature Validated", "Repeater",
        "1. Capture a SAML response (in Proxy, base64-decode the SAMLResponse field).\n"
        "2. Modify a claim value in the assertion XML.\n"
        "3. Re-encode and send the modified SAMLResponse in Repeater.\n"
        "PASS: Application rejects the assertion because the signature is now invalid.\n"
        "FAIL: Application accepts the tampered assertion (signature not verified)."),
    "ASVS-107": ("IdP-Provided Claims Not Overridable", "Repeater",
        "1. After SSO authentication, find requests that contain user attributes.\n"
        "2. In Repeater, modify role/group/email values in the request.\n"
        "3. Check if the application uses the modified values or re-fetches from IdP.\n"
        "PASS: Application always uses IdP-provided claims; client modifications ignored.\n"
        "FAIL: Application accepts user-modified attribute values."),
    # -- Authorization ---------------------------------------------------------
    "ASVS-122": ("Object-Level Authorization (IDOR)", "Repeater",
        "1. As User A, find a URL referencing an object: /api/orders/1234\n"
        "2. In Repeater, replace 1234 with another user's object ID (1235, 1236...).\n"
        "3. Send with User A's session token.\n"
        "PASS: Server returns 403/404 for objects owned by other users.\n"
        "FAIL: Server returns another user's data (IDOR)."),
    "ASVS-123": ("Field-Level Authorization", "Repeater",
        "1. As a regular user, call an API endpoint that returns a user object.\n"
        "2. Check if the response includes admin-only fields (role, internalId, etc.).\n"
        "3. In Repeater, try sending a request to an admin endpoint with a user token.\n"
        "PASS: Admin-only fields are absent from regular user responses.\n"
        "FAIL: Sensitive fields are returned to non-privileged users."),
    "ASVS-124": ("Adaptive Auth Controls Based on Context", "Repeater",
        "1. Find a sensitive action (e.g. fund transfer, admin change).\n"
        "2. In Repeater, replay the action from a different IP (use Proxy settings)\n"
        "   or modify User-Agent/Accept-Language to simulate a new device.\n"
        "3. Check if re-authentication or step-up auth is triggered.\n"
        "PASS: Unusual context triggers step-up authentication.\n"
        "FAIL: Sensitive actions are allowed regardless of contextual changes."),
    "ASVS-125": ("Authorization Enforced Server-Side", "Repeater",
        "1. As a regular user, identify admin-only API endpoints from JS source or\n"
        "   API documentation (e.g. /api/admin/users, /api/config/update).\n"
        "2. In Repeater, call each endpoint with a regular user session token.\n"
        "PASS: Admin endpoints return 401/403 for non-admin users.\n"
        "FAIL: Admin functionality is accessible to regular users."),
    "ASVS-126": ("Authorization Decisions Applied Immediately", "Repeater",
        "1. Establish two sessions: Admin (A) and User (U).\n"
        "2. In A's session, revoke User U's access or demote their role.\n"
        "3. Immediately in Repeater using U's session token, call a privileged endpoint.\n"
        "PASS: U's request is rejected immediately after role change.\n"
        "FAIL: U can still access privileged resources until session expires."),
    # -- Cryptography ---------------------------------------------------------
    "ASVS-167": ("Cryptographic Fail-Secure", "Repeater",
        "1. Find encrypted/signed data being passed to the server (e.g. encrypted cookie,\n"
        "   signed token, padded cipher value).\n"
        "2. In Repeater, flip individual bytes in the encrypted value and observe errors.\n"
        "3. Check if error responses differ based on which byte was flipped (oracle).\n"
        "4. Use Burp's Hackvertor extension for automated padding oracle testing.\n"
        "PASS: All invalid ciphertext attempts produce identical, generic error responses.\n"
        "FAIL: Different errors for different byte positions indicate a padding oracle."),
    # -- Data Protection -------------------------------------------------------
    "ASVS-184": ("EXIF/Metadata Stripped from Uploaded Files", "Manual",
        "1. Create a test image with EXIF metadata (GPS, author, device info).\n"
        "   Use ExifTool: exiftool -GPSLatitude=51.5 -GPSLongitude=-0.1 test.jpg\n"
        "2. Upload the image via the application's upload feature.\n"
        "3. Download/view the uploaded image and check its EXIF data:\n"
        "   exiftool downloaded_image.jpg\n"
        "PASS: EXIF metadata is stripped from the served file.\n"
        "FAIL: Original EXIF metadata (especially GPS) is preserved in the served file."),
    # -- Encoding and Sanitization ---------------------------------------------
    "ASVS-001": ("Canonical Decoding Before Validation", "Repeater",
        "1. Find an input that is validated (e.g. a URL or path parameter).\n"
        "2. In Repeater, try double-encoding: %252e%252e%252f (double-encoded ../)\n"
        "3. Try Unicode normalization: \\u002e\\u002e\\u002f for ../\n"
        "4. Try overlong UTF-8: \\xc0\\xaf for /\n"
        "PASS: All encoded variants of forbidden characters are rejected.\n"
        "FAIL: Double-encoded or alternate representations bypass validation."),
    "ASVS-004": ("XSS via JS Context Injection", "Repeater",
        "1. Find a page that reflects user input inside a JavaScript context:\n"
        "   var x = 'USER_INPUT';\n"
        "2. In Repeater, inject: '; alert(1); var x='\n"
        "3. Also try: \\x3cscript\\x3ealert(1)\\x3c/script\\x3e (hex-encoded)\n"
        "PASS: Injection is escaped; no JS execution occurs.\n"
        "FAIL: Injected JavaScript executes in the browser."),
    "ASVS-006": ("OS Command Injection", "Repeater",
        "1. Find parameters that might invoke OS commands (file operations, ping, etc.).\n"
        "2. In Repeater, inject: ; id, && whoami, | ls -la, `id`\n"
        "3. Also test blind injection: ; sleep 5 (observe response time increase).\n"
        "PASS: Command separators are rejected or neutralized; no OS output returned.\n"
        "FAIL: Command output appears in response or time delay confirms execution."),
    "ASVS-007": ("LDAP Injection", "Repeater",
        "1. Find a login or search form that queries LDAP (directory services).\n"
        "2. In Repeater, inject LDAP metacharacters in username: *)(uid=*\n"
        "3. Try: admin)(&) and *)(objectClass=*\n"
        "PASS: Input is escaped; no LDAP injection behavior observed.\n"
        "FAIL: Authentication bypass or unexpected query results occur."),
    "ASVS-008": ("XPath Injection", "Repeater",
        "1. Find XML-based search or authentication endpoints.\n"
        "2. In Repeater, inject XPath payloads: ' or '1'='1\n"
        "   For blind: ' or count(/)=1 and '1'='1\n"
        "PASS: XPath metacharacters are rejected.\n"
        "FAIL: Authentication bypass or data extraction occurs."),
    "ASVS-009": ("CSV Formula Injection", "Repeater",
        "1. Find any feature that exports data to CSV (reports, user lists, orders).\n"
        "2. In Repeater, submit data containing: =SUM(1+1), +cmd|' /C calc'!A0\n"
        "3. Download the resulting CSV and open it in a text editor.\n"
        "PASS: The exported value is quoted and the leading = is escaped (prefixed with ').\n"
        "FAIL: The formula is unescaped in the CSV output."),
    "ASVS-010": ("HTML Sanitization in WYSIWYG", "Repeater",
        "1. Find a rich text editor (WYSIWYG) in the application.\n"
        "2. In Repeater, submit HTML containing: <script>alert(1)</script>\n"
        "3. Also try: <img src=x onerror=alert(1)>, <svg onload=alert(1)>\n"
        "4. View the output in the browser.\n"
        "PASS: Script tags and event handlers are stripped or encoded.\n"
        "FAIL: JavaScript executes when the content is rendered."),
    "ASVS-011": ("Context-Appropriate Sanitization", "Repeater",
        "1. Identify all output contexts: HTML body, HTML attribute, JS, CSS, URL.\n"
        "2. Inject context-specific payloads:\n"
        "   HTML body: <img src=x onerror=alert(1)>\n"
        "   HTML attr: \" onmouseover=\"alert(1)\n"
        "   JavaScript: '; alert(1); //\n"
        "   CSS: body{background:url('javascript:alert(1)')}\n"
        "PASS: Each context correctly encodes the relevant metacharacters.\n"
        "FAIL: Any context allows script execution."),
    "ASVS-012": ("SVG Script Content Sanitized", "Repeater",
        "1. Find an SVG upload or inline SVG feature.\n"
        "2. Upload an SVG containing: <svg><script>alert(1)</script></svg>\n"
        "3. Also try: <svg><foreignObject><body xmlns='http://www.w3.org/1999/xhtml'>\n"
        "   <script>alert(1)</script></body></foreignObject></svg>\n"
        "PASS: SVG script content is stripped or sanitized.\n"
        "FAIL: Script executes when the SVG is rendered."),
    "ASVS-013": ("Template/Markdown Expression Injection", "Repeater",
        "1. Find fields that accept Markdown, BBCode, or template expressions.\n"
        "2. In Repeater, inject: {{7*7}}, ${7*7}, #{7*7}, <%= 7*7 %>\n"
        "3. Also try: [[7*7]] and [[${''.class.forName('java.lang.Runtime')}]]\n"
        "PASS: Template expressions are not evaluated; shown as literal text.\n"
        "FAIL: Expression result (49) appears in the response (template injection)."),
    "ASVS-014": ("SSRF Prevention", "Repeater",
        "1. Find parameters that accept URLs or hostnames (webhook, import, fetch).\n"
        "2. In Repeater, inject internal addresses:\n"
        "   http://127.0.0.1/, http://169.254.169.254/latest/meta-data/\n"
        "   http://192.168.1.1/, http://10.0.0.1/\n"
        "3. Use Burp Collaborator: set URL to your Collaborator payload.\n"
        "PASS: Internal URLs are rejected; no Collaborator interaction observed.\n"
        "FAIL: Internal content is returned or Collaborator receives a DNS/HTTP ping."),
    "ASVS-015": ("Template Injection via Dynamic Templates", "Repeater",
        "1. Find features that generate content from user-provided templates\n"
        "   (email templates, PDF generation, report builders).\n"
        "2. Inject: {{7*7}}, {7*7}, <% 7*7 %>, #{7*7}\n"
        "3. Check if arithmetic result (49) appears in output.\n"
        "PASS: Expressions are treated as literals.\n"
        "FAIL: Expressions are evaluated (server-side template injection)."),
    "ASVS-016": ("JNDI Injection", "Repeater",
        "1. Find HTTP headers or parameters that may be logged (User-Agent, X-Forwarded-For).\n"
        "2. In Repeater, inject a Burp Collaborator JNDI payload:\n"
        "   ${jndi:ldap://YOUR_COLLABORATOR_PAYLOAD/a}\n"
        "3. Check Collaborator for incoming LDAP/DNS connections.\n"
        "PASS: No Collaborator interaction (JNDI lookup not triggered).\n"
        "FAIL: Collaborator receives a connection (Log4Shell or similar)."),
    "ASVS-017": ("Memcache Injection", "Repeater",
        "1. Find parameters that may map to cache keys (user preferences, session data).\n"
        "2. In Repeater, inject Memcache metacharacters: \\r\\nset injected 0 0 5\\r\\nhello\n"
        "3. Check if a subsequent fetch of 'injected' returns 'hello'.\n"
        "PASS: Newline injection is neutralized; no cache poisoning occurs.\n"
        "FAIL: Injected cache entries can be retrieved."),
    "ASVS-018": ("SMTP/IMAP Header Injection", "Repeater",
        "1. Find any form that sends email (contact form, notification settings).\n"
        "2. In Repeater, inject in the 'To' or 'Subject' field:\n"
        "   test@example.com\\r\\nBcc: attacker@evil.com\n"
        "3. Check if a BCC copy is sent to the injected address.\n"
        "PASS: CRLF in email fields is rejected or stripped.\n"
        "FAIL: Additional recipients or headers are injected into the email."),
    "ASVS-019": ("ReDoS Prevention", "Repeater",
        "1. Find input fields with regex-based validation (email, phone, postcode).\n"
        "2. In Repeater, send a ReDoS payload for each field:\n"
        "   Email: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@b.c (50+ 'a')\n"
        "   Phone: 0000000000000000000000000000000000000000000000000\n"
        "3. Measure response time. Repeat with increasing length.\n"
        "PASS: Response time is consistent regardless of input length.\n"
        "FAIL: Response time grows super-linearly with input length (exponential backtracking)."),
    "ASVS-021": ("Safe Deserialization", "Repeater",
        "1. Find endpoints that accept serialized objects (Java, PHP, Python pickle,\n"
        "   .NET viewstate, JSON with type hints, XML with class attributes).\n"
        "2. Use ysoserial (Java), PHPGGC (PHP), or pickle-tools to generate payloads.\n"
        "3. In Repeater, send the crafted payload to the endpoint.\n"
        "   Alternatively, use Burp's Java Deserialization Scanner extension.\n"
        "PASS: Deserialization of untrusted data is rejected or allowlisted.\n"
        "FAIL: Command execution or error reveals deserialization is occurring."),
    # -- File Handling ---------------------------------------------------------
    "ASVS-071": ("Compressed File Size Limits", "Repeater",
        "1. Find a file upload that accepts ZIP, GZIP, DOCX, or similar.\n"
        "2. Create a zip bomb: a small file that expands to GB when decompressed.\n"
        "   Use: dd if=/dev/zero bs=1M count=1000 | gzip > bomb.gz (1GB uncompressed)\n"
        "3. Upload in Repeater. Monitor response time and server memory.\n"
        "PASS: Server rejects files exceeding size limits before full extraction.\n"
        "FAIL: Server attempts to extract, causing timeout or memory exhaustion."),
    "ASVS-072": ("Per-User Upload Quota Enforced", "Repeater",
        "1. Find the maximum allowed file size and upload count.\n"
        "2. In Repeater, upload files in a loop until the quota should be reached.\n"
        "3. Verify that subsequent uploads are rejected with a 400/403 quota error.\n"
        "PASS: Upload is rejected once quota is exceeded.\n"
        "FAIL: No quota is enforced; unlimited files can be uploaded."),
    "ASVS-073": ("No Symlink in Uploaded Archives", "Repeater",
        "1. Create a ZIP file containing a symlink: ln -s /etc/passwd link.txt; zip --symlinks test.zip link.txt\n"
        "2. Upload this ZIP in Repeater.\n"
        "3. If the application extracts the archive, check if the symlink is followed\n"
        "   (i.e., if link.txt serves /etc/passwd content).\n"
        "PASS: Symlinks inside archives are ignored or rejected.\n"
        "FAIL: Symlink is extracted and followed, exposing server filesystem."),
    "ASVS-074": ("Image Pixel Size Limit Enforced", "Repeater",
        "1. Create an image with extreme dimensions (e.g. 100000x100000 pixels, 1KB file\n"
        "   using a PNG with decompression bomb properties).\n"
        "2. In Repeater, upload the image.\n"
        "PASS: Server rejects or limits images above a maximum pixel dimension.\n"
        "FAIL: Server attempts to process, causing timeout or memory exhaustion."),
    "ASVS-076": ("Path Traversal in File Operations", "Repeater",
        "1. Find any file download or delete endpoint: /download?file=report.pdf\n"
        "2. In Repeater, try path traversal payloads:\n"
        "   file=../../../etc/passwd\n"
        "   file=..%2F..%2F..%2Fetc%2Fpasswd\n"
        "   file=....//....//etc/passwd\n"
        "PASS: Request is rejected or restricted to allowed directory.\n"
        "FAIL: /etc/passwd or other system files are returned."),
    # -- OAuth and OIDC --------------------------------------------------------
    "ASVS-134": ("OAuth State Parameter Validated (CSRF)", "Proxy/Manual",
        "1. Start an OAuth flow in the browser. Capture the authorization_request URL.\n"
        "2. Copy the 'state' parameter value.\n"
        "3. In Repeater, send the authorization callback with a modified state value.\n"
        "PASS: Application rejects the callback when state does not match.\n"
        "FAIL: Application accepts the callback regardless of state value."),
    "ASVS-135": ("PKCE Required for Authorization Code Flow", "Proxy",
        "1. In Proxy, intercept the OAuth authorization request.\n"
        "2. Check if 'code_challenge' and 'code_challenge_method' are present.\n"
        "3. Try removing code_challenge from the request and forwarding.\n"
        "PASS: Authorization server rejects requests without code_challenge.\n"
        "FAIL: Authorization proceeds without PKCE."),
    "ASVS-136": ("Mix-Up Attack Prevention", "Proxy",
        "1. If the application supports multiple OAuth providers, intercept the callback.\n"
        "2. Check if the response includes an 'iss' claim matching the expected provider.\n"
        "3. Try substituting a code from provider A into provider B's callback URL.\n"
        "PASS: Application validates 'iss' and rejects cross-provider code substitution.\n"
        "FAIL: Authorization code from one provider is accepted by another provider's flow."),
    "ASVS-137": ("OAuth Client Requests Minimal Scopes", "Proxy",
        "1. Intercept the OAuth authorization request in Proxy.\n"
        "2. Review the 'scope' parameter value.\n"
        "PASS: Only required scopes are requested (no 'admin', 'read:all', etc. unnecessarily).\n"
        "FAIL: Overly broad scopes are requested by the client."),
    "ASVS-138": ("Resource Server Validates Token Audience", "Repeater",
        "1. Obtain a valid access token for Service A.\n"
        "2. In Repeater, present this token to Service B's API endpoints.\n"
        "PASS: Service B rejects the token (audience mismatch).\n"
        "FAIL: Service B accepts a token intended for a different service."),
    "ASVS-139": ("Resource Server Enforces Scope/Claims", "Repeater",
        "1. Obtain an access token with limited scope (e.g. 'read').\n"
        "2. In Repeater, use this token to call write/admin API endpoints.\n"
        "PASS: Write operations are rejected when token only has 'read' scope.\n"
        "FAIL: Scope is not enforced; all operations allowed with any valid token."),
    "ASVS-140": ("Proof of Auth Strength in Token", "Proxy",
        "1. Log in with only username/password (no MFA) and obtain an access token.\n"
        "2. In Proxy, check the token's 'acr' (Authentication Context Class Reference) claim.\n"
        "3. Call a sensitive resource that requires MFA-level authentication.\n"
        "PASS: Sensitive resource requires higher 'acr' value and rejects password-only tokens.\n"
        "FAIL: Sensitive resources accept tokens regardless of authentication strength."),
    "ASVS-141": ("Sender-Constrained Tokens (DPoP/mTLS)", "Proxy",
        "1. Capture a bearer access token from normal authentication.\n"
        "2. In Repeater, use this token from a different client (no DPoP proof or mTLS cert).\n"
        "PASS: Server rejects the token without valid DPoP proof or client certificate.\n"
        "FAIL: Stolen bearer token is accepted from any client (no sender binding)."),
    "ASVS-142": ("Redirect URI Exact Match Validation", "Proxy",
        "1. Intercept the OAuth authorization request in Proxy.\n"
        "2. Modify redirect_uri to a similar but different URL:\n"
        "   From: https://app.example.com/callback\n"
        "   To:   https://attacker.com/callback\n"
        "   Also try: https://app.example.com.attacker.com/callback\n"
        "PASS: Authorization server rejects non-pre-registered redirect URIs.\n"
        "FAIL: Authorization code is sent to the attacker-controlled URI."),
    "ASVS-143": ("Authorization Code Single-Use", "Repeater",
        "1. Complete a normal OAuth flow and capture the authorization code.\n"
        "2. In Repeater, send the token request with the same code a second time.\n"
        "PASS: Second use of the code is rejected and previously issued tokens are revoked.\n"
        "FAIL: Code can be exchanged multiple times for tokens."),
    "ASVS-144": ("Authorization Code Short-Lived", "Manual",
        "1. Capture an authorization code from the OAuth callback URL.\n"
        "2. Wait 11 minutes (L1/L2) or 2 minutes (L3).\n"
        "3. In Repeater, attempt to exchange the aged code for a token.\n"
        "PASS: Server rejects the expired code.\n"
        "FAIL: Code is accepted after the maximum lifetime has elapsed."),
    "ASVS-145": ("Implicit/Password Grant Flows Disabled", "Proxy",
        "1. Intercept or manually craft an OAuth token request with:\n"
        "   grant_type=implicit or grant_type=password\n"
        "2. Send in Repeater.\n"
        "PASS: Server returns 400 (unsupported_grant_type).\n"
        "FAIL: Server issues tokens via implicit or password grant flows."),
    "ASVS-146": ("Refresh Token Replay Prevention", "Repeater",
        "1. Obtain a refresh token through normal OAuth flow.\n"
        "2. Use the refresh token once to get a new access token.\n"
        "3. In Repeater, use the original refresh token again.\n"
        "PASS: The already-used refresh token is rejected.\n"
        "FAIL: Used refresh tokens remain valid (no rotation or invalidation)."),
    "ASVS-147": ("PKCE code_verifier Validated", "Repeater",
        "1. Capture an OAuth token request that includes code_verifier.\n"
        "2. In Repeater, modify code_verifier to an incorrect value.\n"
        "PASS: Token request is rejected with invalid_grant.\n"
        "FAIL: Token is issued without verifying the PKCE code_verifier."),
    "ASVS-148": ("Dynamic Client Registration Restricted", "Repeater",
        "1. Check if the authorization server exposes a registration endpoint:\n"
        "   POST /oauth/register or POST /.well-known/openid-configuration registration\n"
        "2. In Repeater, attempt to register a new client without authentication.\n"
        "PASS: Unauthenticated registration is rejected or requires admin approval.\n"
        "FAIL: Any client can self-register without authorization."),
    "ASVS-149": ("Refresh Tokens Have Absolute Expiry", "Manual",
        "1. Obtain a refresh token and record the issuance time.\n"
        "2. Continue using the refresh token daily to reset sliding expiry.\n"
        "3. After 30+ days (or documented maximum), attempt to use the refresh token.\n"
        "PASS: Refresh token is rejected after absolute maximum lifetime.\n"
        "FAIL: Refresh tokens can be kept alive indefinitely via rotation."),
    "ASVS-150": ("Refresh Token Revocation Available", "Manual",
        "1. Log in to the application's security settings or authorization server UI.\n"
        "2. Verify there is an option to view and revoke OAuth authorizations.\n"
        "3. After revoking, attempt to use the associated refresh token in Repeater.\n"
        "PASS: Revoked refresh tokens are immediately rejected.\n"
        "FAIL: No revocation UI exists or revoked tokens remain valid."),
    "ASVS-151": ("Confidential Client Authentication Required", "Repeater",
        "1. Find the token endpoint URL.\n"
        "2. In Repeater, send a token request without client credentials\n"
        "   (remove client_secret or Authorization: Basic header).\n"
        "PASS: Token endpoint rejects requests without client authentication.\n"
        "FAIL: Token is issued without verifying client identity."),
    "ASVS-152": ("Minimal Scopes Assigned to Client", "Manual",
        "1. Review the OAuth server configuration or consent screen.\n"
        "2. Verify the registered scopes match only what the application needs.\n"
        "3. Attempt to authorize with additional scopes not in the client's allowlist.\n"
        "PASS: Authorization server only issues pre-configured scopes.\n"
        "FAIL: Client can request and receive scopes beyond its configuration."),
    "ASVS-153": ("response_mode Restricted per Client", "Proxy",
        "1. Intercept the authorization request.\n"
        "2. Add or modify: response_mode=fragment or response_mode=query\n"
        "3. Try response_mode=form_post if not configured.\n"
        "PASS: Unauthorized response_mode values are rejected.\n"
        "FAIL: Server accepts any response_mode regardless of client configuration."),
    "ASVS-154": ("PAR Required for Code Grant", "Proxy",
        "1. Attempt a standard authorization request without PAR:\n"
        "   GET /authorize?response_type=code&client_id=...&redirect_uri=...\n"
        "2. Check if server requires a pushed authorization request first.\n"
        "PASS: Server rejects direct authorization requests; requires PAR.\n"
        "FAIL: Authorization proceeds without pushed authorization request."),
    "ASVS-155": ("Sender-Constrained Access Tokens Issued", "Proxy",
        "1. After token issuance, inspect the access token (decode JWT if structured).\n"
        "2. Check for 'cnf' (confirmation) claim indicating DPoP or mTLS binding.\n"
        "3. Use the token from a client without the corresponding proof.\n"
        "PASS: Token includes cnf claim; usage without proof is rejected.\n"
        "FAIL: Plain bearer tokens are issued with no sender binding."),
    "ASVS-156": ("PAR Required for Server-Side Clients", "Proxy",
        "1. For a server-side application, intercept the authorization flow.\n"
        "2. Check whether the authorization_details parameter is submitted via PAR.\n"
        "3. Try submitting authorization_details directly in the front-channel.\n"
        "PASS: Server-side authorization details are only accepted via PAR or JAR.\n"
        "FAIL: authorization_details can be passed directly in the authorization URL."),
    "ASVS-157": ("Strong Client Authentication Required", "Repeater",
        "1. Attempt client authentication with a shared secret (client_secret).\n"
        "2. Verify whether the server requires public-key based auth (mTLS or private_key_jwt).\n"
        "3. Try sending a token request with only client_secret instead of a signed JWT.\n"
        "PASS: Server rejects shared-secret auth for confidential clients.\n"
        "FAIL: client_secret is accepted as the sole client authentication method."),
    "ASVS-158": ("OIDC ID Token nonce Validated", "Proxy",
        "1. Intercept the authorization request and note the nonce value sent.\n"
        "2. After receiving the ID token, decode the JWT and verify the nonce claim.\n"
        "3. Try replaying the same ID token in a new authentication request.\n"
        "PASS: nonce in ID token matches the one sent; replay is rejected.\n"
        "FAIL: nonce is absent from ID token or replay is accepted."),
    "ASVS-159": ("Issuer Validated Against Pre-Configured Value", "Proxy",
        "1. Decode the ID token JWT and examine the 'iss' (issuer) claim.\n"
        "2. Try to obtain a token from a different authorization server with a\n"
        "   matching 'iss' claim but a different signing key.\n"
        "PASS: Client validates 'iss' against its pre-configured issuer URL exactly.\n"
        "FAIL: Client accepts tokens with a matching 'iss' from an unauthorized server."),
    "ASVS-160": ("ID Token Audience Validated", "Proxy",
        "1. Decode the ID token JWT and check the 'aud' claim.\n"
        "2. Verify 'aud' contains the client's registered client_id.\n"
        "3. Try using an ID token from one client application with another client.\n"
        "PASS: Application validates 'aud' matches its own client_id.\n"
        "FAIL: Application accepts ID tokens intended for other clients."),
    "ASVS-161": ("OIDC Back-Channel Logout Token Validated", "Repeater",
        "1. If the application supports back-channel logout, find the logout endpoint.\n"
        "2. In Repeater, send a crafted logout_token JWT:\n"
        "   - With typ=JWT instead of typ=logout+jwt\n"
        "   - With a 'nonce' claim included\n"
        "PASS: Server rejects tokens with wrong typ or with nonce claim present.\n"
        "FAIL: Any JWT is accepted as a valid logout token."),
    "ASVS-162": ("OIDC Provider Restricts response_type", "Proxy",
        "1. Intercept an OIDC authorization request.\n"
        "2. Try: response_type=token (implicit flow - should be rejected)\n"
        "3. Try: response_type=id_token (implicit - should be rejected)\n"
        "PASS: Only 'code' and 'id_token code' (if supported) are accepted.\n"
        "FAIL: Implicit flow (response_type=token) is accepted."),
    "ASVS-163": ("OIDC Logout DoS Prevention", "Repeater",
        "1. Find the OIDC front-channel logout endpoint.\n"
        "2. In Repeater, send a logout request without id_token_hint.\n"
        "3. Also try sending with an invalid id_token_hint.\n"
        "PASS: Server validates id_token_hint or prompts user before logout.\n"
        "FAIL: Any unauthenticated request to the logout endpoint logs out all sessions."),
    "ASVS-164": ("User Consent Required for Each Authorization", "Manual",
        "1. Complete an OAuth authorization flow and grant consent.\n"
        "2. Re-initiate the same authorization flow.\n"
        "3. Check if the consent screen is shown again or silently re-authorized.\n"
        "PASS: User is shown consent prompt for each distinct authorization.\n"
        "FAIL: Re-authorization is granted silently without user consent."),
    "ASVS-165": ("Consent Screen Shows Sufficient Information", "Manual",
        "1. Initiate an OAuth authorization flow.\n"
        "2. On the consent screen, verify it shows:\n"
        "   - Client application name and identity\n"
        "   - Requested scopes explained in plain language\n"
        "   - Duration of the authorization\n"
        "PASS: All required information is clearly displayed.\n"
        "FAIL: Consent screen is vague or does not identify the requesting application."),
    "ASVS-166": ("User Can Review and Revoke Consents", "Manual",
        "1. After completing OAuth authorization, navigate to account security settings.\n"
        "2. Verify there is a list of authorized applications and their granted scopes.\n"
        "3. Revoke an authorization and verify the associated tokens stop working.\n"
        "PASS: Users can view, modify, and revoke granted authorizations.\n"
        "FAIL: No interface exists to review or revoke OAuth consents."),
    # -- Secure Coding ---------------------------------------------------------
    "ASVS-194": ("Race Condition / TOCTOU Testing", "Repeater",
        "1. Find a sensitive operation: balance check + transfer, inventory check + purchase.\n"
        "2. In Repeater, create two identical requests for the same operation.\n"
        "3. Use Burp's 'Send in parallel' (group tab) to send both simultaneously.\n"
        "4. Check if both succeed when only one should (double-spend, over-booking).\n"
        "PASS: Only one of the parallel requests succeeds.\n"
        "FAIL: Both succeed, indicating no atomic check-then-act implementation."),
    # -- Secure Communication --------------------------------------------------
    "ASVS-169": ("TLS Cipher Suite Strength", "Target/Manual",
        "1. In Burp, go to Target > Site map > right-click the host > Spider/Audit.\n"
        "2. Use an external tool for definitive cipher analysis:\n"
        "   testssl.sh https://target.com\n"
        "   OR: nmap --script ssl-enum-ciphers -p 443 target.com\n"
        "3. Check for: TLS 1.0/1.1, RC4, 3DES, NULL, EXPORT, ANON ciphers.\n"
        "PASS: Only TLS 1.2/1.3 with AEAD ciphers (AES-GCM, ChaCha20-Poly1305) enabled.\n"
        "FAIL: Deprecated TLS versions or weak ciphers are supported."),
    "ASVS-170": ("mTLS Client Certificate Validation", "Repeater",
        "1. Find an API endpoint that should require mutual TLS.\n"
        "2. In Burp, go to Settings > Network > TLS > Client Certificates.\n"
        "3. Send a request WITHOUT a client certificate to the mTLS endpoint.\n"
        "4. Also try with an invalid/self-signed certificate.\n"
        "PASS: Server rejects connections without a trusted client certificate.\n"
        "FAIL: Server accepts connections without or with invalid client certificates."),
    # -- Self-contained Tokens -------------------------------------------------
    "ASVS-129": ("Token Signed with Trusted Key Material", "Proxy",
        "1. Obtain a JWT access token or ID token from the application.\n"
        "2. Decode the JWT header. Note the 'kid' (key ID) or 'jku'/'x5u' header.\n"
        "3. If 'jku' or 'x5u' is present, try substituting your own key URL.\n"
        "4. Generate a new JWT signed with your own key and set jku to your server.\n"
        "PASS: Server ignores user-supplied key URLs; only uses pre-configured keys.\n"
        "FAIL: Server fetches keys from the attacker-supplied URL and accepts the token."),
    "ASVS-130": ("Token Validity Time Enforced", "Repeater",
        "1. Obtain a JWT access token.\n"
        "2. Decode it and note the 'exp' (expiration) claim.\n"
        "3. Wait until after expiration (or modify system time in a test environment).\n"
        "4. In Repeater, use the expired token.\n"
        "PASS: Expired token is rejected with 401.\n"
        "FAIL: Expired token is accepted."),
    "ASVS-131": ("Token Type Validated Before Use", "Repeater",
        "1. Obtain both an access token and a refresh token (they are different types).\n"
        "2. In Repeater, present the refresh token as an Authorization Bearer token\n"
        "   to an API endpoint (where an access token is expected).\n"
        "3. Also try using an ID token as an access token.\n"
        "PASS: Server rejects wrong token types.\n"
        "FAIL: Server accepts any valid JWT regardless of its intended type."),
    "ASVS-132": ("Token Audience Claim Validated", "Repeater",
        "1. Obtain a valid JWT intended for Service A.\n"
        "2. In Repeater, present this token to Service B.\n"
        "3. Decode the JWT and verify the 'aud' claim only lists Service A.\n"
        "PASS: Service B rejects the token (audience mismatch).\n"
        "FAIL: Token is accepted by services not listed in its 'aud' claim."),
    "ASVS-133": ("Audience Restriction Prevents Token Reuse", "Repeater",
        "1. Identify two services sharing the same signing key.\n"
        "2. Obtain a token for Service A (aud=service-a).\n"
        "3. In Repeater, use this token to authenticate to Service B.\n"
        "PASS: Service B rejects the token (aud does not include service-b).\n"
        "FAIL: Shared signing key allows token reuse across services."),
    # -- Session Management ----------------------------------------------------
    "ASVS-108": ("Session Verification Server-Side Only", "Repeater",
        "1. Obtain a valid session token.\n"
        "2. In Repeater, modify the token value (change last few characters).\n"
        "3. Also try decoding a JWT session token and modifying claims without re-signing.\n"
        "PASS: Modified/invalid session tokens are always rejected.\n"
        "FAIL: Malformed token is accepted (session verified client-side)."),
    "ASVS-112": ("Session Inactivity Timeout Enforced", "Manual",
        "1. Log in and note the session token.\n"
        "2. Leave the browser idle for longer than the stated inactivity timeout.\n"
        "3. In Repeater, attempt a request using the session token.\n"
        "PASS: Session token is rejected after the inactivity period.\n"
        "FAIL: Session remains valid indefinitely without interaction."),
    "ASVS-113": ("Absolute Session Lifetime Enforced", "Manual",
        "1. Log in and record the session token.\n"
        "2. Keep the session active by making periodic requests.\n"
        "3. After the documented maximum session lifetime, attempt authentication.\n"
        "PASS: Session is forcibly terminated after the absolute maximum.\n"
        "FAIL: Session remains valid beyond the documented maximum lifetime."),
    "ASVS-115": ("Terminate Other Sessions Option Available", "Manual",
        "1. Log in from two different browsers/devices.\n"
        "2. In security settings, find 'Active sessions' or 'Log out all devices'.\n"
        "3. Use this to terminate the other session.\n"
        "4. In Repeater, test that the terminated session token is now rejected.\n"
        "PASS: Other active sessions are immediately invalidated.\n"
        "FAIL: No option to terminate other sessions exists or termination has no effect."),
    "ASVS-117": ("Re-Authentication for Sensitive Actions", "Repeater",
        "1. Log in. Perform a sensitive action (email change, password reset, payment).\n"
        "2. Note if re-authentication (password prompt) is required.\n"
        "3. In Repeater, send the sensitive action request directly without the re-auth step.\n"
        "PASS: Sensitive actions require re-authentication and cannot be bypassed.\n"
        "FAIL: Sensitive actions succeed without re-authentication."),
    "ASVS-118": ("Active Sessions Visible and Terminable", "Manual",
        "1. Log in from multiple devices/browsers.\n"
        "2. Navigate to account security settings.\n"
        "3. Verify each active session is listed with device/time information.\n"
        "4. Terminate a specific session and verify it is invalidated in Repeater.\n"
        "PASS: All sessions are visible; individual sessions can be terminated.\n"
        "FAIL: No session management UI exists."),
    "ASVS-119": ("Step-Up Auth for High-Value Operations", "Repeater",
        "1. Complete a step-up authentication flow (re-enter password or MFA).\n"
        "2. Capture the step-up token or cookie that authorizes the sensitive action.\n"
        "3. In Repeater, skip the step-up step and submit the sensitive action directly.\n"
        "PASS: Step-up verification cannot be bypassed.\n"
        "FAIL: Sensitive action succeeds without completing the step-up challenge."),
    "ASVS-120": ("Session Terminated at IdP and RP on Logout", "Manual",
        "1. Log in via SSO/OIDC.\n"
        "2. Log out from the application (relying party).\n"
        "3. Without re-authenticating, try to access the application again.\n"
        "4. Check if the IdP also considers you logged out.\n"
        "PASS: Both RP and IdP sessions are terminated on logout.\n"
        "FAIL: Logging out of RP leaves IdP session active (or vice versa)."),
    "ASVS-121": ("Session Creation Requires Explicit User Action", "Manual",
        "1. Open the application in a fresh browser tab (no prior session).\n"
        "2. Verify that no session cookie is set until the user actively logs in.\n"
        "3. Check that pre-authentication cookies (if any) are separate from session tokens.\n"
        "PASS: Session token is only created after explicit login action.\n"
        "FAIL: Session tokens are created on first visit without authentication."),
    # -- Validation and Business Logic -----------------------------------------
    "ASVS-024": ("Business Logic Flow Order Enforced", "Repeater",
        "1. Identify a multi-step flow (checkout: add to cart > shipping > payment > confirm).\n"
        "2. In Repeater, try to jump directly to step 3 or 4 without completing step 2.\n"
        "3. Try accessing the final step URL directly with a crafted request.\n"
        "PASS: Skipping earlier steps is detected and rejected.\n"
        "FAIL: Final step can be reached directly, bypassing earlier required steps."),
    "ASVS-026": ("Human Timing Required for Business Logic", "Intruder",
        "1. Find a transaction that should take human time (form submission, purchase).\n"
        "2. In Intruder, set up a rapid-fire attack against the endpoint.\n"
        "3. Send 10+ requests per second and observe if all are accepted.\n"
        "PASS: Application enforces minimum time between transactions or throttles.\n"
        "FAIL: All rapid-fire requests succeed (no timing or rate enforcement)."),
    # -- Web Frontend Security -------------------------------------------------
    "ASVS-044": ("Separate Applications on Separate Hostnames", "Target/Manual",
        "1. In Target > Site map, identify distinct applications hosted on the same domain.\n"
        "2. Check if cookies from Application A are sent to Application B's paths.\n"
        "3. Check if localStorage/sessionStorage keys from A are accessible to B.\n"
        "PASS: Each distinct application uses its own hostname.\n"
        "FAIL: Multiple applications share a hostname, allowing cookie/storage sharing."),
    "ASVS-048": ("Authenticated Resources Use Sec-Fetch-* Validation", "Repeater",
        "1. Find an endpoint serving authenticated resources (images, scripts, user data).\n"
        "2. In Repeater, send the request with modified Sec-Fetch-* headers:\n"
        "   Sec-Fetch-Site: cross-site\n"
        "   Sec-Fetch-Mode: no-cors\n"
        "   Sec-Fetch-Dest: image\n"
        "3. Check if the server validates these headers.\n"
        "PASS: Server rejects cross-origin requests for authenticated resources.\n"
        "FAIL: Authenticated resources are served regardless of Sec-Fetch-* values."),
    "ASVS-049": ("External Resources Use SRI", "Target/Manual",
        "1. In Target > Site map, browse the application and note external script/CSS URLs.\n"
        "2. In Proxy, capture HTML responses and search for <script src='https://\n"
        "3. Check each external resource tag for the 'integrity' attribute.\n"
        "PASS: All external scripts and stylesheets have a valid integrity= attribute.\n"
        "FAIL: Any external resource is loaded without SRI integrity verification."),
    # -- WebRTC ----------------------------------------------------------------
    "ASVS-198": ("WebRTC TURN Server Not Abusable", "Manual",
        "1. Identify the TURN server credentials from WebRTC ICE configuration\n"
        "   (inspect JavaScript or intercepted API response for 'urls', 'username', 'credential').\n"
        "2. Use these credentials with a TURN client (turnutils_uclient or coturn test client)\n"
        "   to attempt to relay arbitrary TCP/UDP traffic.\n"
        "PASS: TURN server only allows WebRTC relay; general TCP proxying is blocked.\n"
        "FAIL: TURN server can be abused to proxy arbitrary traffic (TURN relay abuse)."),
    "ASVS-199": ("DTLS Version Approved", "Manual",
        "1. Capture WebRTC negotiation (SDP offer/answer) from Proxy or browser dev tools.\n"
        "2. Review the DTLS fingerprint and version in the SDP: 'a=fingerprint:' line.\n"
        "3. Use a WebRTC test tool or Wireshark to confirm DTLS 1.2+ is negotiated.\n"
        "PASS: Only DTLS 1.2 or 1.3 is used.\n"
        "FAIL: DTLS 1.0 or 1.1 is negotiated."),
    "ASVS-200": ("SRTP Authentication Checked", "Manual",
        "1. Capture WebRTC media traffic using a tool such as Chrome WebRTC internals.\n"
        "2. Verify the media is protected by SRTP (Secure Real-time Transport Protocol).\n"
        "3. Check that the SRTP_MASTER_KEY is derived from DTLS.\n"
        "PASS: All media is encrypted and authenticated via SRTP.\n"
        "FAIL: Media is sent over plain RTP without SRTP authentication."),
    "ASVS-201": ("Media Server Resilient to Malformed Packets", "Manual",
        "1. Use a WebRTC fuzzing tool (e.g. webrtc-fuzzer or custom RTP fuzzer)\n"
        "   to send malformed RTP/RTCP packets to the media server.\n"
        "2. Monitor the server for crashes or availability degradation.\n"
        "PASS: Media server continues processing valid traffic during fuzzing.\n"
        "FAIL: Malformed packets cause server crash or degraded service."),
    "ASVS-202": ("Media Server Resilient to Traffic Flood", "Manual",
        "1. Simulate a flood of RTP packets at 10x-100x normal bitrate to the media server.\n"
        "2. Use tools such as mgen or custom scripts.\n"
        "3. Monitor whether legitimate calls are affected.\n"
        "PASS: Media server applies rate limiting; legitimate sessions are not disrupted.\n"
        "FAIL: Flood causes legitimate call quality degradation or server unavailability."),
    "ASVS-203": ("No ClientHello Race Condition", "Manual",
        "1. Research whether the media server's DTLS implementation was vulnerable to\n"
        "   CVE-2021-3449 (ClientHello Race Condition in OpenSSL).\n"
        "2. Check the DTLS library version: OpenSSL < 1.1.1k is vulnerable.\n"
        "PASS: Media server uses a patched DTLS implementation.\n"
        "FAIL: Media server uses a DTLS library vulnerable to ClientHello race conditions."),
    "ASVS-204": ("Recording Mechanisms Secure", "Manual",
        "1. If the application supports call recording, verify recordings are:\n"
        "   - Stored in a location inaccessible directly from the web\n"
        "   - Require authentication to access\n"
        "   - Are encrypted at rest\n"
        "2. Try accessing recording storage paths directly via Burp.\n"
        "PASS: Recordings are protected and not directly web-accessible.\n"
        "FAIL: Recording files are accessible without authentication."),
    "ASVS-205": ("DTLS Certificate Checked Against SDP Fingerprint", "Manual",
        "1. Intercept the SDP offer/answer (Proxy or browser dev tools).\n"
        "2. Note the 'a=fingerprint:sha-256 XX:XX...' value.\n"
        "3. Use Wireshark to capture the DTLS handshake and extract the certificate.\n"
        "4. Calculate the certificate fingerprint and compare with the SDP value.\n"
        "PASS: DTLS certificate fingerprint matches the SDP fingerprint exactly.\n"
        "FAIL: Application accepts WebRTC sessions where fingerprints do not match."),
    "ASVS-206": ("Signaling Server Resilient to Malformed Messages", "Manual",
        "1. Connect to the WebRTC signaling server (WebSocket).\n"
        "2. Send malformed SDP or signaling messages: truncated, oversized, invalid JSON.\n"
        "3. Monitor server availability and whether valid connections still work.\n"
        "PASS: Invalid signaling messages are rejected without affecting other sessions.\n"
        "FAIL: Malformed messages cause signaling server instability or crash."),
    "ASVS-207": ("Signaling Server Resilient to Message Flood", "Intruder",
        "1. Find the WebSocket signaling endpoint.\n"
        "2. In Burp's WebSockets history, replay messages rapidly using Repeater or a script.\n"
        "3. Monitor whether other users' signaling is affected.\n"
        "PASS: Per-connection rate limiting prevents flood from affecting other users.\n"
        "FAIL: Message flood degrades or disrupts other users' signaling sessions."),
}

# Build the manual checklist for ASVS: all Technical controls not in dispatch


# =============================================================================
# v5 checks: headers, cookies, CSP quality, credential leaks
# =============================================================================
# =============================================================================
# ASVS v5 additional checks - headers, cookies, CSP quality, credential leaks
# =============================================================================

# -- Security Header Checks ----------------------------------------------------

def chk_coep(rh, qh, body, url, mi, h, cb):
    """Cross-Origin-Embedder-Policy missing on HTML responses"""
    if not _is_html(rh): return None
    if not _get_header(rh, "Cross-Origin-Embedder-Policy"):
        return _finding("ASVS-040", "Missing Cross-Origin-Embedder-Policy Header",
                        "Low", url,
                        "Cross-Origin-Embedder-Policy (COEP) header is absent.\n"
                        "COEP prevents cross-origin resources from being loaded unless "
                        "they explicitly grant permission, protecting against Spectre-style "
                        "side-channel attacks (ASVS V3.4.8).")
    return None


def chk_xxss_deprecated(rh, qh, body, url, mi, h, cb):
    """X-XSS-Protection header still set (deprecated and harmful)"""
    if not _is_html(rh): return None
    val = _get_header(rh, "X-XSS-Protection") or ""
    if val.strip() not in ("", "0"):
        return _finding("ASVS-035", "X-XSS-Protection Header Is Deprecated and Should Be Removed",
                        "Low", url,
                        "X-XSS-Protection: %s is set. This header is deprecated and "
                        "can introduce XSS vulnerabilities in older browsers.\n"
                        "Remove this header entirely or set to '0'. "
                        "Use a strong CSP instead (ASVS V3.4)." % val)
    return None


def chk_cors_credentials(rh, qh, body, url, mi, h, cb):
    """CORS: Access-Control-Allow-Credentials: true with wildcard or reflected origin"""
    acac = _get_header(rh, "Access-Control-Allow-Credentials") or ""
    if acac.strip().lower() != "true": return None
    acao = _get_header(rh, "Access-Control-Allow-Origin") or ""
    origin_req = _get_header(qh, "Origin") or ""
    if acao.strip() == "*":
        return _finding("ASVS-034", "CORS: Credentials Allowed with Wildcard Origin",
                        "High", url,
                        "Access-Control-Allow-Credentials: true combined with "
                        "Access-Control-Allow-Origin: * is invalid per the spec "
                        "but some servers implement it anyway.\n"
                        "This configuration allows any origin to make credentialed "
                        "cross-origin requests (ASVS V3.5.8).")
    if origin_req and acao.strip() == origin_req.strip():
        return _finding("ASVS-034", "CORS: Origin Reflected with Credentials Allowed",
                        "High", url,
                        "Server reflects the Origin header (%s) back in "
                        "Access-Control-Allow-Origin with credentials enabled.\n"
                        "Only explicitly allowlisted origins shall be permitted "
                        "(ASVS V3.5.8)." % origin_req[:60])
    return None


def chk_cors_methods(rh, qh, body, url, mi, h, cb):
    """CORS: Overly permissive Access-Control-Allow-Methods"""
    acam = _get_header(rh, "Access-Control-Allow-Methods") or ""
    if not acam: return None
    dangerous = [m for m in ["DELETE", "PUT", "PATCH", "TRACE", "CONNECT"]
                 if m in acam.upper()]
    if "*" in acam:
        return _finding("ASVS-034", "CORS: Wildcard Access-Control-Allow-Methods",
                        "Medium", url,
                        "Access-Control-Allow-Methods: * permits any HTTP method "
                        "from cross-origin requests.\n"
                        "Only explicitly required methods shall be listed (ASVS V3.5.8).")
    if dangerous:
        return _finding("ASVS-034", "CORS: Dangerous Methods in Access-Control-Allow-Methods",
                        "Medium", url,
                        "Access-Control-Allow-Methods includes potentially dangerous "
                        "methods: %s\nVerify these are intentionally exposed to "
                        "cross-origin callers (ASVS V3.5.8)." % ", ".join(dangerous))
    return None


def chk_timing_allow_origin(rh, qh, body, url, mi, h, cb):
    """Timing-Allow-Origin wildcard exposes resource timing to all origins"""
    tao = _get_header(rh, "Timing-Allow-Origin") or ""
    if tao.strip() == "*":
        return _finding("ASVS-034", "Timing-Allow-Origin: * Exposes Resource Timing",
                        "Low", url,
                        "Timing-Allow-Origin: * allows any cross-origin page to read "
                        "detailed resource timing information for this response.\n"
                        "This can leak information about authentication state, content "
                        "size, and server processing time to attacker-controlled pages.")
    return None


def chk_server_timing(rh, qh, body, url, mi, h, cb):
    """Server-Timing header exposes backend performance metrics"""
    st = _get_header(rh, "Server-Timing") or ""
    if st:
        return _finding("ASVS-180", "Server-Timing Header Exposes Backend Metrics",
                        "Low", url,
                        "Server-Timing header reveals backend performance data: %s\n"
                        "This can disclose internal service names, database query times, "
                        "and infrastructure topology to clients and cross-origin pages "
                        "(ASVS V13.4.3)." % st[:120])
    return None


# -- Cookie Attribute Checks ---------------------------------------------------

def chk_cookie_httponly(rh, qh, body, url, mi, h, cb):
    """Session cookie missing HttpOnly flag"""
    missing = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if not hdr.lower().startswith("set-cookie:"): continue
        val = hdr.split(":", 1)[1]
        m = re.match(r"\s*([^=]+)=", val)
        if not m: continue
        name = m.group(1).strip()
        is_sess = any(s in name.lower() for s in
                      ["sess","sid","session","token","auth","jsessionid",
                       "phpsessid","asp.net_sessionid"])
        if is_sess and "httponly" not in val.lower():
            missing.append(name)
    if missing:
        return _finding("ASVS-029", "Session Cookie Missing HttpOnly Flag",
                        "High", url,
                        "Session cookies without HttpOnly: %s\n"
                        "HttpOnly prevents JavaScript from reading the cookie, "
                        "mitigating XSS-based session theft (ASVS V3.3.1)."
                        % ", ".join(missing[:5]))
    return None


def chk_cookie_domain_broad(rh, qh, body, url, mi, h, cb):
    """Cookie Domain attribute set too broadly"""
    issues = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if not hdr.lower().startswith("set-cookie:"): continue
        val = hdr.split(":", 1)[1]
        nm = re.match(r"\s*([^=]+)=", val)
        if not nm: continue
        name = nm.group(1).strip()
        dm = re.search(r"\bdomain\s*=\s*([^;,\s]+)", val, re.IGNORECASE)
        if dm:
            domain = dm.group(1).strip().lstrip(".")
            # Flag if domain has only one level (e.g. "example.com" when host is "app.example.com")
            host = str(url.getHost()).lower()
            if domain and domain != host and not host.endswith("." + domain):
                pass  # domain doesn't match host, unusual
            elif domain and domain == ".".join(host.split(".")[-2:]):
                issues.append("Cookie '%s' has Domain=%s (shared across all subdomains)"
                               % (name, domain))
    if issues:
        return _finding("ASVS-029", "Cookie Domain Attribute Too Broad",
                        "Low", url,
                        "\n".join(issues[:3]) +
                        "\nBroad Domain attributes share cookies with all subdomains, "
                        "including potentially untrusted ones (ASVS V3.3.2).")
    return None


def chk_cookie_persistent(rh, qh, body, url, mi, h, cb):
    """Session cookie with very long Max-Age or far-future Expires"""
    import re as _re
    issues = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if not hdr.lower().startswith("set-cookie:"): continue
        val = hdr.split(":", 1)[1]
        nm = re.match(r"\s*([^=]+)=", val)
        if not nm: continue
        name = nm.group(1).strip()
        is_sess = any(s in name.lower() for s in
                      ["sess","sid","session","auth","jsessionid","phpsessid"])
        if not is_sess: continue
        ma = re.search(r"\bmax-age\s*=\s*(\d+)", val, re.IGNORECASE)
        if ma:
            age = int(ma.group(1))
            if age > 86400 * 30:  # more than 30 days
                issues.append("Cookie '%s': Max-Age=%d seconds (%d days)"
                               % (name, age, age // 86400))
    if issues:
        return _finding("ASVS-029", "Session Cookie Has Excessive Lifetime",
                        "Low", url,
                        "\n".join(issues) +
                        "\nSession cookies shall expire within a reasonable period. "
                        "Long-lived sessions increase the window for session theft "
                        "(ASVS V3.3.4).")
    return None


def chk_secure_cookie_over_http(rh, qh, body, url, mi, h, cb):
    """Cookie with Secure flag served over HTTP (will be silently dropped)"""
    if str(url.getProtocol()).lower() == "https": return None
    issues = []
    for hdr in rh:
        if not isinstance(hdr, str): continue
        if not hdr.lower().startswith("set-cookie:"): continue
        val = hdr.split(":", 1)[1]
        if "secure" in val.lower():
            nm = re.match(r"\s*([^=]+)=", val)
            name = nm.group(1).strip() if nm else "unknown"
            issues.append(name)
    if issues:
        return _finding("ASVS-029", "Secure Cookie Served Over HTTP (Will Be Dropped)",
                        "Medium", url,
                        "Cookies with Secure flag set over HTTP: %s\n"
                        "Browsers silently drop Secure cookies received over HTTP. "
                        "This likely indicates a misconfiguration (ASVS V3.3.1)."
                        % ", ".join(issues[:5]))
    return None


# -- CSP Quality Checks --------------------------------------------------------

def chk_csp_quality(rh, qh, body, url, mi, h, cb):
    """CSP directive quality - unsafe-inline, unsafe-eval, wildcards"""
    if not _is_html(rh): return None
    csp = _get_header(rh, "Content-Security-Policy") or ""
    if not csp: return None  # chk_035 handles missing CSP
    issues = []
    csp_l = csp.lower()
    if "unsafe-inline" in csp_l and "script-src" in csp_l:
        issues.append("script-src contains 'unsafe-inline' (defeats XSS protection)")
    if "unsafe-eval" in csp_l:
        issues.append("CSP contains 'unsafe-eval' (allows eval(), new Function())")
    if "unsafe-inline" in csp_l and "style-src" in csp_l:
        issues.append("style-src contains 'unsafe-inline' (CSS injection possible)")
    if re.search(r"script-src[^;]*\*", csp_l):
        issues.append("script-src contains wildcard '*' (defeats CSP entirely)")
    if re.search(r"script-src[^;]*\bdata:", csp_l):
        issues.append("script-src allows data: URIs (can be used to inject scripts)")
    if re.search(r"script-src[^;]*\bhttp:", csp_l):
        issues.append("script-src allows http: scheme (downgrades to insecure resources)")
    if "default-src" not in csp_l:
        issues.append("CSP has no default-src fallback directive")
    if issues:
        return _finding("ASVS-035", "Content Security Policy Has Weak Directives",
                        "Medium", url,
                        "CSP quality issues found:\n* " + "\n* ".join(issues) +
                        "\n\nA strong CSP shall not use unsafe-inline, unsafe-eval, "
                        "or wildcards in script-src (ASVS V3.4.1).")
    return None


def chk_hsts_quality(rh, qh, body, url, mi, h, cb):
    """HSTS header quality - max-age too short or missing includeSubDomains"""
    if str(url.getProtocol()).lower() != "https": return None
    hsts = _get_header(rh, "Strict-Transport-Security") or ""
    if not hsts: return None  # chk_033 covers missing HSTS
    issues = []
    ma = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
    if ma:
        age = int(ma.group(1))
        if age < 31536000:
            issues.append("max-age=%d is less than 1 year (31536000 seconds)" % age)
    else:
        issues.append("max-age directive is missing from HSTS header")
    if "includesubdomains" not in hsts.lower():
        issues.append("includeSubDomains directive is missing")
    if issues:
        return _finding("ASVS-033", "HSTS Header Has Weak Configuration",
                        "Low", url,
                        "HSTS configuration issues: %s\n"
                        "Current header: %s\n"
                        "HSTS shall have max-age >= 31536000 and includeSubDomains "
                        "(ASVS V3.7.1)." % ("; ".join(issues), hsts[:100]))
    return None


# -- Credential/Secret Leak Checks --------------------------------------------

def chk_aws_key(rh, qh, body, url, mi, h, cb):
    """AWS access key exposed in response body"""
    m = re.search(r"\b(AKIA[0-9A-Z]{16})\b", body)
    if m:
        return _finding("ASVS-187", "AWS Access Key ID Exposed in Response",
                        "High", url,
                        "AWS Access Key ID pattern detected: %s...\n"
                        "Credentials shall never be included in HTTP responses. "
                        "Rotate this key immediately (ASVS V14.3.3)." % m.group(1)[:8],
                        body_snippet=_body_snippet(body, r"\bAKIA[0-9A-Z]{16}\b"))
    return None


def chk_private_key(rh, qh, body, url, mi, h, cb):
    """Private key block exposed in response"""
    if re.search(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----",
                 body, re.IGNORECASE):
        return _finding("ASVS-187", "Private Key Block Exposed in Response",
                        "High", url,
                        "Response contains a PEM private key block.\n"
                        "Private keys shall never be transmitted in HTTP responses. "
                        "Revoke and reissue the affected certificate immediately "
                        "(ASVS V14.3.3).",
                        body_snippet=_body_snippet(body,
                            r"-----BEGIN\s+(?:RSA|EC|DSA)?\s*PRIVATE KEY-----"))
    return None


def chk_db_connection_string(rh, qh, body, url, mi, h, cb):
    """Database connection string exposed in response"""
    patterns = [
        (r"(?:mysql|postgresql|postgres|mongodb|mssql|sqlserver|oracle)\s*://\s*\w+:[^@\s]{3,}@",
         "Database URI with credentials"),
        (r"Server\s*=\s*[^;]+;\s*Database\s*=\s*[^;]+;\s*(?:User|Uid)\s*=\s*[^;]+;\s*(?:Password|Pwd)\s*=\s*[^;]{3,}",
         "SQL Server connection string"),
        (r"Data\s+Source\s*=\s*[^;]+;\s*Initial\s+Catalog\s*=\s*[^;]+;\s*(?:User\s+ID|Password)\s*=\s*[^;]{3,}",
         "ADO.NET connection string"),
    ]
    for pat, desc in patterns:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            return _finding("ASVS-187", "Database Connection String in Response: %s" % desc,
                            "High", url,
                            "Response appears to contain a database connection string "
                            "with credentials.\n"
                            "Database credentials shall never appear in HTTP responses "
                            "(ASVS V14.3.3).",
                            body_snippet=_body_snippet(body, pat))
    return None


def chk_internal_hostname(rh, qh, body, url, mi, h, cb):
    """Internal hostnames disclosed in response body"""
    st = _get_status(rh)
    if st < 400: return None  # Only check error responses to reduce FPs
    patterns = [
        r"\b\w+\.internal\b",
        r"\b\w+\.corp\b",
        r"\b\w+\.local\b",
        r"\b\w+\.intranet\b",
        r"\b\w+\.lan\b",
    ]
    for pat in patterns:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            hostname = m.group(0)
            # Skip if it's just a TLD in a URL we already know
            if hostname.lower() in str(url).lower(): continue
            return _finding("ASVS-195", "Internal Hostname Disclosed in Error Response",
                            "Low", url,
                            "Error response reveals internal hostname: %s\n"
                            "Internal network topology shall not be exposed in responses "
                            "(ASVS V16.4.1)." % hostname,
                            body_snippet=_body_snippet(body, pat))
    return None


def chk_go_panic(rh, qh, body, url, mi, h, cb):
    """Go/Rust/Node panic or unhandled error in response"""
    st = _get_status(rh)
    if st < 400: return None
    checks = [
        (r"goroutine\s+\d+\s+\[running\]", "Go goroutine stack trace"),
        (r"panic:\s+runtime error:", "Go runtime panic"),
        (r"thread\s+'\w+'\s+panicked\s+at\s+'", "Rust thread panic"),
        (r"UnhandledPromiseRejectionWarning:", "Node.js unhandled promise rejection"),
        (r"Error:\s+Cannot\s+find\s+module\s+", "Node.js module error"),
        (r"at\s+(?:Object\.|Module\.|Function\.)[A-Z]\w+\s+\(.*:\d+:\d+\)", "Node.js stack trace"),
    ]
    for pat, desc in checks:
        if re.search(pat, body):
            return _finding("ASVS-195", "Runtime Error Exposed: %s" % desc,
                            "Medium", url,
                            "Response contains a %s. Runtime errors reveal "
                            "internal implementation details.\n"
                            "Generic error messages shall be used in production "
                            "(ASVS V16.4.2)." % desc,
                            body_snippet=_body_snippet(body, pat))
    return None


def chk_api_internal_class(rh, qh, body, url, mi, h, cb):
    """Internal class/package names in API error response"""
    ct = _get_header(rh, "Content-Type") or ""
    if "json" not in ct.lower(): return None
    st = _get_status(rh)
    if st < 400: return None
    # Detect Java/C# fully-qualified class names in error responses
    m = re.search(
        r'"(?:exception|error|class|type)"\s*:\s*"([a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*){2,}[A-Z]\w*)"',
        body, re.IGNORECASE)
    if m:
        cls = m.group(1)
        return _finding("ASVS-195", "Internal Class Name in API Error Response",
                        "Low", url,
                        "API error response reveals internal class name: %s\n"
                        "Internal implementation details shall not be exposed "
                        "in API error responses (ASVS V16.4.2)." % cls[:80],
                        body_snippet=_body_snippet(body,
                            r'"(?:exception|error|class|type)"\s*:'))
    return None

# =============================================================================
# v6 advanced checks
# =============================================================================

def chk_jwt_deep(rh, qh, body, url, mi, h, cb):
    """JWT deep inspection: kid injection, jku/x5u, claim validation, short secrets"""
    import base64, math
    # Collect JWTs from response body AND Authorization request header
    candidates = []
    auth = _get_header(qh, "Authorization") or ""
    if auth.lower().startswith("bearer "):
        candidates.append(auth[7:].strip())
    # Also from response body
    for m in re.finditer(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*',
                          body):
        candidates.append(m.group(0))
    for token in candidates:
        parts = token.split(".")
        if len(parts) < 2: continue
        try:
            def _b64d(s):
                s += "=" * (4 - len(s) % 4)
                return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")
            header_str = _b64d(parts[0])
            payload_str = _b64d(parts[1]) if len(parts) > 1 else "{}"

            # -- jku / x5u injection surface -----------------------------------
            if '"jku"' in header_str or '"x5u"' in header_str:
                return _finding("ASVS-129",
                    "JWT Contains jku/x5u Header (Key Injection Surface)",
                    "High", url,
                    "JWT header contains jku or x5u parameter pointing to an "
                    "external key URL.\n"
                    "If the server fetches keys from this URL without validation, "
                    "an attacker can supply their own signing key.\n"
                    "Key material shall only be loaded from pre-configured "
                    "trusted locations (ASVS V9.1.1).",
                    body_snippet=header_str[:200])

            # -- kid parameter injection ----------------------------------------
            kid_m = re.search(r'"kid"\s*:\s*"([^"]+)"', header_str)
            if kid_m:
                kid = kid_m.group(1)
                if any(c in kid for c in ["'", '"', ";", "--", "../", "/"]):
                    return _finding("ASVS-129",
                        "JWT kid Parameter Contains Suspicious Characters",
                        "High", url,
                        "JWT kid value contains characters suggestive of SQL "
                        "injection or path traversal: %s\n"
                        "The kid parameter shall be validated against an allowlist "
                        "(ASVS V9.1.1)." % kid[:60])

            # -- Expiry in the past ---------------------------------------------
            import time
            exp_m = re.search(r'"exp"\s*:\s*(\d+)', payload_str)
            if exp_m:
                exp = int(exp_m.group(1))
                now = int(time.time())
                if exp < now:
                    # Expired token still being used/served
                    return _finding("ASVS-130",
                        "Expired JWT Token in Use",
                        "Medium", url,
                        "A JWT token with exp=%d was found but current time is %d "
                        "(expired %d seconds ago).\n"
                        "Expired tokens shall not be accepted "
                        "(ASVS V9.1.3)." % (exp, now, now - exp))

            # -- iat far in the future (clock skew attack) ---------------------
            iat_m = re.search(r'"iat"\s*:\s*(\d+)', payload_str)
            if iat_m:
                iat = int(iat_m.group(1))
                now = int(time.time())
                if iat > now + 300:  # more than 5 min in future
                    return _finding("ASVS-129",
                        "JWT iat Claim Is in the Future",
                        "Low", url,
                        "JWT issued-at (iat=%d) is %d seconds in the future.\n"
                        "This may indicate a clock skew attack or token "
                        "manipulation (ASVS V9.1.3)." % (iat, iat - now))

            # -- HS256 with suspiciously short key hint -------------------------
            alg_m = re.search(r'"alg"\s*:\s*"([^"]+)"', header_str)
            alg = alg_m.group(1) if alg_m else ""
            if alg.upper() in ["HS256", "HS384", "HS512"]:
                # Check if secret is short (key length hint from token length)
                sig = parts[2] if len(parts) > 2 else ""
                if len(sig) < 20:
                    return _finding("ASVS-128",
                        "JWT HMAC Signature Appears Unusually Short",
                        "Medium", url,
                        "JWT uses %s but the signature is only %d chars "
                        "(base64url). This may indicate a very short secret key "
                        "susceptible to brute-force.\n"
                        "HMAC secrets shall be at least 32 bytes (ASVS V9.1.2)."
                        % (alg, len(sig)))

        except Exception:
            continue
    return None


def chk_graphql_introspect(rh, qh, body, url, mi, h, cb):
    """GraphQL: if introspection enabled, extract full schema via active probe"""
    us = str(url.getPath()).lower()
    ct = _get_header(rh, "Content-Type") or ""
    # Only probe if this looks like a GraphQL endpoint
    if not any(k in us for k in ["graphql", "gql", "query"]):
        if "graphql" not in body.lower() and "__schema" not in body.lower():
            return None
    if "json" not in ct.lower(): return None

    # Send introspection query
    introspection_query = (
        '{"query": "{ __schema { queryType { name } mutationType { name } '
        'types { name kind fields { name args { name } } } } }"}'
    )
    try:
        req_bytes = (
            "POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n%s"
        ) % (str(url.getPath()), str(url.getHost()),
             len(introspection_query), introspection_query)
        port = url.getPort() if url.getPort() > 0 else (
            443 if str(url.getProtocol()).lower()=="https" else 80)
        resp = cb.makeHttpRequest(
            cb.getHelpers().buildHttpService(
                str(url.getHost()), port,
                str(url.getProtocol()).lower()=="https"),
            cb.getHelpers().stringToBytes(req_bytes))
        if not resp: return None
        aresp = cb.getHelpers().analyzeResponse(resp)
        resp_body = cb.getHelpers().bytesToString(
            resp[aresp.getBodyOffset():])
        if "__schema" not in resp_body: return None
        # Extract mutation type names
        mutations = re.findall(r'"name"\s*:\s*"(\w+)"', resp_body)
        unique_m = list(dict.fromkeys(mutations))[:30]
        return _finding("ASVS-064",
            "GraphQL Introspection Enabled - Schema Extracted",
            "High", url,
            "GraphQL introspection is enabled and the full schema was "
            "retrieved.\n\nTypes/Fields found (%d): %s\n\n"
            "Introspection reveals the complete API attack surface.\n"
            "Disable introspection in production (ASVS V4.3.2)."
            % (len(unique_m), ", ".join(unique_m[:20])),
            body_snippet=resp_body[:300])
    except Exception:
        pass
    return None


def chk_cors_active_probe(rh, qh, body, url, mi, h, cb):
    """CORS: active probe with evil origin to confirm misconfiguration"""
    # Only probe if CORS headers present
    acao = _get_header(rh, "Access-Control-Allow-Origin") or ""
    if not acao: return None
    try:
        evil_origin = "https://evil.attacker-controlled.com"
        path = str(url.getPath()) or "/"
        if str(url.getQuery()): path += "?" + str(url.getQuery())
        req_str = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Origin: %s\r\n"
            "Connection: close\r\n\r\n"
        ) % (path, str(url.getHost()), evil_origin)
        port = url.getPort() if url.getPort() > 0 else (
            443 if str(url.getProtocol()).lower()=="https" else 80)
        resp = cb.makeHttpRequest(
            cb.getHelpers().buildHttpService(
                str(url.getHost()), port,
                str(url.getProtocol()).lower()=="https"),
            cb.getHelpers().stringToBytes(req_str))
        if not resp: return None
        aresp = cb.getHelpers().analyzeResponse(resp)
        resp_hdrs = list(aresp.getHeaders())
        resp_acao = None
        resp_acac = None
        for h2 in resp_hdrs:
            if isinstance(h2, str):
                if h2.lower().startswith("access-control-allow-origin:"):
                    resp_acao = h2.split(":",1)[1].strip()
                if h2.lower().startswith("access-control-allow-credentials:"):
                    resp_acac = h2.split(":",1)[1].strip()
        if resp_acao and evil_origin in resp_acao:
            severity = "High" if (resp_acac or "").lower() == "true" else "Medium"
            return _finding("ASVS-034",
                "CONFIRMED: CORS Reflects Arbitrary Origin%s" % (
                    " with Credentials" if severity=="High" else ""),
                severity, url,
                "Active CORS probe confirmed: server reflects the evil origin\n"
                "Access-Control-Allow-Origin: %s\n"
                "Access-Control-Allow-Credentials: %s\n\n"
                "Any cross-origin site can make requests to this endpoint%s.\n"
                "Only explicitly allowlisted origins shall be permitted "
                "(ASVS V3.5.8)." % (
                    resp_acao, resp_acac or "not set",
                    " and read the credentialed response" if severity=="High"
                    else ""))
    except Exception:
        pass
    return None


def chk_header_injection(rh, qh, body, url, mi, h, cb):
    """Header injection: detect if user-supplied values appear unescaped in response headers"""
    # Check URL query parameters reflected in response headers
    us = str(url)
    params = us.split("?", 1)[1] if "?" in us else ""
    if not params: return None
    for part in params.split("&"):
        if "=" not in part: continue
        key, _, val = part.partition("=")
        if len(val) < 4: continue
        # Check if value appears in response headers (unescaped)
        for hdr in rh:
            if not isinstance(hdr, str): continue
            if hdr.lower().startswith(("http/", "set-cookie:")): continue
            if val in hdr and ":" in hdr:
                hdr_name = hdr.split(":")[0].strip()
                return _finding("ASVS-056",
                    "Possible Header Injection: URL Param in Response Header",
                    "High", url,
                    "URL parameter '%s' value '%s' appears unescaped in "
                    "response header '%s'.\n"
                    "HTTP response header injection can enable cache poisoning, "
                    "response splitting, and XSS.\n"
                    "User-supplied values shall be encoded before inclusion in "
                    "response headers (ASVS V4.1.3)." % (key[:30], val[:40], hdr_name[:40]),
                    body_snippet=hdr[:200])
    return None


# =============================================================================
# Dispatch table
# =============================================================================
_RAW_DISPATCH = {
    "ASVS-002": chk_002, "ASVS-003": chk_002,
    "ASVS-005": chk_005,
    "ASVS-020": chk_020,
    "ASVS-028": chk_028,
    "ASVS-029": chk_029,
    "ASVS-031": chk_031,
    "ASVS-033": chk_033,
    "ASVS-034": chk_034,
    "ASVS-035": chk_035,
    "ASVS-036": chk_036,
    "ASVS-037": chk_037,
    "ASVS-038": chk_038,
    "ASVS-039": chk_039,
    "ASVS-040": chk_040,
    "ASVS-046": chk_046,
    "ASVS-050": chk_050,
    "ASVS-051": chk_051, "ASVS-052": chk_051,
    "ASVS-054": chk_054,
    "ASVS-057": chk_057,
    "ASVS-064": chk_064,
    "ASVS-065": chk_065,
    "ASVS-075": chk_075,
    "ASVS-079": chk_079, "ASVS-084": chk_079,
    "ASVS-093": chk_093,
    "ASVS-110": chk_110, "ASVS-111": chk_110,
    "ASVS-114": chk_114,
    "ASVS-168": chk_168,
    "ASVS-175": chk_175,
    "ASVS-176": chk_176,
    "ASVS-177": chk_177,
    "ASVS-178": chk_178,
    "ASVS-180": chk_180,
    "ASVS-182": chk_182,
    "ASVS-186": chk_186,
    "ASVS-195": chk_195,
    "ASVS-PERM":  chk_perm_policy,
    "ASVS-SRI":   chk_sri,
    "ASVS-SJSON": chk_sensitive_json,
    "ASVS-JWT":   chk_jwt_in_body,
    "ASVS-CORP":  chk_corp,
    "ASVS-SSNO":  chk_samesite_none,
    "ASVS-LKCK":  chk_large_cookie,
    # v3 additions
    "ASVS-030":   chk_030,
    "ASVS-032":   chk_032,
    "ASVS-055":   chk_055,
    "ASVS-085":   chk_085,
    "ASVS-094":   chk_094,
    "ASVS-109":   chk_109,
    "ASVS-116":   chk_116,
    "ASVS-127":   chk_127_alg, "ASVS-128": chk_127_alg,
    "ASVS-173":   chk_173_creds,
    "ASVS-179":   chk_179,
    "ASVS-181":   chk_181,
    "ASVS-185":   chk_185,
    "ASVS-187":   chk_187,
    "ASVS-025":   chk_025_ratelimit,
    "ASVS-083":   chk_083_maxlen,
    "ASVS-087":   chk_083_maxlen,
    "ASVS-095":   chk_095_reset,
    # v4 additions
    "ASVS-027":   chk_027,
    "ASVS-041":   chk_041_csrf, "ASVS-042": chk_041_csrf,
    "ASVS-043":   chk_043_method,
    "ASVS-045":   chk_045_postmsg,
    "ASVS-047":   chk_047_js_auth,
    "ASVS-053":   chk_053_preload,
    "ASVS-056":   chk_056_proxy_hdrs,
    "ASVS-058":   chk_058_smuggling, "ASVS-059": chk_058_smuggling,
    "ASVS-060":   chk_060_http2_conn,
    "ASVS-063":   chk_063_graphql_depth,
    "ASVS-066":   chk_066_websocket_origin, "ASVS-067": chk_066_websocket_origin,
    "ASVS-077":   chk_077_content_disp, "ASVS-078": chk_077_content_disp,
    "ASVS-174":   chk_174_ssrf,
    "ASVS-183":   chk_183_cache_api,
    "ASVS-189":   chk_189_excess_fields,
    "ASVS-190":   chk_190_open_redirect_internal,
    "ASVS-191":   chk_191_mass_assign,
    "ASVS-192":   chk_192_proto_pollution,
    "ASVS-193":   chk_193_param_pollution,
    "ASVS-022":   chk_022_server_val, "ASVS-023": chk_022_server_val,
    "ASVS-069":   chk_069_upload_size, "ASVS-070": chk_069_upload_size,
    "ASVS-196":   chk_196_error_handling, "ASVS-197": chk_196_error_handling,
    # v5 additions
    "ASVS-COEP":  chk_coep,
    "ASVS-XXSS":  chk_xxss_deprecated,
    "ASVS-CORSC": chk_cors_credentials,
    "ASVS-CORSM": chk_cors_methods,
    "ASVS-TAO":   chk_timing_allow_origin,
    "ASVS-STIM":  chk_server_timing,
    "ASVS-HTPO":  chk_cookie_httponly,
    "ASVS-CKDM":  chk_cookie_domain_broad,
    "ASVS-CKPE":  chk_cookie_persistent,
    "ASVS-SCHO":  chk_secure_cookie_over_http,
    "ASVS-CSPQ":  chk_csp_quality,
    "ASVS-HSTQ":  chk_hsts_quality,
    "ASVS-AWSK":  chk_aws_key,
    "ASVS-PKEY":  chk_private_key,
    "ASVS-DBCS":  chk_db_connection_string,
    "ASVS-INTH":  chk_internal_hostname,
    "ASVS-GOPN":  chk_go_panic,
    "ASVS-APIC":  chk_api_internal_class,
    "ASVS-JWTD":  chk_jwt_deep,
    "ASVS-GQL2":  chk_graphql_introspect,
    "ASVS-CORS2": chk_cors_active_probe,
    "ASVS-HDRI":  chk_header_injection,
}

UNIQUE_CHECKS = list({fn.__name__: (eid, fn)
                      for eid, fn in _RAW_DISPATCH.items()}.values())


# =============================================================================
# Table models
# =============================================================================
class FindingsModel(DefaultTableModel):
    def isCellEditable(self, row, col):
        return False


class ControlsModel(DefaultTableModel):
    def getColumnClass(self, col):
        # Return Java Boolean for checkbox col, Object for all others
        if col == 0:
            return JBoolean
        return DefaultTableModel.getColumnClass(self, col)

    def isCellEditable(self, row, col):
        return col == 0


# =============================================================================
# BurpExtender
# =============================================================================
class BurpExtender(IBurpExtender, IScannerCheck, ITab,
                   IContextMenuFactory, IHttpListener):

    EXT_NAME = "ASVS Security Scanner"

    def registerExtenderCallbacks(self, callbacks):
        self._cb      = callbacks
        self._helpers = callbacks.getHelpers()
        self._out     = PrintWriter(callbacks.getStdout(), True)
        self._err     = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName(self.EXT_NAME)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        saved = None
        try: saved = self._cb.loadExtensionSetting("asvs_enabled_controls")
        except Exception: pass
        if saved:
            self._enabled = set(s.strip() for s in saved.split(",") if s.strip())
        else:
            self._enabled = set(eid for eid, _ in UNIQUE_CHECKS)
        self._findings = []
        self._seen     = set()
        self._sev_overrides = {}

        self._cooldown    = {}   # key -> datetime of last fire
        self._cooldown_s  = 300  # 5 minute default cooldown

        # Cross-request correlation state
        self._response_store   = {}   # host -> list of (url, status, len, headers_hash)
        self._session_tokens   = {}   # host -> set of session token values seen
        self._login_responses  = {}   # host -> list of (url, body_len, status)
        self._token_entropy    = {}   # host -> {cookie_name: [values]}
        self._req_counter      = [0]  # total requests scanned [mutable counter]
        self._scan_start       = datetime.datetime.now()
        # Map finding URL -> messageInfo for real Send to Repeater
        self._msg_store        = {}   # url_key -> messageInfo
        # Register proxy listener for live stats
        try:
            sov = self._cb.loadExtensionSetting("asvs_sev_overrides")
            if sov:
                for pair in sov.split(","):
                    if ":" in pair:
                        k,v = pair.split(":",1)
                        self._sev_overrides[k.strip()] = v.strip()
        except Exception: pass
        SwingUtilities.invokeLater(self._buildUI)
        self._out.println("[ASVS] Loaded. %d auto-checks, %d total controls."
                          % (len(UNIQUE_CHECKS), len(ALL_CONTROLS)))

    def getTabCaption(self): return "ASVS Scanner"
    def getUiComponent(self): return self._root

    def processHttpMessage(self, toolFlag, isRequest, messageInfo):
        if isRequest: return
        try:
            self._req_counter[0] += 1
            if hasattr(self, "_statsLabel") and self._req_counter[0] % 10 == 0:
                elapsed = max(1, (datetime.datetime.now() - self._scan_start).seconds)
                rate = self._req_counter[0] / elapsed
                fp_n = sum(1 for f in self._findings
                           if f.get("title","").startswith("[FP]"))
                lbl  = self._statsLabel
                cnt  = self._req_counter[0]
                fc   = len(self._findings)
                def _upd(lbl=lbl, cnt=cnt, rate=rate, fc=fc, fp_n=fp_n):
                    lbl.setText("  Requests: %d | %.1f/s | Findings: %d | FP: %d"
                               % (cnt, rate, fc, fp_n))
                SwingUtilities.invokeLater(_upd)
            for f in self._runChecks(messageInfo):
                self._addFinding(f)
        except Exception as ex:
            self._err.println("[ASVS] Listener error: " + str(ex))


    def doPassiveScan(self, baseRequestResponse):
        issues = []
        try:
            for f in self._runChecks(baseRequestResponse):
                self._addFinding(f)
                issues.append(_BurpIssue(f, [baseRequestResponse],
                                          baseRequestResponse.getHttpService()))
        except Exception as ex:
            self._err.println("[ASVS] Scan error: " + str(ex))
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []

    def consolidateDuplicateIssues(self, existing, new_issue):
        return -1 if (existing.getIssueName() == new_issue.getIssueName() and
                      str(existing.getUrl()) == str(new_issue.getUrl())) else 0

    def createMenuItems(self, invocation):
        menu = ArrayList()
        item = JMenuItem("ASVS: Scan Selected Request(s)")
        item.addActionListener(self._ContextScanAction(self, invocation))
        menu.add(item)
        evid = JMenuItem("ASVS: Log as Evidence for Selected Control")
        evid.addActionListener(self._LogEvidAction(self, invocation))
        menu.add(evid)
        return menu

    class _LogEvidAction(ActionListener):
        def __init__(self, ext, inv): self._ext = ext; self._inv = inv
        def actionPerformed(self, event):
            msgs = self._inv.getSelectedMessages()
            if not msgs: return
            msg = msgs[0]
            # Find selected row in manual testing checklist
            if not hasattr(self._ext, "_mtView"): return
            row = self._ext._mtView.getSelectedRow()
            if row < 0:
                JOptionPane.showMessageDialog(None,
                    "Please select a control in the Manual Testing tab first.",
                    "ASVS", JOptionPane.WARNING_MESSAGE)
                return
            mr  = self._ext._mtView.convertRowIndexToModel(row)
            cid = str(self._ext._mtModel.getValueAt(mr, 1))
            try:
                url = str(self._ext._helpers.analyzeRequest(msg).getUrl())
                aResp = self._ext._helpers.analyzeResponse(msg.getResponse())
                status = str(aResp.getStatusCode())
                evidence = "Evidence: %s (HTTP %s)" % (url[:120], status)
                self._ext._mtModel.setValueAt(url[:120], mr, 6)
                old_notes = str(self._ext._mtModel.getValueAt(mr, 7) or "")
                new_notes = (old_notes + " | " if old_notes else "") + evidence
                self._ext._mtModel.setValueAt(new_notes[:200], mr, 7)
                JOptionPane.showMessageDialog(None,
                    "Evidence logged for %s:\n%s (HTTP %s)" % (cid, url[:80], status),
                    "ASVS Evidence Logged", JOptionPane.INFORMATION_MESSAGE)
            except Exception as ex:
                JOptionPane.showMessageDialog(None, "Error: "+str(ex),
                    "ASVS", JOptionPane.ERROR_MESSAGE)

    class _ContextScanAction(ActionListener):
        def __init__(self, ext, inv):
            self._ext = ext; self._inv = inv
        def actionPerformed(self, event):
            msgs = self._inv.getSelectedMessages()
            if not msgs: return
            count = 0
            for msg in msgs:
                for f in self._ext._runChecks(msg):
                    self._ext._addFinding(f); count += 1
            JOptionPane.showMessageDialog(None,
                "Scan complete. %d new finding(s) added." % count,
                "ASVS Scanner", JOptionPane.INFORMATION_MESSAGE)

    def _runChecks(self, messageInfo):
        results = []
        try:
            response = messageInfo.getResponse()
            if not response: return results
            aResp = self._helpers.analyzeResponse(response)
            aReq  = self._helpers.analyzeRequest(
                        messageInfo.getHttpService(), messageInfo.getRequest())
            rh   = list(aResp.getHeaders())
            qh   = list(aReq.getHeaders())
            url  = self._helpers.analyzeRequest(messageInfo).getUrl()
            status = aResp.getStatusCode()
            if _should_skip(url, rh, status): return results

            # Feature 18: scope-aware scanning
            if getattr(self, "_inScopeOnly", [False])[0]:
                if not self._cb.isInScope(url):
                    return results
            body = self._helpers.bytesToString(response[aResp.getBodyOffset():])
            called = set()
            for eid, fn in UNIQUE_CHECKS:
                if eid not in self._enabled: continue
                if fn in called: continue
                called.add(fn)
                try:
                    r = fn(rh, qh, body, url, messageInfo, self._helpers, self._cb)

                    if r:
                        r["req_hdrs"]  = "\n".join(str(x) for x in qh)
                        r["resp_hdrs"] = "\n".join(str(x) for x in rh)
                        r["status"]    = str(aResp.getStatusCode())
                        r["_msg_key"]  = str(url)
                        # Store the real messageInfo for Send to Repeater
                        self._msg_store[str(url)] = messageInfo
                        results.append(r)
                except Exception as ex:
                    self._err.println("[ASVS] Check %s error: %s" % (eid, str(ex)))
            for cf in self._correlate(url, rh, qh, body, status):
                cf["req_hdrs"]  = "\n".join(str(x) for x in qh)
                cf["resp_hdrs"] = "\n".join(str(x) for x in rh)
                cf["status"]    = str(status)
                results.append(cf)
        except Exception as ex:
            self._err.println("[ASVS] _runChecks error: " + str(ex))
        return results

    # Header-based checks dedup by host (not full URL)
    _HEADER_CHECKS = {
        'ASVS-027','ASVS-028','ASVS-029','ASVS-030','ASVS-031',
        'ASVS-032','ASVS-033','ASVS-034','ASVS-036','ASVS-037',
        'ASVS-038','ASVS-039','ASVS-040','ASVS-053','ASVS-054',
        'ASVS-055','ASVS-056','ASVS-057','ASVS-058','ASVS-059',
        'ASVS-060','ASVS-063','ASVS-109','ASVS-110','ASVS-111',
        'ASVS-114','ASVS-168','ASVS-173','ASVS-178','ASVS-179',
        'ASVS-180','ASVS-181',
        'ASVS-COEP','ASVS-XXSS','ASVS-CORSC','ASVS-CORSM',
        'ASVS-TAO','ASVS-STIM','ASVS-HTPO','ASVS-CKDM',
        'ASVS-CKPE','ASVS-SCHO','ASVS-CSPQ','ASVS-HSTQ',
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
        self._findings = []; self._seen = set()
        SwingUtilities.invokeLater(self._refreshTable)

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

        # -- Toolbar row 1: title + filter text -------------------------------
        tb1 = JToolBar(); tb1.setFloatable(False)
        tb1.add(JLabel("  ASVS Security Scanner  "))
        tb1.addSeparator()
        self._filterField = JTextField(18)
        tb1.add(JLabel(" Filter: ")); tb1.add(self._filterField)
        tb1.addSeparator()

        # Severity filter
        sevs = ["All Severities", "High", "Medium", "Low", "Information"]
        self._sevBox = JComboBox(Vector(sevs))
        tb1.add(JLabel(" Severity: ")); tb1.add(self._sevBox)

        # Level filter (findings already have L1/L2/L3 in the "Level" column)
        lvls = ["All Levels", "L1", "L2", "L3"]
        self._lvlFilterBox = JComboBox(Vector(lvls))
        tb1.add(JLabel(" Level: ")); tb1.add(self._lvlFilterBox)

        # Chapter filter
        chapters = ["All Chapters"] + sorted(set(c[2] for c in ALL_CONTROLS))
        self._chapFilterBox = JComboBox(Vector(chapters))
        tb1.add(JLabel(" Chapter: ")); tb1.add(self._chapFilterBox)

        # HTTP Status filter (populated dynamically from findings)
        self._statusBox = JComboBox(Vector(["All Statuses"]))
        tb1.add(JLabel(" Status: ")); tb1.add(self._statusBox)

        panel.add(tb1, BorderLayout.NORTH)

        # -- Toolbar row 2: action buttons -------------------------------------
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

        # Wrap both toolbars in a vertical panel
        topPanel = JPanel(BorderLayout())
        topPanel.add(tb1, BorderLayout.NORTH)
        topPanel.add(tb2, BorderLayout.SOUTH)
        panel.add(topPanel, BorderLayout.NORTH)

        cols = ["Time","Status","ID","Req.ID","Chapter","Section","Level","Severity","URL","Title"]
        self._tModel  = FindingsModel(Vector(cols), 0)
        self._tView   = JTable(self._tModel)
        self._tView.setSelectionMode(javax.swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._tSorter = TableRowSorter(self._tModel)
        self._tView.setRowSorter(self._tSorter)
        self._tView.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        self._tView.setRowHeight(20)
        cm = self._tView.getColumnModel()
        for i, w in enumerate([130,50,80,70,155,165,45,68,220,260]):
            cm.getColumn(i).setPreferredWidth(w)
        ren = self._SeverityRenderer()
        for i in range(len(cols)): cm.getColumn(i).setCellRenderer(ren)
        self._detail = JTextArea()
        self._detail.setEditable(False); self._detail.setLineWrap(True)
        self._detail.setWrapStyleWord(True)
        self._detail.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._tView.getSelectionModel().addListSelectionListener(self._RowSelector(self))
        # Right-click context menu for severity override
        self._tView.addMouseListener(self._RightClickMenu(self))
        # Notes area below detail
        self._notesArea = JTextArea(3, 40)
        self._notesArea.setLineWrap(True); self._notesArea.setWrapStyleWord(True)
        self._notesArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._notesArea.getDocument().addDocumentListener(self._NotesListener(self))
        notesPanel = JPanel(BorderLayout())
        notesPanel.add(JLabel("  Analyst Notes:"), BorderLayout.NORTH)
        notesPanel.add(JScrollPane(self._notesArea), BorderLayout.CENTER)
        detailOuter = JPanel(BorderLayout())
        detailOuter.add(JScrollPane(self._detail), BorderLayout.CENTER)
        detailOuter.add(notesPanel, BorderLayout.SOUTH)
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           JScrollPane(self._tView), detailOuter)
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
        self._lvlFilterBox.addActionListener(self._ComboFilterAction(self))
        self._chapFilterBox.addActionListener(self._ComboFilterAction(self))
        self._statusBox.addActionListener(self._ComboFilterAction(self))
        return panel

    class _SeverityRenderer(DefaultTableCellRenderer):
        _C = {"High":Color(0xFF6666),"Medium":Color(0xFFB266),
              "Low":Color(0xFFFF99),"Information":Color(0xADD8E6)}
        def getTableCellRendererComponent(self,tbl,val,sel,foc,row,col):
            c = DefaultTableCellRenderer.getTableCellRendererComponent(
                self,tbl,val,sel,foc,row,col)
            if not sel:
                mr  = tbl.convertRowIndexToModel(row)
                sev = str(tbl.getModel().getValueAt(mr,7))
                c.setBackground(self._C.get(sev,Color.WHITE))
            return c

    class _RowSelector(ListSelectionListener):
        def __init__(self,ext): self._ext=ext
        def valueChanged(self,ev):
            if ev.getValueIsAdjusting(): return
            row = self._ext._tView.getSelectedRow()
            if row < 0: return
            mr = self._ext._tView.convertRowIndexToModel(row)
            if mr >= len(self._ext._findings): return
            f = self._ext._findings[mr]
            txt = (
                "ID          : %s  (%s)\n"
                "Chapter     : %s\n"
                "Section     : %s\n"
                "Assess Type : %s\n"
                "Levels      : %s\n"
                "Severity    : %s\n"
                "HTTP Status : %s\n"
                "URL         : %s\n"
                "\nFinding:\n%s\n"
                "\nRequirement:\n%s" % (
                    f.get("id",""), f.get("req_id",""),
                    f.get("chapter",""), f.get("section",""),
                    f.get("assess_type",""), f.get("levels",""),
                    f.get("severity",""), f.get("status",""),
                    f.get("url",""),
                    f.get("detail",""), f.get("description",""))
            )
            if f.get("req_hdrs"):
                txt += "\n\n---- Request Headers ----\n" + f.get("req_hdrs","")
            if f.get("resp_hdrs"):
                txt += "\n\n---- Response Headers ----\n" + f.get("resp_hdrs","")
            if f.get("body_snippet"):
                txt += "\n\n---- Body Snippet (evidence) ----\n" + f.get("body_snippet","")
            self._ext._detail.setText(txt)
            self._ext._detail.setCaretPosition(0)
            try:
                self._ext._notesArea.setText(f.get("notes",""))
            except Exception: pass

    class _ClearAction(ActionListener):
        def __init__(self,ext): self._ext=ext
        def actionPerformed(self,e): self._ext.clearFindings()

    class _ExportAction(ActionListener):
        def __init__(self,ext): self._ext=ext
        def actionPerformed(self,e): self._ext._exportCSV()

    class _DeleteAction(ActionListener):
        def __init__(self, ext): self._ext = ext
        def actionPerformed(self, e):
            rows = self._ext._tView.getSelectedRows()
            if not rows or len(rows) == 0: return
            # Convert view rows -> model rows, sort descending so removals don't shift indices
            model_rows = sorted(
                [self._ext._tView.convertRowIndexToModel(r) for r in rows],
                reverse=True)
            for mr in model_rows:
                if mr < len(self._ext._findings):
                    f = self._ext._findings[mr]
                    key = f["id"] + "|" + f["url"]
                    self._ext._seen.discard(key)
                    del self._ext._findings[mr]
            SwingUtilities.invokeLater(self._ext._refreshTable)
            self._ext._detail.setText("")

    class _ComboFilterAction(ActionListener):
        def __init__(self, ext): self._ext = ext
        def actionPerformed(self, e): self._ext._applyFindingFilter()

    class _FilterListener(DocumentListener):
        def __init__(self,ext): self._ext=ext
        def _a(self): self._ext._applyFindingFilter()
        def changedUpdate(self,e): self._a()
        def insertUpdate(self,e):  self._a()
        def removeUpdate(self,e):  self._a()

    def _applyFindingFilter(self):
        filters = []
        txt = self._filterField.getText().strip()
        if txt:
            try: filters.append(RowFilter.regexFilter("(?i)" + txt))
            except Exception: pass
        sev = str(self._sevBox.getSelectedItem())
        if sev and sev != "All Severities":
            try: filters.append(RowFilter.regexFilter("(?i)^" + sev + "$", 7))
            except Exception: pass
        lvl = str(self._lvlFilterBox.getSelectedItem())
        if lvl and lvl != "All Levels":
            # Level col (5) contains e.g. "L1/L2/L3" or "L1/L2" - match if lvl appears in it
            try: filters.append(RowFilter.regexFilter("(?i)\\b" + lvl + "\\b", 6))
            except Exception: pass
        chap = str(self._chapFilterBox.getSelectedItem())
        if chap and chap != "All Chapters":
            try: filters.append(RowFilter.regexFilter("(?i)^" + re.escape(chap) + "$", 4))
            except Exception: pass
        status = str(self._statusBox.getSelectedItem())
        if status and status != "All Statuses":
            try: filters.append(RowFilter.regexFilter("^" + re.escape(status) + "$", 1))
            except Exception: pass
        if not filters:
            self._tSorter.setRowFilter(None)
        elif len(filters) == 1:
            self._tSorter.setRowFilter(filters[0])
        else:
            self._tSorter.setRowFilter(RowFilter.andFilter(Arrays.asList(filters)))

    def _refreshTable(self):
        self._tModel.setRowCount(0)
        statuses = sorted(set(f.get("status","") for f in self._findings if f.get("status","")))
        cur_status = str(self._statusBox.getSelectedItem())
        self._statusBox.removeAllItems()
        self._statusBox.addItem("All Statuses")
        for s in statuses:
            self._statusBox.addItem(s)
        if cur_status in statuses:
            self._statusBox.setSelectedItem(cur_status)
        for f in self._findings:
            self._tModel.addRow(Vector([f.get("ts",""),f.get("status",""),f.get("id",""),f.get("req_id",""),
                                  f.get("chapter",""),f.get("section",""),
                                  f.get("levels",""),f.get("severity",""),
                                  f.get("url",""),f.get("title","")]))
        self._root.setTitleAt(0, "Findings (%d)" % len(self._findings))
        fp_n = sum(1 for f in self._findings if f.get("title","").startswith("[FP]"))
        if hasattr(self, "_statsLabel"):
            self._statsLabel.setText(
                "  Findings: %d | FP: %d | Suppressed: %d" % (
                len(self._findings), fp_n,
                sum(1 for k in self._seen if "|HOST|" in k or k.count("|")==1)))
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
        chooser.setSelectedFile(java.io.File("asvs_findings_%s.csv" % ts))
        if chooser.showSaveDialog(self._root) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.endswith(".csv"): path += ".csv"
            try:
                def q(s): return '"' + str(s).replace('"','""') + '"'
                fos = FileOutputStream(path)
                osw = OutputStreamWriter(fos, "UTF-8")
                bw  = BufferedWriter(osw)
                # Export only currently visible (filtered) rows
                visible_rows = [self._tView.convertRowIndexToModel(r)
                               for r in range(self._tView.getRowCount())]
                visible_findings = [self._findings[r] for r in visible_rows
                                    if r < len(self._findings)]
                bw.write("Time,Status,ID,Req.ID,Chapter,Section,Levels,Severity,"
                         "URL,Title,Detail,Description,Notes\n")
                for f in visible_findings:
                    bw.write(",".join([
                        q(f.get("ts","")),q(f.get("status","")),
                        q(f.get("id","")),q(f.get("req_id","")),
                        q(f.get("chapter","")),q(f.get("section","")),
                        q(f.get("levels","")),q(f.get("severity","")),
                        q(f.get("url","")),q(f.get("title","")),
                        q(f.get("detail","")),q(f.get("description","")),
                        q(f.get("notes",""))
                    ])+"\n")
                exported = len(visible_findings)
                bw.close()
                JOptionPane.showMessageDialog(None,
                    "Exported %d finding(s) to:\n%s" % (exported, path),
                    "Export Complete",JOptionPane.INFORMATION_MESSAGE)
            except Exception as ex:
                JOptionPane.showMessageDialog(None,"Export failed: "+str(ex),
                    "Export Error",JOptionPane.ERROR_MESSAGE)


    # IDs with a passive check (exact)
    _PASSIVE_IDS = set(_RAW_DISPATCH.keys())
    # IDs whose passive check is heuristic/low-confidence
    _HEURISTIC_IDS = {"ASVS-022","ASVS-023","ASVS-025","ASVS-063","ASVS-083","ASVS-087","ASVS-094","ASVS-109","ASVS-116","ASVS-183","ASVS-189","ASVS-191"}

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
        outer = JPanel(BorderLayout(4,4))
        outer.setBorder(BorderFactory.createEmptyBorder(6,6,6,6))
        tb = JToolBar(); tb.setFloatable(False)
        chapters = ["All Chapters"] + sorted(set(c[2] for c in ALL_CONTROLS))
        levels   = ["All Levels","L1 Only","L2+","L3 Only"]
        self._chapBox    = JComboBox(Vector(chapters))
        self._lvlBox     = JComboBox(Vector(levels))
        self._ctrlSearch = JTextField(16)
        allBtn   = JButton("All")
        noneBtn  = JButton("None")
        l1Btn    = JButton("L1 Only")
        techBtn  = JButton("Technical Only")
        applyBtn = JButton("  Apply Selection  ")
        applyBtn.setBackground(Color(0x388E3C)); applyBtn.setForeground(Color.WHITE)
        tb.add(JLabel(" Chapter: ")); tb.add(self._chapBox)
        tb.add(JLabel("  Level: ")); tb.add(self._lvlBox)
        tb.add(JLabel("  Search: ")); tb.add(self._ctrlSearch)
        modes = ["All Modes", "Passive", "Heuristic", "Manual Only"]
        self._modeBox = JComboBox(Vector(modes))
        tb.add(JLabel("  Mode: ")); tb.add(self._modeBox)
        tb.addSeparator()
        tb.add(allBtn); tb.add(noneBtn); tb.add(l1Btn); tb.add(techBtn)
        tb.addSeparator(); tb.add(applyBtn)
        outer.add(tb, BorderLayout.NORTH)
        legend = JPanel()
        legend.setLayout(BoxLayout(legend,BoxLayout.X_AXIS))
        def mkLbl(col,txt):
            lbl=JLabel("  "+txt+"  "); lbl.setOpaque(True); lbl.setBackground(col)
            lbl.setBorder(BorderFactory.createLineBorder(Color.GRAY)); return lbl
        legend.add(mkLbl(Color(0xE8F5E9),"Technical (auto-scanned)"))
        legend.add(JLabel("  "))
        legend.add(mkLbl(Color(0xE3F2FD),"Questionnaire (manual)"))
        legend.add(JLabel("    "))
        legend.add(mkLbl(Color(0xC8E6C9),"Passive (auto-detected)"))
        legend.add(JLabel("  "))
        legend.add(mkLbl(Color(0xFFF9C4),"Heuristic (low confidence)"))
        legend.add(JLabel("  "))
        legend.add(mkLbl(Color(0xF5F5F5),"Manual Only (active/stateful)"))
        legend.add(JLabel("  ")); legend.add(JLabel("Bold = L1 required"))
        outer.add(legend, BorderLayout.SOUTH)
        ctrlCols = ["Active","ID","Req.ID","Chapter","Section","L1","L2","L3","Type","Scan Mode","Default Sev","Requirement"]
        self._ctrlModel  = ControlsModel(Vector(ctrlCols),0)
        self._ctrlView   = JTable(self._ctrlModel)
        self._ctrlSorter = TableRowSorter(self._ctrlModel)
        self._ctrlView.setRowSorter(self._ctrlSorter)
        self._ctrlView.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        self._ctrlView.setRowHeight(20)
        ccm = self._ctrlView.getColumnModel()
        for i,w in enumerate([45,80,70,185,175,28,28,28,100,90,70,600]):
            ccm.getColumn(i).setPreferredWidth(w)
        sevEditor = javax.swing.DefaultCellEditor(
            JComboBox(Vector(["Default","High","Medium","Low","Information"])))
        ccm.getColumn(10).setCellEditor(sevEditor)
        cren = self._ControlsRenderer()
        for i in range(1,len(ctrlCols)): ccm.getColumn(i).setCellRenderer(cren)
        for c in ALL_CONTROLS:
            cid,chap_id,chap,sec_id,sec,req_id,desc,l1,l2,l3,atype = c
            sev_key = "sev_override_" + cid
            sev_override = self._sev_overrides.get(cid, "Default")
            self._ctrlModel.addRow(Vector([JBoolean(cid in self._enabled),
                cid,req_id,chap,sec,
                "X" if l1 else "","X" if l2 else "","X" if l3 else "",
                atype, ASVSExtension._scan_mode(cid), sev_override, desc]))
        outer.add(JScrollPane(self._ctrlView),BorderLayout.CENTER)
        ext = self

        class _AllL(ActionListener):
            def __init__(self,s): self._s=s
            def actionPerformed(self,e):
                for r in range(ext._ctrlModel.getRowCount()):
                    ext._ctrlModel.setValueAt(JBoolean(self._s),r,0)

        class _L1L(ActionListener):
            def actionPerformed(self,e):
                for r in range(ext._ctrlModel.getRowCount()):
                    ext._ctrlModel.setValueAt(
                        JBoolean(ext._ctrlModel.getValueAt(r,5)=="X"),r,0)

        class _TechL(ActionListener):
            def actionPerformed(self,e):
                for r in range(ext._ctrlModel.getRowCount()):
                    ext._ctrlModel.setValueAt(
                        JBoolean(ext._ctrlModel.getValueAt(r,8)=="Technical"),r,0)

        class _ApplyL(ActionListener):
            def actionPerformed(self,e):
                ext._enabled=set()
                for r in range(ext._ctrlModel.getRowCount()):
                    if ext._ctrlModel.getValueAt(r,0):
                        ext._enabled.add(str(ext._ctrlModel.getValueAt(r,1)))
                try:
                    ext._cb.saveExtensionSetting("asvs_enabled_controls", ",".join(sorted(ext._enabled)))
                except Exception: pass
                JOptionPane.showMessageDialog(None,
                    "%d control(s) now active.\n"
                    "(Technical = auto-scanned; Questionnaire = manual review)"
                    % len(ext._enabled),
                    "ASVS Scanner",JOptionPane.INFORMATION_MESSAGE)

        class _FA(ActionListener):
            def actionPerformed(self,e): ext._applyCtrlFilter()

        class _FD(DocumentListener):
            def _d(self): ext._applyCtrlFilter()
            def changedUpdate(self,e): self._d()
            def insertUpdate(self,e):  self._d()
            def removeUpdate(self,e):  self._d()

        allBtn.addActionListener(_AllL(True))
        noneBtn.addActionListener(_AllL(False))
        l1Btn.addActionListener(_L1L())
        techBtn.addActionListener(_TechL())
        applyBtn.addActionListener(_ApplyL())
        self._chapBox.addActionListener(_FA())
        self._lvlBox.addActionListener(_FA())
        self._modeBox.addActionListener(_FA())
        self._ctrlSearch.getDocument().addDocumentListener(_FD())
        return outer

    class _ControlsRenderer(DefaultTableCellRenderer):
        _MODE_COL = {"Passive": Color(0xC8E6C9),
                     "Heuristic": Color(0xFFF9C4),
                     "Manual Only": Color(0xF5F5F5)}
        def getTableCellRendererComponent(self,table,value,isSelected,hasFocus,row,col):
            c = DefaultTableCellRenderer.getTableCellRendererComponent(
                self,table,value,isSelected,hasFocus,row,col)
            if not isSelected:
                mr   = table.convertRowIndexToModel(row)
                atyp = str(table.getModel().getValueAt(mr,8))
                mode = str(table.getModel().getValueAt(mr,9))
                l1   = str(table.getModel().getValueAt(mr,5))
                if col == 9:
                    c.setBackground(self._MODE_COL.get(mode, Color.WHITE))
                else:
                    c.setBackground(Color(0xE8F5E9) if atyp=="Technical" else Color(0xE3F2FD))
                fnt = c.getFont()
                c.setFont(fnt.deriveFont(Font.BOLD if l1=="X" else Font.PLAIN))
            return c

    def _applyCtrlFilter(self):
        chap = str(self._chapBox.getSelectedItem())
        lvl  = str(self._lvlBox.getSelectedItem())
        txt  = self._ctrlSearch.getText().strip()
        mode = str(self._modeBox.getSelectedItem()) if hasattr(self, "_modeBox") else "All Modes"
        filters = []
        if chap and chap != "All Chapters":
            try: filters.append(RowFilter.regexFilter("(?i)^"+re.escape(chap)+"$",3))
            except Exception: pass
        if lvl == "L1 Only":
            try: filters.append(RowFilter.regexFilter("^X$",5))
            except Exception: pass
        elif lvl == "L2+":
            try: filters.append(RowFilter.regexFilter("^X$",6))
            except Exception: pass
        elif lvl == "L3 Only":
            try: filters.append(RowFilter.regexFilter("^X$",7))
            except Exception: pass
        if mode and mode != "All Modes":
            try: filters.append(RowFilter.regexFilter("^"+re.escape(mode)+"$",9))
            except Exception: pass
        if txt:
            try: filters.append(RowFilter.regexFilter("(?i)"+txt))
            except Exception: pass
        if not filters: self._ctrlSorter.setRowFilter(None)
        elif len(filters)==1: self._ctrlSorter.setRowFilter(filters[0])
        else: self._ctrlSorter.setRowFilter(RowFilter.andFilter(Arrays.asList(filters)))


    class _RightClickMenu(java.awt.event.MouseAdapter):
        _SEVS = ["High", "Medium", "Low", "Information", "False Positive"]
        def __init__(self, ext): self._ext = ext
        def mouseReleased(self, e):
            if e.isPopupTrigger(): self._show(e)
        def mousePressed(self, e):
            if e.isPopupTrigger(): self._show(e)
        def _show(self, e):
            row = self._ext._tView.rowAtPoint(e.getPoint())
            if row < 0: return
            if not self._ext._tView.isRowSelected(row):
                self._ext._tView.setRowSelectionInterval(row, row)
            menu = JPopupMenu()
            ext = self._ext
            for sev in self._SEVS:
                item = JMenuItem("Set severity: " + sev)
                item.addActionListener(self._SetSev(ext, sev))
                menu.add(item)
            menu.addSeparator()
            dupItem = JMenuItem("Mark as Duplicate (suppress future)")
            dupItem.addActionListener(self._MarkDuplicate(ext))
            menu.add(dupItem)
            sendRepItem = JMenuItem("Send to Repeater")
            sendRepItem.addActionListener(self._SendToRepeater(ext))
            menu.add(sendRepItem)
            srchItem = JMenuItem("Search in Evidence...")
            srchItem.addActionListener(self._SearchEvidence(ext))
            menu.add(srchItem)
            aiItem = JMenuItem("AI Triage (Anthropic)")
            aiItem.addActionListener(self._AITriageAction(ext))
            menu.add(aiItem)
            menu.show(e.getComponent(), e.getX(), e.getY())

    class _SetSev(java.awt.event.ActionListener):
        def __init__(self, ext, sev): self._ext = ext; self._sev = sev
        def actionPerformed(self, e):
            rows = self._ext._tView.getSelectedRows()
            for vr in rows:
                mr = self._ext._tView.convertRowIndexToModel(vr)
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

    class _MarkDuplicate(java.awt.event.ActionListener):
        def __init__(self, ext): self._ext = ext
        def actionPerformed(self, e):
            rows = self._ext._tView.getSelectedRows()
            model_rows = sorted(
                [self._ext._tView.convertRowIndexToModel(r) for r in rows],
                reverse=True)
            for mr in model_rows:
                if mr < len(self._ext._findings):
                    f = self._ext._findings[mr]
                    # Permanently suppress this finding
                    key = f["id"] + "|" + f["url"]
                    host_key = f["id"] + "|HOST|" + str(f["url"]).split("/")[2] if "/" in f["url"] else key
                    self._ext._seen.add(key)
                    self._ext._seen.add(host_key)
                    del self._ext._findings[mr]
            SwingUtilities.invokeLater(self._ext._refreshTable)
            self._ext._detail.setText("")


    class _SendToRepeater(java.awt.event.ActionListener):
        def __init__(self, ext): self._ext = ext
        def actionPerformed(self, e):
            row = self._ext._tView.getSelectedRow()
            if row < 0: return
            mr  = self._ext._tView.convertRowIndexToModel(row)
            if mr >= len(self._ext._findings): return
            f   = self._ext._findings[mr]
            try:
                from java.net import URL as _URL
                u = _URL(f["url"])
                host = u.getHost()
                port = u.getPort() if u.getPort() > 0 else (443 if u.getProtocol()=="https" else 80)
                use_https = u.getProtocol().lower() == "https"
                msg_key = f.get("_msg_key","")
                stored_msg = self._ext._msg_store.get(msg_key)
                if stored_msg and stored_msg.getRequest():
                    req_bytes = stored_msg.getRequest()
                else:
                    path = u.getPath() or "/"
                    if u.getQuery(): path += "?" + u.getQuery()
                    req_str = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, host)
                    req_bytes = self._ext._helpers.stringToBytes(req_str)
                self._ext._cb.sendToRepeater(host, port, use_https, req_bytes,
                                              f.get("id","") + " - " + f.get("title","")[:40])
                JOptionPane.showMessageDialog(None,
                    "Sent to Repeater: %s" % f["url"][:80],
                    "ASVS Scanner", JOptionPane.INFORMATION_MESSAGE)
            except Exception as ex:
                JOptionPane.showMessageDialog(None, "Send to Repeater failed: " + str(ex),
                    "ASVS Scanner", JOptionPane.ERROR_MESSAGE)

    class _AITriageAction(java.awt.event.ActionListener):
        def __init__(self, ext): self._ext = ext
        def actionPerformed(self, e):
            row = self._ext._tView.getSelectedRow()
            if row < 0: return
            mr = self._ext._tView.convertRowIndexToModel(row)
            if mr >= len(self._ext._findings): return
            self._ext._aiTriage(self._ext._findings[mr])

    class _SearchEvidence(java.awt.event.ActionListener):
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
                    f.get("description",""), f.get("url",""),
                ]).lower()
                if term_l in searchable:
                    matches.append("%s | %s | %s" % (
                        f.get("id",""), f.get("severity",""), f.get("url","")[:60]))
            if matches:
                msg = "Found %d match(es) for '%s':\n\n" % (len(matches), term)
                msg += "\n".join(matches[:25])
                if len(matches) > 25: msg += "\n...and %d more" % (len(matches)-25)
                JOptionPane.showMessageDialog(None, msg,
                    "Evidence Search Results", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(None,
                    "No findings contain '%s' in their evidence." % term,
                    "Evidence Search", JOptionPane.INFORMATION_MESSAGE)

    class _NotesListener(DocumentListener):
        def __init__(self, ext): self._ext = ext; self._updating = False
        def _save(self):
            if self._updating: return
            row = self._ext._tView.getSelectedRow()
            if row < 0: return
            mr = self._ext._tView.convertRowIndexToModel(row)
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
        chap_count = {}
        urls = set()
        fp_count = 0
        for f in fs:
            s = f.get("severity","?")
            sev_count[s] = sev_count.get(s, 0) + 1
            c = f.get("chapter","?")
            chap_count[c] = chap_count.get(c, 0) + 1
            urls.add(f.get("url",""))
            if f.get("title","").startswith("[FP]"): fp_count += 1
        lines = ["=" * 48]
        lines.append("  ASVS Scan Summary")
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
        lines.append("By Chapter (findings / FP):")
        chap_fp = {}
        for f in fs:
            c2 = f.get("chapter","?")
            if f.get("title","").startswith("[FP]"):
                chap_fp[c2] = chap_fp.get(c2,0) + 1
        for c, n in sorted(chap_count.items(), key=lambda x: -x[1]):
            fp_c = chap_fp.get(c, 0)
            fp_pct = " (%d%% FP)" % (100*fp_c//n) if fp_c else ""
            lines.append("  %-36s %d%s" % ((c[:34]+"..") if len(c)>36 else c, n, fp_pct))
        lines.append("")
        passive_n  = sum(1 for c in ALL_CONTROLS if ASVSExtension._scan_mode(c[0]) == "Passive")
        heuristic_n = sum(1 for c in ALL_CONTROLS if ASVSExtension._scan_mode(c[0]) == "Heuristic")
        manual_n   = sum(1 for c in ALL_CONTROLS if ASVSExtension._scan_mode(c[0]) == "Manual Only")
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
            if len(c) <= 10: continue
            if str(c[10]) != "Technical": continue
            if cid in mt_dispatch: continue
            chap = str(c[2]) if len(c) > 2 else ""
            sec  = str(c[4])[:60] if len(c) > 4 else ""
            l1   = "L1" if (len(c) > 7 and c[7]) else ""
            guide_key = "_MANUAL_GUIDE" if "ASVS"=="ASVS" else "_ECWASS_MANUAL_GUIDE"
            guide_map = _MANUAL_GUIDE if "ASVS"=="ASVS" else _ECWASS_MANUAL_GUIDE
            guide = guide_map.get(cid, ("", "Manual", ""))
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
                    "Manual Testing Help", JOptionPane.INFORMATION_MESSAGE)

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


    class _MTBulkAction(java.awt.event.ActionListener):
        def __init__(self, ext, status): self._ext = ext; self._status = status
        def actionPerformed(self, e):
            rows = self._ext._mtView.getSelectedRows()
            if not rows: return
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
            guide = _MANUAL_GUIDE.get(cid)
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
        chooser.setSelectedFile(java.io.File("asvs_manual_%s.csv" % ts))
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
    _S = {"High":"High","Medium":"Medium","Low":"Low","Information":"Information"}
    def __init__(self,f,msgs,svc): self._f=f; self._msg=msgs; self._svc=svc
    def getUrl(self):
        try: return JavaURL(self._f["url"])
        except: return None
    def getIssueName(self): return "[%s] %s"%(self._f["id"],self._f["title"])
    def getIssueType(self): return 0x08000000
    def getSeverity(self): return self._S.get(self._f["severity"],"Information")
    def getConfidence(self): return "Tentative"
    def getIssueBackground(self): return "ASVS: "+self._f.get("description","")
    def getRemediationBackground(self): return "Remediate per OWASP ASVS."
    def getIssueDetail(self): return self._f.get("detail","")
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return self._msg
    def getHttpService(self): return self._svc
