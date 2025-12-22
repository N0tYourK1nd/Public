# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory
from java.awt.event import ActionListener
from javax.swing import JMenuItem, JOptionPane
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
import json

class BurpExtender(IBurpExtender, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Copy as JavaScript")
        callbacks.registerContextMenuFactory(self)
        
        print("[+] Copy as JavaScript extension loaded")
    
    def createMenuItems(self, invocation):
        menu_items = []
        context = invocation.getInvocationContext()
        
        # Check if we are in a request editor or viewer (Repeater/Proxy)
        if context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST or \
           context == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            
            request_response = invocation.getSelectedMessages()
            
            if request_response and len(request_response) > 0:
                formats = [
                    ('fetch', 'Fetch API'),
                    ('xhr', 'XMLHttpRequest'),
                    ('axios', 'Axios'),
                    ('jquery', 'jQuery')
                ]
                
                for fmt, label in formats:
                    # Normal
                    menu = JMenuItem("Copy as JavaScript (" + label + ")")
                    menu.addActionListener(JavaScriptConverterListener(
                        self._callbacks, request_response[0], self._helpers, fmt, False))
                    menu_items.append(menu)
                    
                    # Minified
                    menu_min = JMenuItem("Copy as JavaScript (" + label + " - minified)")
                    menu_min.addActionListener(JavaScriptConverterListener(
                        self._callbacks, request_response[0], self._helpers, fmt, True))
                    menu_items.append(menu_min)
                
        return menu_items

class JavaScriptConverterListener(ActionListener):
    """Listens for menu clicks - must implement ActionListener"""
    
    def __init__(self, callbacks, request_response, helpers, format_type, minify):
        self._callbacks = callbacks
        self._request_response = request_response
        self._helpers = helpers
        self._format_type = format_type
        self._minify = minify
    
    def actionPerformed(self, event):
        try:
            request = self._request_response.getRequest()
            # Pass the full request_response object for body parsing reliability
            converter = RequestToJavaScript(self._helpers, self._format_type, self._minify)
            js_code = converter.convert(request, self._request_response)
            
            if js_code:
                self._copy_to_clipboard(js_code)
        except Exception as e:
            # Only show error if the extension itself crashes
            print("[-] Error generating code: " + str(e))
    
    def _copy_to_clipboard(self, text):
        selection = StringSelection(text)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(selection, None)

class RequestToJavaScript(object):
    
    def __init__(self, helpers, format_type='fetch', minify=False):
        self._helpers = helpers
        self._format_type = format_type
        self._minify = minify
    
    def convert(self, request, request_response):
        request_info = self._helpers.analyzeRequest(request_response)
        
        method = request_info.getMethod()
        url = self._get_full_url(request, request_info)
        headers = self._parse_headers(request_info.getHeaders())
        body = self._get_body(request, request_info)
        
        if self._format_type == 'fetch':
            return self._generate_fetch(method, url, headers, body)
        elif self._format_type == 'xhr':
            return self._generate_xhr(method, url, headers, body)
        elif self._format_type == 'axios':
            return self._generate_axios(method, url, headers, body)
        elif self._format_type == 'jquery':
            return self._generate_jquery(method, url, headers, body)
        
        return ""
    
    def _get_full_url(self, request, request_info):
        try:
            return str(request_info.getUrl())
        except:
            # Robust fallback
            try:
                request_str = self._helpers.bytesToString(request)
            except:
                request_str = str(request)
                
            first_line = request_str.split('\n')[0]
            parts = first_line.split(' ')
            path = parts[1] if len(parts) >= 2 else '/'
            
            headers = request_info.getHeaders()
            host = "localhost"
            protocol = "https"
            
            for header in headers:
                if header.lower().startswith('host:'):
                    host = header.split(':', 1)[1].strip()
                    if host.endswith(':80'): protocol = "http"
                    elif host.endswith(':443'): protocol = "https"
                    break
            
            return protocol + "://" + host + path
    
    def _parse_headers(self, headers):
        header_dict = {}
        for header in headers[1:]:
            if ':' in header:
                key, value = header.split(':', 1)
                header_dict[key.strip()] = value.strip()
        
        if 'Host' in header_dict: del header_dict['Host']
        if 'Content-Length' in header_dict: del header_dict['Content-Length']
        return header_dict
    
    def _get_body(self, request, request_info):
        offset = request_info.getBodyOffset()
        if offset < len(request):
            return self._helpers.bytesToString(request[offset:])
        return None
    
    def _escape_string(self, s):
        if not s: return ""
        s = str(s)
        s = s.replace('\\', '\\\\')
        s = s.replace("'", "\\'")
        s = s.replace('"', '\\"')
        s = s.replace("\n", "\\n")
        s = s.replace("\r", "\\r")
        s = s.replace("/", "\\/") # XSS safety
        return s
    
    # --- CLEAN GENERATORS (NO LOGGING) ---
    
    def _generate_fetch(self, method, url, headers, body):
        lines = []
        sep = "" if self._minify else "\n"
        indent = "" if self._minify else "  "
        
        lines.append("fetch('" + self._escape_string(url) + "', {")
        lines.append(indent + "method: '" + method + "',")
        
        if headers:
            lines.append(indent + "headers: {")
            h_lines = []
            for k, v in headers.items():
                h_lines.append(indent + indent + "'" + self._escape_string(k) + "': '" + self._escape_string(v) + "'")
            lines.append(("," + sep).join(h_lines))
            lines.append(indent + "},")
            
        if body and method.upper() in ['POST', 'PUT', 'PATCH']:
            lines.append(indent + "body: '" + self._escape_string(body) + "',")
            
        lines.append(indent + "credentials: 'include',")
        lines.append(indent + "mode: 'cors'")
        lines.append("})")
        
        code = sep.join(lines)
        if self._minify:
            code = code.replace(", ", ",").replace(": ", ":")
        return code

    def _generate_xhr(self, method, url, headers, body):
        lines = []
        if self._minify:
            lines.append("var x=new XMLHttpRequest();x.open('" + method + "','" + self._escape_string(url) + "',1);")
            lines.append("x.withCredentials=1;")
            if headers:
                for k, v in headers.items():
                    lines.append("x.setRequestHeader('" + self._escape_string(k) + "','" + self._escape_string(v) + "');")
            if body and method.upper() in ['POST', 'PUT', 'PATCH']:
                lines.append("x.send('" + self._escape_string(body) + "');")
            else:
                lines.append("x.send();")
            return "".join(lines)
        else:
            lines.append("var xhr = new XMLHttpRequest();")
            lines.append("xhr.open('" + method + "', '" + self._escape_string(url) + "', true);")
            if headers:
                for k, v in headers.items():
                    lines.append("xhr.setRequestHeader('" + self._escape_string(k) + "', '" + self._escape_string(v) + "');")
            lines.append("xhr.withCredentials = true;")
            if body and method.upper() in ['POST', 'PUT', 'PATCH']:
                lines.append("xhr.send('" + self._escape_string(body) + "');")
            else:
                lines.append("xhr.send();")
            return "\n".join(lines)

    def _generate_axios(self, method, url, headers, body):
        code = "axios({"
        code += "method:'" + method + "',"
        code += "url:'" + self._escape_string(url) + "',"
        if headers:
            code += "headers:{"
            hl = []
            for k,v in headers.items(): hl.append("'" + self._escape_string(k) + "':'" + self._escape_string(v) + "'")
            code += ",".join(hl) + "},"
        if body and method.upper() in ['POST', 'PUT', 'PATCH']:
            code += "data:'" + self._escape_string(body) + "',"
        code += "withCredentials:true})"
        
        if not self._minify:
            code = code.replace("{", "{\n  ").replace(",", ",\n  ").replace("}", "\n}")
        return code

    def _generate_jquery(self, method, url, headers, body):
        code = "$.ajax({"
        code += "type:'" + method + "',"
        code += "url:'" + self._escape_string(url) + "',"
        if headers:
            code += "headers:{"
            hl = []
            for k,v in headers.items(): hl.append("'" + self._escape_string(k) + "':'" + self._escape_string(v) + "'")
            code += ",".join(hl) + "},"
        if body and method.upper() in ['POST', 'PUT', 'PATCH']:
            code += "data:'" + self._escape_string(body) + "',"
        code += "xhrFields:{withCredentials:true}})"
        
        if not self._minify:
            code = code.replace("{", "{\n  ").replace(",", ",\n  ").replace("}", "\n}")
        return code
