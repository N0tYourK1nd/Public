# -*- coding: utf-8 -*-
"""
Burp Suite Extension: Copy as JavaScript
Converts HTTP requests to JavaScript fetch() or XMLHttpRequest equivalents
Supports multiple formats: fetch, XMLHttpRequest, axios, jQuery
"""

from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse
from java.lang import String
from java.awt.event import ActionListener
from javax.swing import JMenuItem, JOptionPane
from java.awt import Dimension
import json
import re
import base64
from urllib import quote


class BurpExtender(IBurpExtender, IContextMenuFactory):
    """Main extension class implementing context menu factory"""
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Copy as JavaScript")
        callbacks.registerContextMenuFactory(self)
        
        print("[+] Copy as JavaScript extension loaded")
        print("[+] Formats: fetch, XHR, axios, jQuery")
    
    def createMenuItems(self, invocation):
        """Create context menu items"""
        menu_items = []
        
        if invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST or \
           invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            
            request_response = invocation.getSelectedMessages()
            
            if request_response and len(request_response) > 0:
                formats = [
                    ('fetch', 'Fetch API'),
                    ('xhr', 'XMLHttpRequest'),
                    ('axios', 'Axios'),
                    ('jquery', 'jQuery')
                ]
                
                for fmt, label in formats:
                    menu = JMenuItem("Copy as JavaScript (" + label + ")")
                    menu.addActionListener(JavaScriptConverterListener(
                        self._callbacks, 
                        request_response[0], 
                        self._helpers,
                        fmt,
                        False
                    ))
                    menu_items.append(menu)
                    
                    menu_min = JMenuItem("Copy as JavaScript (" + label + " - minified)")
                    menu_min.addActionListener(JavaScriptConverterListener(
                        self._callbacks,
                        request_response[0],
                        self._helpers,
                        fmt,
                        True
                    ))
                    menu_items.append(menu_min)
        
        return menu_items


class JavaScriptConverterListener(ActionListener):
    """Action listener for menu item clicks"""
    
    def __init__(self, callbacks, request_response, helpers, format_type, minify):
        self._callbacks = callbacks
        self._request_response = request_response
        self._helpers = helpers
        self._format_type = format_type
        self._minify = minify
    
    def actionPerformed(self, event):
        """Handle menu click"""
        try:
            request = self._request_response.getRequest()
            converter = RequestToJavaScript(self._helpers, self._format_type, self._minify)
            js_code = converter.convert(request)
            
            if js_code:
                self._copy_to_clipboard(js_code)
            else:
                JOptionPane.showMessageDialog(
                    None,
                    "Failed to convert request",
                    "Error",
                    JOptionPane.ERROR_MESSAGE
                )
        except Exception as e:
            JOptionPane.showMessageDialog(
                None,
                "Error: " + str(e),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    
    def _copy_to_clipboard(self, text):
        """Copy text to system clipboard"""
        from java.awt.datatransfer import StringSelection
        from java.awt import Toolkit
        
        selection = StringSelection(text)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(selection, None)


class RequestToJavaScript(object):
    """Core converter: HTTP request -> JavaScript"""
    
    def __init__(self, helpers, format_type='fetch', minify=False):
        self._helpers = helpers
        self._format_type = format_type
        self._minify = minify
    
    def convert(self, request):
        """Main conversion method"""
        request_info = self._helpers.analyzeRequest(request)
        
        method = request_info.getMethod()
        url = self._get_full_url(request, request_info)
        headers = self._parse_headers(request_info.getHeaders())
        body = self._get_body(request, request_info)
        
        if self._format_type == 'fetch':
            js = self._generate_fetch(method, url, headers, body)
        elif self._format_type == 'xhr':
            js = self._generate_xhr(method, url, headers, body)
        elif self._format_type == 'axios':
            js = self._generate_axios(method, url, headers, body)
        elif self._format_type == 'jquery':
            js = self._generate_jquery(method, url, headers, body)
        else:
            js = self._generate_fetch(method, url, headers, body)
        
        if self._minify:
            js = self._minify_javascript(js)
        
        return js
    
    def _get_full_url(self, request, request_info):
        """Extract full URL from request"""
        try:
            return str(request_info.getUrl())
        except:
            try:
                request_str = str(bytearray(request))
            except:
                request_str = str(request)
            
            first_line = request_str.split('\\n')[0]
            parts = first_line.split(' ')
            
            if len(parts) >= 2:
                path = parts[1]
            else:
                path = '/'
            
            headers = request_info.getHeaders()
            host = None
            protocol = "https"
            
            for header in headers:
                if header.lower().startswith('host:'):
                    host = header.split(':', 1)[1].strip()
                    if host.endswith(':80'):
                        protocol = "http"
                    elif host.endswith(':443'):
                        protocol = "https"
                    elif ':' in host:
                        port = host.split(':')[1]
                        protocol = "http" if port == "80" else "https"
                    break
            
            if not host:
                return "https://localhost" + path
            
            return protocol + "://" + host + path
    
    def _parse_headers(self, headers):
        """Parse headers from request"""
        header_dict = {}
        
        for header in headers[1:]:
            if ':' in header:
                key, value = header.split(':', 1)
                header_dict[key.strip()] = value.strip()
        
        if 'Host' in header_dict:
            del header_dict['Host']
        if 'Content-Length' in header_dict:
            del header_dict['Content-Length']
        
        return header_dict
    
    def _get_body(self, request, request_info):
        """Extract request body"""
        body_offset = request_info.getBodyOffset()
        
        if body_offset < len(request):
            try:
                body_bytes = bytearray(request[body_offset:])
                body = str(body_bytes)
            except:
                body = str(request[body_offset:])
            return body
        
        return None
    
    def _generate_fetch(self, method, url, headers, body):
        """Generate fetch() API code"""
        js_lines = []
        
        js_lines.append("fetch('" + self._escape_string(url) + "',{")
        js_lines.append("method:'" + method + "',")
        
        if headers:
            js_lines.append("headers:{")
            header_lines = []
            for key, value in headers.items():
                header_lines.append("'" + self._escape_string(key) + "':'" + self._escape_string(value) + "'")
            js_lines.append(",".join(header_lines))
            js_lines.append("},")
        
        if body and method.upper() in ['POST', 'PUT', 'PATCH']:
            try:
                json_obj = json.loads(body)
                body_str = json.dumps(json_obj)
            except:
                body_str = body
            js_lines.append("body:'" + self._escape_string(body_str) + "',")
        
        js_lines.append("credentials:'include',")
        js_lines.append("mode:'cors'")
        js_lines.append("}).then(r=>r.text()).then(d=>console.log(d)).catch(e=>console.error('Error:',e));")
        
        return "".join(js_lines)
    
    def _generate_xhr(self, method, url, headers, body):
        """Generate XMLHttpRequest code"""
        js_lines = []
        
        js_lines.append("var xhr=new XMLHttpRequest();")
        js_lines.append("xhr.open('" + method + "','" + self._escape_string(url) + "',true);")
        
        if headers:
            for key, value in headers.items():
                js_lines.append("xhr.setRequestHeader('" + self._escape_string(key) + "','" + self._escape_string(value) + "');")
        
        js_lines.append("xhr.withCredentials=true;")
        js_lines.append("xhr.onload=function(){console.log(xhr.responseText);};")
        js_lines.append("xhr.onerror=function(){console.error('Error');};")
        
        if body and method.upper() in ['POST', 'PUT', 'PATCH']:
            try:
                json_obj = json.loads(body)
                body_str = json.dumps(json_obj)
            except:
                body_str = body
            js_lines.append("xhr.send('" + self._escape_string(body_str) + "');")
        else:
            js_lines.append("xhr.send();")
        
        return "".join(js_lines) if self._minify else "\n".join(js_lines)
    
    def _generate_axios(self, method, url, headers, body):
        """Generate axios code"""
        js_lines = []
        
        js_lines.append("axios({")
        js_lines.append("method:'" + method.lower() + "',")
        js_lines.append("url:'" + self._escape_string(url) + "',")
        
        if headers:
            js_lines.append("headers:{")
            header_lines = []
            for key, value in headers.items():
                header_lines.append("'" + self._escape_string(key) + "':'" + self._escape_string(value) + "'")
            js_lines.append(",".join(header_lines))
            js_lines.append("},")
        
        if body and method.upper() in ['POST', 'PUT', 'PATCH']:
            try:
                json_obj = json.loads(body)
                body_str = json.dumps(json_obj)
            except:
                body_str = body
            js_lines.append("data:'" + self._escape_string(body_str) + "',")
        
        js_lines.append("withCredentials:true")
        js_lines.append("}).then(r=>console.log('Success:',r.data)).catch(e=>console.error('Error:',e));")
        
        return "".join(js_lines) if self._minify else "\n".join(js_lines)
    
    def _generate_jquery(self, method, url, headers, body):
        """Generate jQuery AJAX code"""
        js_lines = []
        
        js_lines.append("$.ajax({")
        js_lines.append("type:'" + method + "',")
        js_lines.append("url:'" + self._escape_string(url) + "',")
        
        if headers:
            js_lines.append("headers:{")
            header_lines = []
            for key, value in headers.items():
                header_lines.append("'" + self._escape_string(key) + "':'" + self._escape_string(value) + "'")
            js_lines.append(",".join(header_lines))
            js_lines.append("},")
        
        if body and method.upper() in ['POST', 'PUT', 'PATCH']:
            try:
                json_obj = json.loads(body)
                body_str = json.dumps(json_obj)
            except:
                body_str = body
            js_lines.append("data:'" + self._escape_string(body_str) + "',")
        
        js_lines.append("xhrFields:{withCredentials:true},")
        js_lines.append("crossDomain:true,")
        js_lines.append("success:function(d){console.log('Success:',d);},")
        js_lines.append("error:function(e){console.error('Error:',e);}")
        js_lines.append("});")
        
        return "".join(js_lines) if self._minify else "\n".join(js_lines)
    
    def _escape_string(self, s):
        """Escape string for JavaScript"""
        if not s:
            return ""
        
        s = str(s)
        s = s.replace('\\', '\\\\')
        s = s.replace("'", "\\'")
        s = s.replace("\n", "\\n")
        s = s.replace("\t", "\\t")
        s = s.replace("\r", "\\r")
        s = s.replace('"', '\\"')
        
        return s
    
    def _minify_javascript(self, code):
        """Minify JavaScript code"""
        # Already minified during generation for tight output
        return code.strip()
