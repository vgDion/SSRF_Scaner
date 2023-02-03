import sys
from burp import IBurpExtender
from burp import IHttpListener
from burp import IScanIssue
try:
    from urllib.parse import urlparse
except ImportError:
     from urlparse import urlparse

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        
        callbacks.setExtensionName("SSRF Vulnerability Scanner")

        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
        
        request = messageInfo.getRequest()
        requestInfo = self._helpers.analyzeRequest(request)


        if self.checkForSSRF(requestInfo):
            self._callbacks.addScanIssue(IScanIssue(
                messageInfo.getHttpService(),
                requestInfo.getUrl(),
                [self._callbacks.getScanIssues("SSRF Vulnerability")],
                "SSRF Vulnerability",
                "The request is vulnerable to SSRF",
                "High",
                "Certain"))

    def checkForSSRF(self, requestInfo):
        host = requestInfo.getUrl().getHost()
        parsed_host = urlparse(host).hostname
        if parsed_host == "127.0.0.1" or parsed_host == "localhost":
            return True

        if self.checkForPrivateIP(parsed_host):
            return True

        if self.checkForReservedIP(parsed_host):
            return True

        if self.checkForInternalHostname(parsed_host):
            return True

        return False

    def checkForPrivateIP(self, host):
        if host.startswith("10.") or host.startswith("172.") or host.startswith("192.168."):
            return True
        return False

    def checkForReservedIP(self, host):
        if host.startswith("0.") or host.startswith("169.254.") or host.startswith("192.0.0.") or host.startswith(
                "198.18"):
            return True
        return False

    def checkForInternalHostname(self, host):
        if host.endswith(".local") or host.endswith(".internal"):
            return True
        return False
