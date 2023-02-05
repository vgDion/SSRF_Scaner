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
            # set extension name
    callbacks.setExtensionName("SSRF Vulnerability Scanner")

    # register an HTTP listener
    callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return

        # get the request
        request = messageInfo.getRequest()
        requestInfo = self._helpers.analyzeRequest(request)

        # check for SSRF vulnerability and if found, add a scan issue
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

        # check if the host is '127.0.0.1' or 'localhost'
        if parsed_host == "127.0.0.1" or parsed_host == "localhost":
            return True

        # check if the host is a private IP
        if self.checkForPrivateIP(parsed_host):
            return True

        # check if the host is a reserved IP
        if self.checkForReservedIP(parsed_host):
            return True

        # check if the host is an internal hostname
        if self.checkForInternalHostname(parsed_host):
            return True

        return False

    def checkForPrivateIP(self, host):
        # check if the host is a private IP
        if host.startswith("10.") or host.startswith("172.") or host.startswith("192.168."):
            return True
        return False

    def checkForReservedIP(self, host):
        # check if the host is a reserved IP
        if host.startswith("0.") or host.startswith("169.254.") or host.startswith("192.0.0.") or host.startswith(
                "198.18"):
            return True
        return False

    def checkForInternalHostname(self, host):
        # check if the host is an internal hostname
        if host.endswith(".local") or host.endswith(".internal"):
            return True
        return False
