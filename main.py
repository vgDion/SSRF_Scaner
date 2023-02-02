from burp import IBurpExtender
from burp import IHttpListener



class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Get a reference to the helpers object
        self._helpers = callbacks.getHelpers()

        # Set the extension name
        callbacks.setExtensionName("SSRF Vulnerability Scanner")

        # Register the HTTP listener
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process requests, not responses
        if not messageIsRequest:
            return

        # Get the request and request information
        request = messageInfo.getRequest()
        requestInfo = self._helpers.analyzeRequest(request)

        # Check if the request is vulnerable to SSRF
        if self.checkForSSRF(requestInfo):
            # Report the vulnerability to Burp
            self.callbacks.addScanIssue(self.ScanIssue(
                messageInfo.getHttpService(),
                self._helpers.analyzeRequest(messageInfo).getUrl(),
                [self._callbacks.getScanIssues("SSRF Vulnerability")],
                "SSRF Vulnerability",
                "The request is vulnerable to SSRF",
                "High",
                "Certain"))

    def checkForSSRF(self, requestInfo):
        # Extract the URL from the request
        url = requestInfo.getUrl().toString()

        # Check for known blacklisted IP addresses or localhost addresses
        if "localhost" in url or "127.0.0.1" in url:
            return True

        # Check for known file URIs, e.g. file://
        if "file://" in url:
            return True

        # Check for known protocol that shouldn't be used in requests
        blacklisted_protocols = ["gopher", "dict", "dict://", "tp://", "tftp://", "ldap://", "ldaps://", "rtsp://"]
        for protocol in blacklisted_protocols:
            if protocol in url:
                return True

        # Check for external IP address


        # If none of the checks above return True, then the request is not vulnerable to SSRF
        return False
