from burp import IBurpExtender
from burp import IHttpListener
import urlparse

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        
        self._helpers = callbacks.getHelpers()
        
      
        callbacks.setExtensionName("SSRF Vulnerability Scanner")
        
        
        callbacks.registerHttpListener(self)
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        
        if not messageIsRequest:
            return
        
        
        request = messageInfo.getRequest()
        requestInfo = self._helpers.analyzeRequest(request)
        
       
        if self.checkForSSRF(requestInfo):
            
            callbacks.addScanIssue(ScanIssue(
                messageInfo.getHttpService(),
                self._helpers.analyzeRequest(messageInfo).getUrl(),
                [self._callbacks.getScanIssues("SSRF Vulnerability")],
                "SSRF Vulnerability",
                "The request is vulnerable to SSRF",
                "High",
                "Certain"))
    
    def checkForSSRF(self, requestInfo):
       
        host = requestInfo.getUrl().getHost()
        parsed_host = urlparse.urlparse(host).hostname
        if parsed_host == "127.0.0.1" or parsed_host == "localhost":
            return True
        
        
        if self.checkForPrivateIP(parsed_host):
            return True
        
        
        if self.checkForReservedIP(parsed_host):
            return True
           
        
        return False
    
    
    def checkForPrivateIP(self, host):
       
        if host.startswith("10.") or host.startswith("172.") or host.startswith("192.168."):
            return True
        return False
    
    def checkForReservedIP(self, host):
        
        if host.startswith("0.") or host.startswith("169.254.") or host.startswith("192.") or host.startswith("198.18."):
            return True
        return False
