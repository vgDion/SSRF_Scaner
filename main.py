from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
import array
from urlparse import urlparse, unquote
import re


class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SSRF Scanner")
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):
        try:
            requestInfo = self._helpers.analyzeRequest(baseRequestResponse)
            headers = requestInfo.getHeaders()
            requestBody = baseRequestResponse.getRequest()[requestInfo.getBodyOffset():]
            url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
            parsedUrl = urlparse(str(url))

            # Check if the URL scheme is http or https
            if not parsedUrl.scheme in ["http", "https"]:
                return None

            # Extract the parameters from the request
            parameters = requestInfo.getParametersfor parameter in parameters:
                paramValue = parameter.getValue()
                # Check if the parameter value is a URL
                if re.match("^http[s]?", paramValue):
                    # Decode the URL
                    paramValue = unquote(paramValue)

                    # Create a new URL with the parameter value
                    newUrl = urlparse(paramValue)

                    if not newUrl.scheme or not newUrl.hostname:
                        print("some prob")
                        continue

                    # Check if the host of the new URL is the same as the host of the original URL
                    if newUrl.hostname != parsedUrl.hostname:
                        # Send a request to the new URL and check if the response is successful
                        checkRequest = self._helpers.buildHttpRequest(requestInfo.getUrl())

                        malUrlhostname = "localhost/admin"
                        malUrlport = 443

                        checkRequest = checkRequest.replace(requestInfo.getUrl().toString(), "localhost/admin")
                        checkResponse = self._callbacks.makeHttpRequest(malUrlhostname, malUrlport, False,
                                                                        checkRequest)


                        if checkResponse.getStatusCode() < 400:

                            issue = ScanIssue(
                                baseRequestResponse.getHttpService(),
                                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                [self._callbacks.applyMarkers(baseRequestResponse, None,
                                                              [parameter.getNameStart(), parameter.getNameEnd(),
                                                               parameter.getValueStart(), parameter.getValueEnd()])],
                                "SSRF Vulnerability",
                                "The parameter " + parameter.getName() + " in " + requestInfo.getUrl().getPath() + " appears to be vulnerable to SSRF. The application was able to successfully make a request to an external URL.",
                                "High"
                            )
                            print("Potential SSRF vulnerabilities found in " + url.toString())
                            return [issue]
                        else: print("No potential SSRF vulnerabilities found in " + url.toString())
        except Exception as e:
            print(e)
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        try:
            requestInfo = self._helpers.analyzeRequest(baseRequestResponse)
            headers = requestInfo.getHeaders()
            requestBody = baseRequestResponse.getRequest()[requestInfo.getBodyOffset():]
            url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
            parsedUrl = urlparse(str(url))

            # Check if the request is a GET or POST request
            if not requestInfo.getMethod() in ["GET", "POST"]:
                return None

            # Check if the URL scheme is http or https
            if not parsedUrl.scheme in ["http", "https"]:
                return None

            # Extract the parameters from the request
            parameters = requestInfo.getParameters()

            for parameter in parameters:
                paramValue = parameter.getValue()

                # Check if the parameter value is a URL
                if re.match("^http[s]?", paramValue):
                    #Decode the URL and extract the hostname
                    paramValue = unquote(paramValue)
                    newUrl = urlparse(paramValue)
                    #print(newUrl)
                    #print(newUrl.hostname)
                    #print(newUrl.port)
                    if not newUrl.scheme or not newUrl.hostname:
                        print("some prob")
                        continue
                # Check if the host of the new URL is the same as the host of the original URL
                    if newUrl.hostname != parsedUrl.hostname:
                        # Send a request to the new URL and check if the response is successful
                        checkRequest = self._helpers.buildHttpRequest(requestInfo.getUrl())

                        malUrlhostname = "localhost/admin"
                        malUrlport = 443
                        checkRequest = checkRequest.replace(requestInfo.getUrl().toString(), "localhost/admin")

                        checkResponse = self._callbacks.makeHttpRequest(malUrlhostname, malUrlport, False,
                                                                        checkRequest)


                        if checkResponse.getStatusCode() < 400:

                            # Issue description
                            description = "The parameter " + parameter.getName() + " in " + requestInfo.getUrl().getPath() + " appears to be vulnerable to SSRF. The application was able to successfully make a request to an external URL."

                            # Issue severity
                            severity = "High"

                            # Issue name
                            issueName = "SSRF Vulnerability"

                            # Issue background
                            issueBackground = "Server-Side Request Forgery (SSRF) is a vulnerability that occurs when an application allows an attacker to send requests from the server-side of the application to a destination specified by the attacker."

                            # Issue detail
                            issueDetail = "The parameter " + parameter.getName() + " in " + requestInfo.getUrl().getPath() + " appears to be vulnerable to SSRF. The application was able to successfully make a request to an external URL."

                            # Create a ScanIssue object
                            scanIssue = ScanIssue(
                                baseRequestResponse.getHttpService(),
                                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                [self._callbacks.applyMarkers(baseRequestResponse, None,
                                                              [parameter.getNameStart(), parameter.getNameEnd(),
                                                               parameter.getValueStart(), parameter.getValueEnd()])],
                                issueName,
                                issueDetail,
                                severity
                            )

                            print("Potential SSRF vulnerabilities found in " + url.toString())
                            self._callbacks.addScanIssue(scanIssue)
                        else:print("No potential SSRF vulnerabilities found in " + url.toString())

            return None
        except Exception as e:
            print(e)
            return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getUrl() == newIssue.getUrl() and existingIssue.getIssueName() == newIssue.getIssueName() and existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1
        else:
            return 0


class ScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
