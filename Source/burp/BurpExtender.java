/*
	BurpExtender.java v0.2
	
	Super Serial - Passive
	
	Extension including passive scan check for Java serialized objects in server response. Checks are based on response 
	content-type and data. Scanner issue is created if content-type is application/x-java-serialized-object OR 
	content-type is application/octet-stream AND response body starts with 0xACED0005. This extension does not do any 
	form of vulnerability exploitation, only potentional vulnerability detection.
*/

package burp;

import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.net.URL;

public class BurpExtender implements IBurpExtender,IScannerCheck {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	
	private static final String CONTENT_TYPE = "application/x-java-serialized-object";
	private static final byte FILE_HEADER_0 = (byte) 172; //0xAC
	private static final byte FILE_HEADER_1 = (byte) 237; //0xED
	private static final byte FILE_HEADER_2 = 0x00; //0x00
	private static final byte FILE_HEADER_3 = 0x05; //0x05
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks mCallbacks) {
		callbacks = mCallbacks;
		helpers = callbacks.getHelpers();
		
		callbacks.setExtensionName("Super Serial - Passive");
		
		callbacks.registerScannerCheck(this);
	}
	
	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		List<IScanIssue> issues = null; //issues to report (if any)
		
		byte[] req = baseRequestResponse.getRequest();
		IRequestInfo reqInfo = helpers.analyzeRequest(req);
		byte[] resp = baseRequestResponse.getResponse();
		IResponseInfo respInfo = helpers.analyzeResponse(resp);
		
		int[][] reqHighlights = processRequest(reqInfo,req);
		int[][] respHighlights = processResponse(respInfo,resp);
		ArrayList<int[]> reqMarkers = null;
		ArrayList<int[]> respMarkers = null;
		
		//parse results
		int resId = 0;
		if(reqHighlights!=null) { //vuln found in request
			reqMarkers = new ArrayList<int[]>(2);
			if(reqHighlights[0]!=null) { //request content-type header found
				resId = resId | 1;
				reqMarkers.add(reqHighlights[0]);
			}
			if(reqHighlights[1]!=null) { //request serialized data found
				resId = resId | 2;
				reqMarkers.add(reqHighlights[1]);
			}
		}
		if(respHighlights!=null) { //vuln found in response
			respMarkers = new ArrayList<int[]>(2);
			if(respHighlights[0]!=null) {
				resId = resId | 4;
				respMarkers.add(respHighlights[0]);
			}
			if(respHighlights[1]!=null) {
				resId = resId | 8;
				respMarkers.add(respHighlights[1]);
			}
		}
		
		if(resId>0) { //vuln found, create highlight Request/Response and scanner issue
			issues = new ArrayList<IScanIssue>(1);
			IHttpRequestResponseWithMarkers issueRR = callbacks.applyMarkers(baseRequestResponse,reqMarkers,respMarkers);
			SerializationRCEScanIssue issue = new SerializationRCEScanIssue(issueRR,issueRR.getHttpService(),helpers.analyzeRequest(issueRR).getUrl(),resId);
			issues.add(issue);
		}
		
		return issues;
	}
	
	//no active scan checks for this extension, therefore do nothing here
	@Override
	public java.util.List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,IScannerInsertionPoint insertionPoint) {
		return null;
	}
	
	/*same HTTP method:
	*	duplicate Issue Detail: duplicate vulnerability (report existing only)
	*	different Issue Detail:
	*		existing issue did not include data, new issue does: new vulnerability (report new only)
	*		existing issue included data but not in response, new issue does: new vulnerability (report new only
	*different HTTP methods: new vulnerability (report both) */
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue,IScanIssue newIssue) {
		String eMethod = null;
		String nMethod = null;
		
		//get HTTP method from issues
		IHttpRequestResponse[] rr = existingIssue.getHttpMessages();
		byte[] req = rr[0].getRequest();
		IRequestInfo reqInfo = helpers.analyzeRequest(req);
		eMethod = reqInfo.getMethod(); //retrieve existingIssue HTTP method
		rr = newIssue.getHttpMessages();
		req = rr[0].getRequest();
		reqInfo = helpers.analyzeRequest(req);
		nMethod = reqInfo.getMethod(); //retrieve newIssue HTTP method
		
		//compare existing and new issues
		int retVal = 0;
		if(eMethod.equals(nMethod)) { //same HTTP method
			String existingIssueDetail = existingIssue.getIssueDetail();
			String newIssueDetail = newIssue.getIssueDetail();
			if(existingIssueDetail.equals(newIssueDetail)) {
				retVal = -1; //duplicate issue
			} else {
				if(!existingIssueDetail.contains("0xACED0005") && newIssueDetail.contains("0xACED0005")) { //existing issue does not contain serialized data, new issue does: replace
					retVal = 1;
				} else if(existingIssueDetail.contains("0xACED0005") && newIssueDetail.contains("0xACED0005")) {
					if(!existingIssueDetail.contains("server response body began with") && newIssueDetail.contains("server response body began with")) { /*existing issue does not contain
																																serialized data in response, new issue does: replace */
						retVal = 1;
					}
				}
			}
		}
		
		return retVal;
	}
	
	//check for vuln in request
	private int[][] processRequest(IRequestInfo reqInfo,byte[] req) {
		int dataStart = reqInfo.getBodyOffset();
		List<String> headers = reqInfo.getHeaders();
		return processMessage(headers,req,dataStart);
	}
	
	//check for vuln in response
	private int[][] processResponse(IResponseInfo respInfo,byte[] resp) {
		int dataStart = respInfo.getBodyOffset();
		List<String> headers = respInfo.getHeaders();
		return processMessage(headers,resp,dataStart);
	}
	
	//check for vuln
	//return values:
	//null: no vulns found
	//int[2]: vuln found
	//	if int[0] is defined: content-type header found
	//	if int[1] is defined: data found
	private int[][] processMessage(List<String> headers,byte[] message,int dataStart) {
		int[][] highlights = null;
		boolean vuln = false; //if a potential vulnerability is found
		boolean contentHighlight = false; //if correct content-type header is found and should be highlighted
		int contentStart = -1; //start of content-type
		int contentEnd = -1; //end of content-type
		boolean dataHighlight = false; //if serialized object header was found and should be highlighted
		
		//first check: check content-type
		Iterator<String> headerItr = headers.iterator();
		while(headerItr.hasNext()) {
			String header = headerItr.next();
			String[] headerSplit = header.split(":",2);
			if((headerSplit.length>1) && (headerSplit[0].equalsIgnoreCase("Content-Type"))) { //content-type header found
				String val = headerSplit[1].trim();
				if(val.contains(CONTENT_TYPE)) { //content-type is expected type, set flags for vuln found and highlight content
					vuln = true;
					contentHighlight = true;
					contentStart = helpers.indexOf(message,header.getBytes(),true,0,message.length);
					contentEnd = contentStart+header.length();
					break;
				}
			}
		}
		
		//second check: check actual data
		//if(data.length>=4) { //data must be at least 4 bytes long; check for serialized object by file header
		if((message.length-dataStart)>=4) { //data must be at least 4 bytes long; check for serialized object by file header
			if(message[dataStart] == FILE_HEADER_0) { //first byte: 0xAC
				if(message[dataStart+1] == FILE_HEADER_1) { //second byte: 0xED
					if(message[dataStart+2] == FILE_HEADER_2) { //third byte: 0x00
						if(message[dataStart+3] == FILE_HEADER_3) { //fourth byte: 0x05
							vuln = true;
							dataHighlight = true;
						} else {
							if(!contentHighlight) vuln = false; //unless content-type is expected type, not a vuln
						}
					} else {
						if(!contentHighlight) vuln = false; //unless content-type is expected type, not a vuln
					}
				} else {
					if(!contentHighlight) vuln = false; //unless content-type is expected type, not a vuln
				}
			} else {
				if(!contentHighlight) vuln = false; //unless content-type is expected type, not a vuln
			}
		}
		
		//if one or both vuln criteria were met, create arrays of necessary highlights
		if(vuln) {
			highlights = new int[2][2];
			highlights[0] = null;
			highlights[1] = null;
			
			if(contentHighlight) highlights[0] = new int[] {contentStart,contentEnd};
			if(dataHighlight) highlights[1] = new int[] {dataStart,message.length};
		}
		
		return highlights;
	}
}