/*
	Implementation of IScanIssue interface for Java object serialization remote code execution vulnerability
*/

package burp;

import java.net.URL;

public class SerializationRCEScanIssue implements IScanIssue {
	private String confidence;
	private IHttpRequestResponse[] httpMessages;
	private IHttpService httpService;
	private String issueBackground;
	private String issueDetail;
	private String issueName;
	private int issueType;
	private String remediationBackground;
	private String remediationDetail;
	private String severity;
	private URL url;
	private int detailId; //identifier for how vulnerability was detected
	
	private static final String ISSUE_BACKGROUND = "Java deserialization vulnerabilities occur when an application fails to properly sanitize user-supplied Java "+
													"serialized data. Just like any other HTTP request, all user-controlled input must be validated on the server side."+
													" If the application does not sanitize or validate the serialized object safely, subsequent library methods within "+
													"the class path can be leveraged for code execution by reading the object using the readObject() method. The three "+
													"primary libraries leveraged for further exploitation are: Spring Framework <=3.0.5, <=2.0.6, Groovy < 2.44, Apache "+
													"Commons Collection.<br><br><b>Credit</b>: Credit is given to the presentation \"Marshalling Pickles - AppSec "+
													"California 2015\" by Chris Frohoff & Gabrial Lawrence; Mattias Kaiser's presentation \"Exploiting Deserialization"+
													" Vulnerabilities in Java\"; and the blog from Foxglove Security titled \"What Do WebLogic, WebSphere, JBoss, "+
													"Jenkins, OpenNMS, and Your Application Have in Common. This Vulnerability\" for bringing this issue to our attention.";
	private static final String REM_BACKGROUND = "Each remediation effort may vary due to application functionality, limitations of the environment and the libraries being "+
													"utilized. For all third provided software solutions such as JBoss, WebSphere, WebLogic, Jenkins and OpenNMS, contact the"+
													" vendor for security update information. All other developed applications should override the resolveClass method from "+
													"the ObjectInputStream class. The goal of overriding method is to limit the objects being deserialized to those that are "+
													"expected or desired. All other objects being deserialized should be ignored and disposed of properly. More details can be"+
													" read in the following article entitled “Look-ahead Java deserialization” written in January 2013: "+
													"<a href=\"http://www.ibm.com/developerworks/library/se-lookahead/\">http://www.ibm.com/developerworks/library/se-lookahead/</a>";
	
	public SerializationRCEScanIssue(IHttpRequestResponse rr,IHttpService hs,URL u,int id) {
		confidence = "Tentative";
		httpMessages = new IHttpRequestResponse[] {rr};
		httpService = hs;
		issueBackground = ISSUE_BACKGROUND;
		issueName = "Potential Java Deserialization Vulnerability";
		issueType = 0;
		remediationBackground = REM_BACKGROUND;
		remediationDetail = null;
		severity = "High";
		url = u;
		detailId = id;
		
		//set correct Issue Detail
		issueDetail = constructIssueDetail(detailId);
	}
	
	/* input: what was found
	* 1: request header
	* 2: request data
	* 3: request header and data
	* 4: response header
	* 5: request header, response header
	* 6: request data, response header
	* 7: request header and data, response header
	* 8: response data
	* 9: request header, response data
	* 10: request data, response data
	* 11: request header and data, response data
	* 12: response header and data
	* 13: request header, response header and data
	* 14: request data, response header and data
	* 15: request header and data, response header and data */
	public String constructIssueDetail(int id) {
		String detail = "The application ";
		
		//application "may" or "appears to" transmit
		//"may": no actual data found
		//"appears to": data found
		if((id==1) || (id==4) || (id==5)) detail += "may ";
		else detail += "appears to ";
		detail += "transmit Java serialized objects. ";
		
		//content-type header, skip if none found
		if((id!=2) && (id!=8) && (id!=10)) {
			detail += "The Content-Type header of the ";
			
			if((id==1) || (id==3) || (id==9) || (id==11)) detail += "request was"; //request header (only) found
			else if((id==4) || (id==6) || (id==12) || (id==14)) detail += "server response was"; //response header (only) found
			else detail += "request and the server response were"; //request and response headers found
			
			detail += " set to <b>application/x-java-serialized-object</b>. ";
		}
		
		//data, skip if none found
		if((id!=1) && (id!=4) && (id!=5)) {
			if((id==2) || (id==8) || (id==10)) detail += "The ";
			else detail += "Additionally, the ";
			
			if((id==2) || (id==3) || (id==6) || (id==7)) detail += "request body"; //request data (only) found
			else if((id==8) || (id==9) || (id==12) || (id==13)) detail += "server response body"; //response data (only) found
			else detail += "request body and the server response body"; //request and response data found
			
			detail += " began with the hexadecimal value <b>0xACED0005</b>. ";
		}
		
		detail += "This indicates that the URL may be subject to attack.";
		
		return detail;
	}
	
	@Override
	public String getConfidence() {
		return confidence;
	}
	
	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		return httpMessages;
	}
	
	@Override
	public IHttpService getHttpService() {
		return httpService;
	}
	
	@Override
	public String getIssueBackground() {
		return issueBackground;
	}
	
	@Override
	public String getIssueDetail() {
		return issueDetail;
	}
	
	@Override
	public String getIssueName() {
		return issueName;
	}
	
	@Override
	public int getIssueType() {
		return issueType;
	}
	
	@Override
	public String getRemediationBackground() {
		return remediationBackground;
	}
	
	@Override
	public String getRemediationDetail() {
		return remediationDetail;
	}
	
	@Override
	public String getSeverity() {
		return severity;
	}
	
	@Override
	public URL getUrl() {
		return url;
	}
}