# SuperSerial
SuperSerial - Burp Java Deserialization Vulnerability Identification 

See Blog: https://www.directdefense.com/superserial-java-deserialization-burp-extension/

To help our customers and readers identify or locate Java Deserialization issues, we have created a Burp Suite Extender called “Super Serial” (South Park reference of Al Gore). This first Burp Extension release will help you locate all Java Serialized objects from the server responses, which will likely indicate a Java Deserialization issue.
 
You may ask, why are you not looking at the request as that is where this issue ultimately stems from? Well passive scanning mode may not contain serialized objects during initial spidering or manual walkthrough of an application due to false data being sent by the proxy. Looking at the response is helpful for identification due to the fact that most applications will respond with a serialized object if it was expecting a serialized request. As you can imagine this is not a silver bullet approach. The only way your team can identify all deserialization issues is from a code review perspective.
 
1. To use this extension, please download the latest jar file
 
2. Once downloaded, load the extender Jar in the Extender tab.

3. Next, turn on Passive Scanning in the scanner tab and spider your application environments. You may want to constrain it to “Suite Scope” to avoid scanning other party’s applications, but make sure you set the scope in the Target tab appropriately.

4. Since serialized data will appear as binary in Burp, make sure to change your filters in the proxy history and target tab to show “Other Binary”.

5. Finally, spider your application’s environment and manually walk through all interfaces. If anything was discovered, it will appear in the scanner tab.

Externder written by Jeff Cap
