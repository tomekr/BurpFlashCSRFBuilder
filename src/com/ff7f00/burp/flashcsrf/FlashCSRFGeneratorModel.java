package com.ff7f00.burp.flashcsrf;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import java.util.Arrays;

public class FlashCSRFGeneratorModel {
	// Constants
	private static final Set<String> BLACKLISTED_HEADER_FIELDS = new HashSet<String>(Arrays.asList(
		     new String[] {"Accept-Charset", "Accept-Encoding", "Accept-Ranges",
						"Age", "Allow", "Allowed", "Authorization", "Charge-To",
						"Connect", "Connection", "Content-Length",
						"Content-Location", "Content-Range", "Cookie", "Date",
						"Delete", "ETag", "Expect", "Get", "Head", "Host",
						"If-Modified-Since", "Keep-Alive", "Last-Modified",
						"Location", "Max-Forwards", "Options", "Origin", "Post",
						"Proxy-Authenticate", "Proxy-Authorization",
						"Proxy-Connection", "Public", "Put", "Range", "Referer",
						"Request-Range", "Retry-After", "Server", "TE", "Trace",
						"Trailer", "Transfer-Encoding", "Upgrade", "URI",
						"User-Agent", "Vary", "Via", "Warning", "WWW-Authenticate",
						"x-flash-version"}
		));

	private IHttpRequestResponse request;
	private IBurpExtenderCallbacks burpCallback;
	
	// local instance variables
	private String url;
	private byte[] body;
	private String method;
	private Map<String, String> currentHeaders;
	
	/** Constructor */
	public FlashCSRFGeneratorModel(IHttpRequestResponse request,
			IBurpExtenderCallbacks burpCallback) {
		this.request = request;
		this.burpCallback = burpCallback;
		this.url = getUrlFromCallback();
		this.body = getBodyFromCallback();
                burpCallback.issueAlert("hello");
                burpCallback.issueAlert(burpCallback.getHelpers().bytesToString(this.body));
		this.currentHeaders = getNonBlacklistedHeaders();
	}

	public IBurpExtenderCallbacks getBurpCallback() {
		return burpCallback;
	}
        

	/** Set the request */
	public String getRequestHostName() {
		return request.getHttpService().getHost();
	}

	public Map<String, String> getNonBlacklistedHeaders() {
		Map<String, String> headers = getHeaders();

		// Remove the blacklisted headers from the headers map
		for (String blacklistedHeader : BLACKLISTED_HEADER_FIELDS) {
			headers.remove(blacklistedHeader);
		}

		return headers;
	}
	
	public String[][] getFinalHeadersString() {
		Map<String, String>headers = getNonBlacklistedHeaders();
		String[][] tableData = new String[headers.keySet().size()][2];
		
		int index = 0;
		for (Map.Entry<String, String> entry : headers.entrySet()) {
		    tableData[index][0] = entry.getKey();
		    tableData[index][1] = entry.getValue();
		    index++;
		}
		
		return tableData;
	}

	public Map<String, String> getHeaders() {
		List<String> headers = burpCallback.getHelpers()
											.analyzeRequest(request.getRequest())
											.getHeaders();
		// Remove the first element (which contains the HTTP method and path)
		// and create a map from the headers
		return BurpApiHelper.getHeadersMap(headers.subList(1, headers.size()));
	}
	
	public void setPoCParameters(String url, byte[] data, Map<String, String> headers) {
		this.url = url;
		this.body = data;
		this.currentHeaders = headers;
	}
	
	private String getUrlFromCallback() {
            return burpCallback.getHelpers().analyzeRequest(request).getUrl().toString();
	}
	
	public String createFragmentForGenerator() {
		StringBuilder fragment = new StringBuilder();	
		String urlEnc = burpCallback.getHelpers().urlEncode(url);
		String headersEnc = getCurrentHeadersUrlEncodedString();
		
		fragment.append("url=" + urlEnc);
		
		if(body.length > 0) {
			fragment.append("&body=" + burpCallback.getHelpers()
                                .urlEncode(burpCallback.getHelpers().bytesToString(body)));
		}
		
		if (!headersEnc.equals("")) {
			fragment.append(headersEnc);
		}
		
		return fragment.toString();
	}
	
	public String getCurrentHeadersUrlEncodedString() {
		StringBuilder headersEnc = new StringBuilder();
		
		for (Map.Entry<String, String> entry : currentHeaders.entrySet()) {
			headersEnc.append("&");
			headersEnc.append(entry.getKey());
			headersEnc.append("=");
			headersEnc.append(burpCallback.getHelpers().urlEncode(entry.getValue()));
		}
		
		return headersEnc.toString();
	}

	public Set<String> getHeaderFields() {
		return getHeaders().keySet();
	}
	
	private byte[] getBodyFromCallback() {
		int offset = burpCallback.getHelpers().analyzeRequest(request).getBodyOffset();
                byte[] req = request.getRequest();
                return Arrays.copyOfRange(req, offset, req.length);
	}

	public IHttpRequestResponse getRequest() {
		return request;
	}
	
	public String getMethod() {
		return burpCallback.getHelpers().analyzeRequest(request).getMethod();
	}
	
	public String getPreflightStatus() {
		return "Not-Required";
	}
	
	public boolean isPreflightRequired() {
		boolean preflightRequired = false;
		
		// Check headers
		for (Map.Entry<String, String> entry : currentHeaders.entrySet()) {
			if(!isSimpleHeaderRow(entry.getKey(), entry.getValue())) {
				preflightRequired = true;
			}
		}
		
		return preflightRequired;
	}
	
	/*
	 * SETTERS
	 */
	
	public void setUrl(String url) { this.url = url; }
	public void setBody(byte[] body) { this.body = body; }
	public void setCurrentHeaders(Map<String, String> headers) { this.currentHeaders = headers; }
	
	/*
	 * GETTERS
	 */
	
	public String getUrl() { return this.url; }
	public byte[] getBody() { return this.body; }
	public Map<String, String> getCurrentHeaders() { return this.currentHeaders; }

	public static boolean isSimpleHeaderRow(String field, String value) {
		if(field.equals("Content-Type")) {
			return true;
		}
		
		return false;
	}
}