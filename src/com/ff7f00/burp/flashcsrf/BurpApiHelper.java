package com.ff7f00.burp.flashcsrf;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IResponseInfo;

public class BurpApiHelper {
	public static void sendRequestResponseToRepeater(IBurpExtenderCallbacks callback, IHttpRequestResponse req){
		callback.sendToRepeater(req.getHttpService().getHost(), req.getHttpService().getPort(), req.getHttpService().getProtocol().equalsIgnoreCase("https"), req.getRequest(), null);
	}
	
	public static void sendRequestResponseToIntruder(IBurpExtenderCallbacks callback, IHttpRequestResponse req){
		callback.sendToIntruder(req.getHttpService().getHost(), req.getHttpService().getPort(), req.getHttpService().getProtocol().equalsIgnoreCase("https"), req.getRequest(), null);
	}
	
	public static int getResponseBodyLength(IResponseInfo responseInfo, byte[] response) {
		for (String header: responseInfo.getHeaders()) {
			if (header.toLowerCase().startsWith("content-length:")) {
				return Integer.parseInt(header.substring(header.indexOf(":") + 1).trim());
			}
		}
		
		// if no content-length header returned, let's calculate it manually
		String resp = new String(response);
		String body = resp.substring(responseInfo.getBodyOffset());
				
		return body.length();
	}
	
	public static String iParameterTypeToString(IParameter param){
		String type = "";
		switch(param.getType()){
		case IParameter.PARAM_BODY:
			type = "Body";
			break;
		case IParameter.PARAM_COOKIE:
			type = "Cookie";
			break;
		case IParameter.PARAM_JSON:
			type = "JSON";
			break;
		case IParameter.PARAM_MULTIPART_ATTR:
			type = "Mutlipart";
			break;
		case IParameter.PARAM_URL:
			type = "URL";
			break;
		case IParameter.PARAM_XML:
			type = "XML";
			break;
		case IParameter.PARAM_XML_ATTR:
			type = "XML-Attr";
			break;
		default:
			type = "Unknown";
		}
		return(type);
	}
	
	public static Map<String, String> getHeadersMap(List<String> headers) {
		Map<String, String> map = new HashMap<String, String>();
		for (String header: headers) {
			map.put(header.substring(0, header.indexOf(":")).trim(), 
					header.substring(header.indexOf(":"), header.length()).substring(1).trim());
		}
		return map;
	}
}
