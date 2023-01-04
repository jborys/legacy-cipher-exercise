package com.oa.selfservice.web.util;

import java.util.HashMap;
import java.util.Map;

public class ResourceUtil {
	private static Map<String, String> props = new HashMap<String, String>();

	static {
		props.put("olci.cipher.algorithm", "PBEWithSHAAnd3KeyTripleDES");
		props.put("olci.operating.carrier", "BA,IB,JL,JC,NU");
		props.put("olci.operating.JL.passkey", "dGVzdEpBTA==");
		props.put("olci.operating.JC.passkey", "dGVzdEpBTA==");
		props.put("olci.operating.NU.passkey", "dGVzdEpBTA==");
		props.put("olci.operating.IB.passkey", "dGVzdElCQkE=");
		props.put("olci.operating.BA.passkey", "dGVzdElCQkE=");
	}

	public static String getProperty(String string) {
		return props.get(string);
	}

}
