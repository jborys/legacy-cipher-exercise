package com.oa.selfservice.web.util;

import org.apache.commons.lang.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class CipherLoader {
	private static Map<String, String> props = new HashMap<>();

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

	public String[] getOlciCarriersArr() {
		final String[] olciCarriersArr;
		String olciCarriersStr =  getProperty("olci.operating.carrier");
		olciCarriersArr = StringUtils.split(olciCarriersStr, ",");
		return olciCarriersArr;
	}
}
