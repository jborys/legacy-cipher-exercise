package com.oa.selfservice.web.domain.encrypt;

import static org.junit.Assert.assertEquals;

import java.net.URLDecoder;

import org.junit.BeforeClass;
import org.junit.Test;

import com.oa.selfservice.web.domain.encrypt.EncryptURLParamsForWMS;
import com.oa.selfservice.web.ui.I18NConstants;

public class EncryptURLParamsForWMSTest {

	private static final String linkParameters = "lastName=Crowther&referenceNumber=XYZZYX";
	private static final String encryptedString = "vRXYLYvjrn3O7GFbBHc01eP9zmXEDZgq%2F56UKl%2FE0hHYu10rXONCIjuPG6LAvkE4";
	
	@BeforeClass
	
	public static void loadCrypto() {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	@Test
	public void encryptedParametersShouldMatchExpectedValues() throws Exception {
		String encryptedResult = EncryptURLParamsForWMS.encrypt(linkParameters);
		assertEquals(encryptedString, encryptedResult);
	}
	
	@Test
	public void decryptedParametersShouldMatchExpectedValues() throws Exception {
		String decodedResult = URLDecoder.decode(encryptedString, I18NConstants.UTF8);
		String decryptedResult = EncryptURLParamsForWMS.decrypt(decodedResult);
		
		assertEquals(linkParameters, decryptedResult);
	}
	
    @Test
    public void encryptedParametersShouldDecryptToOriginalParameters() throws Exception {
    	String plainText = String.valueOf(System.currentTimeMillis());
    	String encryptedResult = EncryptURLParamsForWMS.encrypt(plainText);
    	String decodedResult = URLDecoder.decode(encryptedResult, I18NConstants.UTF8);
    	String decryptedResult = EncryptURLParamsForWMS.decrypt(decodedResult);
    	
    	assertEquals(plainText, decryptedResult);
    }

}
