package com.oa.selfservice.web.domain.encrypt;

import com.oa.selfservice.web.ui.I18NConstants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URLDecoder;

import static org.assertj.core.api.Assertions.assertThat;

public class EncryptURLParamsForWMSTest {

	private static final String linkParameters = "lastName=Crowther&referenceNumber=XYZZYX";
	private static final String encryptedString = "vRXYLYvjrn3O7GFbBHc01eP9zmXEDZgq%2F56UKl%2FE0hHYu10rXONCIjuPG6LAvkE4";
	
	@BeforeAll
	
	public static void loadCrypto() {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	@Test
	public void encryptedParametersShouldMatchExpectedValues() throws Exception {
		String encryptedResult = EncryptURLParamsForWMS.encrypt(linkParameters);
		assertThat(encryptedResult).isEqualTo(encryptedString);
	}
	
	@Test
	public void decryptedParametersShouldMatchExpectedValues() throws Exception {
		String decodedResult = URLDecoder.decode(encryptedString, I18NConstants.UTF8);
		String decryptedResult = EncryptURLParamsForWMS.decrypt(decodedResult);
		assertThat(decryptedResult).isEqualTo(linkParameters);
	}
	
    @Test
    public void encryptedParametersShouldDecryptToOriginalParameters() throws Exception {
    	String plainText = String.valueOf(System.currentTimeMillis());
    	String encryptedResult = EncryptURLParamsForWMS.encrypt(plainText);
    	String decodedResult = URLDecoder.decode(encryptedResult, I18NConstants.UTF8);
    	String decryptedResult = EncryptURLParamsForWMS.decrypt(decodedResult);
		assertThat(decryptedResult).isEqualTo(plainText);
    }

}
