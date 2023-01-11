package com.oa.selfservice.web.domain.encrypt;

import com.oa.selfservice.web.ui.I18NConstants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URLDecoder;
import java.net.URLEncoder;

import static org.assertj.core.api.Assertions.assertThat;

public class EncryptURLParamsTest { 
	
    private static final String carrierCode = "BA";
    private static final String textParameters = "&bookingRef=MPWGFG&lastName=BATEST";
    private static final String encodedParameters = "HlwU9yvKJnJHC9QAUfi6uwY2r7zA5rnYbz3q8hgV0r9%2FR8EcxBNprw%3D%3D";

	@BeforeAll
	public static void loadCrypto() {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
    @Test
    public void encryptedParametersShouldMatchExpectedValues() throws Exception {
        String encryptedResult = EncryptURLParams.encrypt(textParameters, carrierCode);
        String encodedResult = URLEncoder.encode(encryptedResult, I18NConstants.UTF8);
        assertThat(encodedResult).isEqualTo(encodedParameters);
    }

    @Test
    public void decryptedParametersShouldMatchExpectedValues() throws Exception {
        String decodedResult = URLDecoder.decode(encodedParameters, I18NConstants.UTF8);
    	String decryptedResult = EncryptURLParams.decrypt(decodedResult, carrierCode);
        assertThat(decryptedResult).isEqualTo(textParameters);
    }
    
    @Test
    public void encryptedParametersShouldDecryptToOriginalParameters() throws Exception {
    	String plainText = String.valueOf(System.currentTimeMillis());
    	String encryptedResult = EncryptURLParams.encrypt(plainText, carrierCode);
    	String decryptedResult = EncryptURLParams.decrypt(encryptedResult, carrierCode);
        assertThat(decryptedResult).isEqualTo(plainText);
    }
}
