package com.oa.selfservice.web.domain.encrypt;

import static junitx.framework.StringAssert.assertStartsWith;
import static org.junit.Assert.assertEquals;

import java.net.URLDecoder;

import org.junit.BeforeClass;
import org.junit.Test;

import com.oa.selfservice.web.domain.encrypt.EncryptDiscountCode;

public class EncryptDiscountCodeTest {
	private static final String discountCode = "FLY4LESS";
	private static final String encryptedDiscountCode = "_!_hi3FWj3DzQejgG%2FzyWkZaQ%3D%3D";
	
	@BeforeClass
	public static void loadCrypto() {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	@Test
	public void alreadyEncryptedDiscountCodeShouldReturnSameCode() throws Exception {
		String result = EncryptDiscountCode.encrypt(encryptedDiscountCode);
		
		assertEquals(encryptedDiscountCode, result);
	}
	
	@Test
	public void encryptedDiscountCodeShouldStartWithUnderscoresAndExclamation() throws Exception { 
		String result = EncryptDiscountCode.encrypt(discountCode);
		
		assertStartsWith("_!_", result);
	}
	
	@Test
	public void encryptDiscountCodeShouldReturnCorrectBase64Code() throws Exception {
		String result = EncryptDiscountCode.encrypt(discountCode);
		
		assertEquals(encryptedDiscountCode, result);
	}
	
	@Test
	public void alreadyDecryptedDiscountCodeShouldReturnSameCode() throws Exception {
		String result = EncryptDiscountCode.decrypt(discountCode);
		
		assertEquals(discountCode, result);
	}
	
	@Test
	public void decryptDiscountCodeShouldReturnCorrectPlainTextCode() throws Exception {
		String result = EncryptDiscountCode.decrypt(URLDecoder.decode(encryptedDiscountCode, "UTF-8")).trim();
		
		assertEquals(discountCode, result);
	}
	
	@Test
	public void encryptedDiscountCodeShouldDecryptToOriginalCode() throws Exception {
		String encrypted = EncryptDiscountCode.encrypt(discountCode);
		String decrypted = EncryptDiscountCode.decrypt(URLDecoder.decode(encrypted, "UTF-8")).trim();
		assertEquals(discountCode, decrypted);
	}

}
