package com.oa.selfservice.web.domain.encrypt;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class EncryptDiscountCodeTest {
	private static final String discountCode = "FLY4LESS";
	private static final String encryptedDiscountCode = "_!_hi3FWj3DzQejgG%2FzyWkZaQ%3D%3D";
	
	@BeforeAll
	public static void loadCrypto() {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	@Test
	public void alreadyEncryptedDiscountCodeShouldReturnSameCode() throws Exception {
		String result = EncryptDiscountCode.encrypt(encryptedDiscountCode);
		assertThat(result).isEqualTo(encryptedDiscountCode);
//		assertEquals(encryptedDiscountCode, result);
	}
	
	@Test
	public void encryptedDiscountCodeShouldStartWithUnderscoresAndExclamation() throws Exception { 
		String result = EncryptDiscountCode.encrypt(discountCode);
		assertThat(result).startsWith("_!_");
	}
	
	@Test
	public void encryptDiscountCodeShouldReturnCorrectBase64Code() throws Exception {
		String result = EncryptDiscountCode.encrypt(discountCode);
		assertThat(result).isEqualTo(encryptedDiscountCode);
	}
	
	@Test
	public void alreadyDecryptedDiscountCodeShouldReturnSameCode() throws Exception {
		String result = EncryptDiscountCode.decrypt(discountCode);
		assertThat(result).isEqualTo(discountCode);
	}
	
	@Test
	public void decryptDiscountCodeShouldReturnCorrectPlainTextCode() throws Exception {
		String result = EncryptDiscountCode.decrypt(URLDecoder.decode(encryptedDiscountCode, StandardCharsets.UTF_8)).trim();
		assertThat(result).isEqualTo(discountCode);
	}
	
	@Test
	public void encryptedDiscountCodeShouldDecryptToOriginalCode() throws Exception {
		String encrypted = EncryptDiscountCode.encrypt(discountCode);
		String decrypted = EncryptDiscountCode.decrypt(URLDecoder.decode(encrypted, StandardCharsets.UTF_8)).trim();
		assertThat(decrypted).isEqualTo(discountCode);
	}

}
