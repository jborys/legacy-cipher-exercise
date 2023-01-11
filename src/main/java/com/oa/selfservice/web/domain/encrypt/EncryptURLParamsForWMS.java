package com.oa.selfservice.web.domain.encrypt;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class EncryptURLParamsForWMS {

	private static byte[] keyBytes = new byte[] { 0x43, 0x79, (byte) 0xd5,
			(byte) 0xac, 0x16, 0x7f, 0x45, 0x74, (byte) 0x92, 0x13,
			(byte) 0xe2, 0x2e, 0xb, (byte) 0x7b, (byte) 0xc4, (byte) 0x93,
			(byte) 0xcb, 0x61, 0xb, 0x7e, (byte) 0xbf, 0x04, 0x4f, 0x66,
			(byte) 0x82, 0x5b, 0x7, (byte) 0x34, (byte) 0x9c, 0x6d, 0x39, 0x56 };
	private static SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

	public static String encrypt(String code) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		byte[] input = code.getBytes(StandardCharsets.UTF_8);

		Cipher cipher = Cipher.getInstance("AES/ECB/ZeroBytePadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
		int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
		cipher.doFinal(cipherText, ctLength);

		String result = new String(Base64.encodeBase64(cipherText));
		result = java.net.URLEncoder.encode(result, StandardCharsets.UTF_8);

		return result;
	}

	public static String decrypt(String code) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		byte[] input = Base64.decodeBase64(code.getBytes());
		Cipher cipher = Cipher.getInstance("AES/ECB/ZeroBytePadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] utf8 = cipher.doFinal(input);

		String result = new String(utf8, StandardCharsets.UTF_8);

		return result;
	}

}
