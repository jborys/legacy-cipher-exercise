package com.oa.selfservice.web.domain.encrypt;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class EncryptDiscountCode {

    private static byte[] keyBytes = new byte[] { (byte) 0xB8, (byte) 0xC1, 0x02, (byte) 0xF3, 0x24, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x40, (byte) 0xC1, 0x12, (byte) 0xF3, 0x14, (byte) 0xF5, 0x16, (byte) 0xC7 };
    private static SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

    public static String encrypt(String code) throws Exception {
        if (code != null && code.startsWith("_!_")) {
            return code;
        }
        String result = "";
        byte[] input = code.getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        cipher.doFinal(cipherText, ctLength);
        result = new String(Base64.encodeBase64(cipherText));

        result = java.net.URLEncoder.encode(result, StandardCharsets.UTF_8);
        result = "_!_" + result;

        return result;
    }

    public static String decrypt(String code) throws Exception {
        if (code != null && !code.startsWith("_!_")) {
            return code;
        } else {
            code = code.substring(3);
        }

        byte[] input = Base64.decodeBase64(code.getBytes());

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = new byte[cipher.getOutputSize(input.length)];
        int ptLength = cipher.update(input, 0, input.length, plainText, 0);
        cipher.doFinal(plainText, ptLength);
        
        String result = new String(plainText).trim();
        
        return result;
    }
}
