package com.oa.selfservice.web.domain.encrypt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import com.oa.selfservice.web.util.CipherMaps;
import com.oa.selfservice.web.util.CipherLoader;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.oa.selfservice.web.domain.exception.CryptoException;
import com.oa.selfservice.web.ui.I18NConstants;
import com.oa.selfservice.web.util.OAComConstants;

/**
 * 
 * This class is used for encrypting and decrypting
 * strings using PBEWithMD5AndDES Cipher algorithm. The class is created
 * with a key and can be used repeatedly to encrypt and decrypt strings using
 * that key.
 * 
 */

public class EncryptURLParams {
	CipherLoader configureCarriers = new CipherLoader();
	public static Log logger = LogFactory.getLog(EncryptURLParams.class);
	private final String[] olciCarriersArr;

	public EncryptURLParams() {
		olciCarriersArr = configureCarriers.getOlciCarriersArr();
		CipherMaps.createCipherMaps();
	}

	public void initializeCarrierCodes() {
		for (String carrierCode : olciCarriersArr) {
			init(carrierCode);
		}
	}

	private static String getOperatingCarrierPassKey(String carrierCode) {

		String carrierPasskey = CipherLoader.getProperty(StringUtils.replace(
				OAComConstants.OLCI_OPERATING_CARRIER_PASSKEY,
				"${carrier}", carrierCode));
		if (StringUtils.isEmpty(carrierPasskey)) {
				logger.error("Warning, operating carrier passkey is empty for property: "
						+ carrierCode);
		}
		if (logger.isDebugEnabled()) {
			logger.debug("Returning operating carrier passkey: " + carrierPasskey + " for property: "
					+ carrierCode);
		}
		return carrierPasskey;
	}

	public static String encrypt(String plainText, String carrierCode) throws CryptoException {
		String returnValue;
		Cipher ecipher;
		EncryptURLParams encryptURLParams = new EncryptURLParams();
		encryptURLParams.initializeCarrierCodes();

		try {
			// Encode the string into bytes using utf-8
			byte[] utf8 = plainText.getBytes(I18NConstants.UTF8);

			// Encrypt
			ecipher = CipherMaps.ecipherMap.get(carrierCode);
			if (ecipher == null){
				synchronized (EncryptURLParams.class) {
					init(carrierCode);
				}
			}
			byte[] enc = ecipher.doFinal(utf8);

			// Encode bytes to base64 to get a string
			returnValue = new String(Base64.encodeBase64(enc));

		} catch (BadPaddingException e) {
				logger.error("BadPaddingException in EncryptURLParams for Request: "+ e);
			throw new CryptoException("BadPaddingException in EncryptURLParams for Request: ", e);
		} catch (IllegalBlockSizeException e) {
				logger.error("IllegalBlockSizeException in EncryptURLParams for Request: "+ e);
			throw new CryptoException("IllegalBlockSizeException in EncryptURLParams for Request: ",e);
		} catch (UnsupportedEncodingException e) {
				logger.error("UnsupportedEncodingException in EncryptURLParams for Request: "+ e);
			throw new CryptoException("UnsupportedEncodingException in EncryptURLParams for Request: ",	e);
		}
		return returnValue;
	}

	public static String decrypt(String encryptedText, String carrierCode) throws CryptoException {
		String returnValue;
		Cipher dcipher;
		EncryptURLParams encryptURLParams = new EncryptURLParams();
		encryptURLParams.initializeCarrierCodes();

		try {
			// Decode base64 to get bytes
			byte[] dec = Base64.decodeBase64(encryptedText.getBytes());

			// Decrypt
			dcipher = CipherMaps.dcipherMap.get(carrierCode);
			if (dcipher == null){
				synchronized (EncryptURLParams.class) {
					init(carrierCode);
				}
				
			}
			byte[] utf8 = dcipher.doFinal(dec);

			// Decode using utf-8
			returnValue =  new String(utf8, I18NConstants.UTF8);

		} catch (BadPaddingException e) {
				logger.error("BadPaddingException in EncryptURLParams for Request: "+ e);
			throw new CryptoException("BadPaddingException in EncryptURLParams for Request: ", e);
		} catch (IllegalBlockSizeException e) {
				logger.error("IllegalBlockSizeException in EncryptURLParams for Request: "+ e);
			throw new CryptoException("IllegalBlockSizeException in EncryptURLParams for Request: ",e);
		} catch (UnsupportedEncodingException e) {
				logger.error("UnsupportedEncodingException in EncryptURLParams for Request: "+ e);
			throw new CryptoException("UnsupportedEncodingException in EncryptURLParams for Request: ",	e);
		}
		
		return returnValue;
	}
	
	private static void init(String carrierCode) {
		byte[] salt = { (byte) 0xC9, (byte) 0x5B, (byte) 0xC8, (byte) 0x32,
				(byte) 0x25, (byte) 0x34, (byte) 0xD3, (byte) 0x53 };
		int iterationCount = 19;
		Cipher ecipher;
		Cipher dcipher;
		String cipher_algorithm = CipherLoader.getProperty(OAComConstants.OLCI_CIPHER_ALGORIHM);

		String sharedSecretPhrase = getOperatingCarrierPassKey(carrierCode);
		KeySpec keySpec = new PBEKeySpec(sharedSecretPhrase.toCharArray(),
				salt, iterationCount);
		try {
			SecretKey key = javax.crypto.SecretKeyFactory.getInstance(
					cipher_algorithm).generateSecret(keySpec);
			ecipher = Cipher.getInstance(cipher_algorithm);
			dcipher = Cipher.getInstance(cipher_algorithm);

			// Prepare the parameters to the ecipher
			AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);

			ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
			dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
			
			CipherMaps.ecipherMap.put(carrierCode, ecipher);
			CipherMaps.dcipherMap.put(carrierCode, dcipher);

		} catch (InvalidKeySpecException e) {
				logger.error("InvalidKeySpecException in EncryptURLParams for Request: "+ e);
		} catch (NoSuchAlgorithmException e) {
				logger.error("NoSuchAlgorithmException in EncryptURLParams for Request: "+ e);
		} catch (NoSuchPaddingException e) {
				logger.error("NoSuchPaddingException in EncryptURLParams for Request: "	+ e);
		} catch (InvalidKeyException e) {
				logger.error("InvalidKeyException in EncryptURLParams for Request: "+ e);
		} catch (InvalidAlgorithmParameterException e) {
				logger.error("InvalidAlgorithmParameterException in EncryptURLParams for Request: "+ e);
		}
	}

}
