package com.oa.selfservice.web.domain.encrypt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.oa.selfservice.web.domain.exception.CryptoException;
import com.oa.selfservice.web.ui.I18NConstants;
import com.oa.selfservice.web.util.OAComConstants;
import com.oa.selfservice.web.util.ResourceUtil;

/**
 * 
 * This class is used for encrypting and decrypting
 * strings using PBEWithMD5AndDES Cipher algorithm. The class is created
 * with a key and can be used repeatedly to encrypt and decrypt strings using
 * that key.
 * 
 */

public class EncryptURLParams {

	private static Map<String, Cipher> ecipherMap;
	private static Map<String, Cipher> dcipherMap;

	public static Log logger = LogFactory.getLog(EncryptURLParams.class);
	
	/*
	 * Read the carriers eligible for deep link in/out from the properties file.
	 * Store the ecipher and dcipher for each carrier in a Map.
	 * Since the ecipher and dcipher remains the same for a given carrier
	 * it is computed once when the class is loaded. 
	 */
	static {
		String olciCarriersStr =  ResourceUtil.getProperty("olci.operating.carrier");
		String[] olciCarriersArr = StringUtils.split(olciCarriersStr, ",");
		ecipherMap = new HashMap<String, Cipher>();
		dcipherMap = new HashMap<String, Cipher>();
		for (String carrierCode : olciCarriersArr) {
			init(carrierCode);
		}
	}

	/**
	 * getOperatingCarrierPassKey method returns passkey for JBA or PJB Carrier
	 * slice eligible for check in.
	 *
	 * @param string   carrierCode
	 * @return string
	 */

	private static String getOperatingCarrierPassKey(String carrierCode) {
		String carrierPasskey = ResourceUtil.getProperty(StringUtils.replace(
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


	/**
	 * Takes a single String as an argument and returns an Encrypted version of
	 * that String.
	 *
	 * @param str2bEncrypted String to be encrypted
	 * @param carrierCode airline carrier code
	 * @return <code>String</code> Encrypted version of the provided String
	 * @throws CryptoException
	 */
	public static String encrypt(String plainText, String carrierCode) throws CryptoException {
		String retval = null;
		Cipher ecipher = null;

		try {
			// Encode the string into bytes using utf-8
			byte[] utf8 = plainText.getBytes(I18NConstants.UTF8);

			// Encrypt
			ecipher = ecipherMap.get(carrierCode);
			if (ecipher == null){
				synchronized (EncryptURLParams.class) {
					init(carrierCode);
				}
			}
			byte[] enc = ecipher.doFinal(utf8);

			// Encode bytes to base64 to get a string
			retval = new String(Base64.encodeBase64(enc));

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
		return retval;
	}


	/**
	 * Takes a encrypted String as an argument, decrypts and returns the
	 * decrypted String.
	 *
	 * @param str2bDecrypted Encrypted String to be decrypted
	 * @param carrierCode airline carrier code
	 * @return <code>String</code> Decrypted version of the provided String
	 * @throws CryptoException
	 */
	public static String decrypt(String encryptedText, String carrierCode) throws CryptoException {
		String retval = null;
		Cipher dcipher = null;

		try {
			// Decode base64 to get bytes
			byte[] dec = Base64.decodeBase64(encryptedText.getBytes());

			// Decrypt
			dcipher = dcipherMap.get(carrierCode);
			if (dcipher == null){
				synchronized (EncryptURLParams.class) {
					init(carrierCode);
				}
				
			}
			byte[] utf8 = dcipher.doFinal(dec);

			// Decode using utf-8
			retval =  new String(utf8, I18NConstants.UTF8);

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
		
		return retval;
	}
	
	/**
	 * 
	 * @param carrierCode
	 */
	private static void init(String carrierCode) {
		byte[] salt = { (byte) 0xC9, (byte) 0x5B, (byte) 0xC8, (byte) 0x32,
				(byte) 0x25, (byte) 0x34, (byte) 0xD3, (byte) 0x53 };
		int iterationCount = 19;
		Cipher ecipher = null;
		Cipher dcipher = null;
		String cipher_algorithm = ResourceUtil.getProperty(OAComConstants.OLCI_CIPHER_ALGORIHM);

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
			
			ecipherMap.put(carrierCode, ecipher);
			dcipherMap.put(carrierCode, dcipher);

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
