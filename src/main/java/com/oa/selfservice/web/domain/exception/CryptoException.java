package com.oa.selfservice.web.domain.exception;

public class CryptoException extends Exception {
	private static final long serialVersionUID = 1L;

	public CryptoException(String string, Exception e) {
		super(string, e);
	}
}
