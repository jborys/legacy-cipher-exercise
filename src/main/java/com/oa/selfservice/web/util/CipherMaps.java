package com.oa.selfservice.web.util;

import javax.crypto.Cipher;
import java.util.HashMap;
import java.util.Map;

public class CipherMaps {
    public static Map<String, Cipher> ecipherMap;
    public static Map<String, Cipher> dcipherMap;

    public static void createCipherMaps() {
        ecipherMap = new HashMap<>();
        dcipherMap = new HashMap<>();
    }
}
