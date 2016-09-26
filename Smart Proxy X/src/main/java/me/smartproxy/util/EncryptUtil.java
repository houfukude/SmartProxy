package me.smartproxy.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Created by hy on 9/22/16.
 */

public class EncryptUtil {

    /**
     * 获取加密的盐
     * @param iv
     */
    public static void getSalt(byte[] iv){
        new SecureRandom().nextBytes(iv);
    }
}
