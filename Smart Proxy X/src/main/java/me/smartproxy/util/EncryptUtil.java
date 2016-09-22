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
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.nextBytes(iv);
        } catch (NoSuchAlgorithmException e) {
            Random rnd = new Random();
            rnd.nextBytes(iv);
        }
    }
}
