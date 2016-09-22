package me.smartproxy.tunnel.shadowsocks;

import java.nio.ByteBuffer;

import me.smartproxy.util.EncryptUtil;

/**
 * Created by hy on 9/22/16.
 */

public class AesCFBEncryptor extends AbstractEncryptor {

    EncryptMethod encryptMethod;
    String password;
    byte[] iv;

    @Override
    public void initEncryptor(EncryptMethod method, String password) {
        this.encryptMethod = method;
        this.password = password;

        //初始化加密的盐
        iv = new byte[method.ivLength];
        EncryptUtil.getSalt(iv);


    }

    @Override
    public byte[] getIV() {
        return new byte[0];
    }

    @Override
    public void encrypt(ByteBuffer buffer) throws Exception {

    }

    @Override
    public void decrypt(ByteBuffer buffer) throws Exception {

    }
}
