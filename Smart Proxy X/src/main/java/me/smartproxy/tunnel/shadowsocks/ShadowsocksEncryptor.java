package me.smartproxy.tunnel.shadowsocks;

import java.nio.ByteBuffer;

import me.smartproxy.tunnel.IEncryptor;
import me.smartproxy.util.EncryptUtil;

/**
 * Created by hy on 9/22/16.
 */
public abstract class ShadowsocksEncryptor implements IEncryptor {

    protected EncryptMethod method;
    protected String password;

    protected ShadowsocksKey shadowsocksKey;

    protected byte[] encryptIV;
    protected byte[] decryptIV;

    /**
     * 初始化加密工具
     * @param method
     * @param password
     */
    public void initEncryptor(EncryptMethod method, String password){
        this.method = method;
        this.password = password;

        if (method.ivLength > 0){
            encryptIV = new byte[method.ivLength];
            EncryptUtil.getSalt(encryptIV);
        }

        shadowsocksKey = new ShadowsocksKey(password, method.keyLength);

        doInitEncryptor();

        //不需要服务器的IV,直接初始化解密
        if (method.ivLength == 0){
            doInitDecryptor();
        }
    }

    /**
     * 获取加密的初始向量
     * @return
     */
    public byte[] getEncryptIV(){
        return encryptIV;
    }

    /**
     * 获取iv的长度
     * @return
     */
    public int getIVLength(){
        return method.ivLength;
    }


    /**
     * 设置解密的iv, 初始化解密
     * @param iv
     * @return
     */
    public void initDecryptor(byte[] iv){
        this.decryptIV = new byte[iv.length];
        System.arraycopy(iv, 0, decryptIV, 0, iv.length);

        doInitDecryptor();
    }


    @Override
    public void encrypt(ByteBuffer buffer) throws Exception {
        if (buffer.remaining() == 0) return;

        byte[] data = new byte[buffer.remaining()];
        buffer.get(data);

        buffer.clear();
        buffer.put(doEncrypt(data));
        buffer.flip();
    }

    @Override
    public void decrypt(ByteBuffer buffer) throws Exception {
        if (buffer.remaining() == 0) return;

        byte[] data = new byte[buffer.remaining()];
        buffer.get(data);

        buffer.clear();
        buffer.put(doDecrypt(data));
        buffer.flip();
    }


    /**
     * 子类初始化加密
     */
    protected abstract void doInitEncryptor();


    /**
     * 子类初始化解密
     */
    protected abstract void doInitDecryptor();


    /**
     * 执行加密
     * @param data
     * @return
     */
    protected abstract byte[] doEncrypt(byte[] data);


    /**
     * 执行解密
     * @param data
     * @return
     */
    protected abstract byte[] doDecrypt(byte[] data);
}
