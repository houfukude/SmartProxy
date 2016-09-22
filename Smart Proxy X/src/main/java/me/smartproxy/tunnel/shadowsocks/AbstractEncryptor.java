package me.smartproxy.tunnel.shadowsocks;

import me.smartproxy.tunnel.IEncryptor;

/**
 * Created by hy on 9/22/16.
 */
public abstract class AbstractEncryptor implements IEncryptor {

    /**
     * 初始化加密工具
     * @param method
     * @param password
     */
    abstract public void initEncryptor(EncryptMethod method, String password);

    /**
     * 获取初始向量
     * @return
     */
    abstract public byte[] getIV();
}
