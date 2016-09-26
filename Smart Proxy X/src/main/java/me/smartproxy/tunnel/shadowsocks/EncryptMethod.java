package me.smartproxy.tunnel.shadowsocks;

/**
 * Created by hy on 9/22/16.
 */
public enum EncryptMethod {

    TABLE("table", 0 , 0, TableEncryptor.class),
    AES_128_CFB("aes-128-cfb", 16, 16, AesCFBEncryptor.class),
    AES_192_CFB("aes-192-cfb", 24, 16, AesCFBEncryptor.class),
    AES_256_CFB("aes-256-cfb", 32, 16, AesCFBEncryptor.class);

    public String name;
    public int keyLength;
    public int ivLength;

    Class<? extends ShadowsocksEncryptor> encryptorClass;

    EncryptMethod(String name, int keyLength, int ivLength, Class<? extends ShadowsocksEncryptor> encryptorClass){
        this.name = name;
        this.keyLength = keyLength;
        this.ivLength = ivLength;
        this.encryptorClass = encryptorClass;
    }

    /**
     * 根据字符串获取加密算法
     * @param method
     * @return
     */
    public static EncryptMethod parseMethod(String method){
        for (EncryptMethod em : EncryptMethod.values()){
            if (em.name.equalsIgnoreCase(method)){
                return em;
            }
        }
        return null;
    }

    /**
     * 构建加密器
     * @param password
     * @return
     */
    public ShadowsocksEncryptor createEncryptor(String password){
        ShadowsocksEncryptor encryptor = null;
        try {
            encryptor = encryptorClass.newInstance();
            encryptor.initEncryptor(this, password);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptor;
    }
}
