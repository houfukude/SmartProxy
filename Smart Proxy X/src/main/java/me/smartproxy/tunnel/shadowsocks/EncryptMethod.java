package me.smartproxy.tunnel.shadowsocks;

/**
 * Created by hy on 9/22/16.
 */
public enum EncryptMethod {

    TABLE("table", 0 , 0, TableEncryptor.class),
    AES_128_CFB("aes-128-cfb", 16, 16, AesCFBEncryptor.class),
    AES_192_CFB("aes-192-cfb", 24, 16, AesCFBEncryptor.class),
    AES_256_CFB("aes-256-cfb", 32, 16, AesCFBEncryptor.class),
    AES_128_CTR("aes-128-ctr", 16, 16, AesCTREncryptor.class),
    AES_192_CTR("aes-192-ctr", 24, 16, AesCTREncryptor.class),
    AES_256_CTR("aes-256-ctr", 32, 16, AesCTREncryptor.class),
    CAMELLIA_128_CFB("camellia-128-cfb", 16, 16, CamelliaCFBEncryptor.class),
    CAMELLIA_192_CFB("camellia-192-cfb", 24, 16, CamelliaCFBEncryptor.class),
    CAMELLIA_256_CFB("camellia-256-cfb", 32, 16, CamelliaCFBEncryptor.class),
    DES_CFB("des-cfb", 8, 8, DesCFBEncryptor.class),
    IDEA_CFB("idea-cfb", 16, 8, IdeaCFBEncryptor.class),
    RC4_MD5("rc4-md5", 16, 16, CamelliaCFBEncryptor.class);

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
