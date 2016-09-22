package me.smartproxy.tunnel.shadowsocks;

/**
 * Created by hy on 9/22/16.
 */
public enum EncryptMethod {

    TABLE("table", 0 , 0, TableEncryptor.class);

    String name;
    int keyLength;
    int ivLength;
    Class<? extends AbstractEncryptor> encryptorClass;

    EncryptMethod(String name, int keyLength, int ivLength, Class<? extends AbstractEncryptor> encryptorClass){
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
    public AbstractEncryptor createEncryptor(String password){
        AbstractEncryptor encryptor = null;
        try {
            encryptor = encryptorClass.newInstance();
            encryptor.initEncryptor(this, password);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
