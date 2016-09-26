package me.smartproxy.tunnel.shadowsocks.bcencryptor;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import me.smartproxy.tunnel.shadowsocks.ShadowsocksEncryptor;

/**
 * Created by hy on 9/22/16.
 */
public class BaseBouncyEncryptor extends ShadowsocksEncryptor {

    SecretKey secretKey;

    StreamCipher encryptCipher;
    StreamCipher decryptCipher;

    @Override
    protected void doInitEncryptor() {
        encryptCipher = createCipher();
        encryptCipher.init(true, createCipherParameters(getEncryptIV()));
    }


    @Override
    protected void doInitDecryptor() {
        decryptCipher = createCipher();
        decryptCipher.init(false, createCipherParameters(decryptIV));
    }


    protected SecretKey getSecretKey(){
        return new SecretKeySpec(shadowsocksKey.getEncoded(), "AES");
    }

    /**
     * 创建加密的参数,包含密钥和IV
     * @param iv
     * @return
     */
    protected CipherParameters createCipherParameters(byte[] iv) {
        CipherParameters cipherParameters = null;

        if (secretKey == null){
            secretKey = getSecretKey();
        }

        if (method.ivLength > 0) {
            cipherParameters = new ParametersWithIV(new KeyParameter(secretKey.getEncoded()), iv);
        } else {
            cipherParameters = new KeyParameter(secretKey.getEncoded());
        }
        return cipherParameters;
    }


    /**
     * 创建加密器, 默认创建了AES-CFB加密器
     * @return
     */
    protected StreamCipher createCipher(){
        return new CFBBlockCipher(new AESFastEngine(), method.ivLength * 8);
    }

    @Override
    protected byte[] doEncrypt(byte[] data) {
        byte[] encrypted = new byte[data.length];

        encryptCipher.processBytes(data, 0, data.length, encrypted, 0);

        return encrypted;
    }

    @Override
    protected byte[] doDecrypt(byte[] data) {
        byte[] decrypted = new byte[data.length];

        decryptCipher.processBytes(data, 0, data.length, decrypted, 0);

        return decrypted;
    }

}
