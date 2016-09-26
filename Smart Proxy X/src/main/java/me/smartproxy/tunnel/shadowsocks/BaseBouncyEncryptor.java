package me.smartproxy.tunnel.shadowsocks;

import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.ByteBuffer;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by hy on 9/22/16.
 */
public class BaseBouncyEncryptor extends ShadowsocksEncryptor {

    SecretKey secretKey;
    StreamBlockCipher encryptCipher;
    StreamBlockCipher decryptCipher;

    @Override
    protected void doInitEncryptor() {
        if (secretKey == null){
            secretKey = getSecretKey();
        }

        encryptCipher = createBlockCipher();

        ParametersWithIV parameterIV = new ParametersWithIV(new KeyParameter(secretKey.getEncoded()), getEncryptIV());
        encryptCipher.init(true, parameterIV);
    }

    @Override
    protected void doInitDecryptor() {
        if (secretKey == null){
            secretKey = getSecretKey();
        }

        decryptCipher = createBlockCipher();

        ParametersWithIV parameterIV = new ParametersWithIV(new KeyParameter(secretKey.getEncoded()), decryptIV);
        decryptCipher.init(false, parameterIV);
    }


    protected SecretKey getSecretKey(){
        return new SecretKeySpec(shadowsocksKey.getEncoded(), "AES");
    }


    /**
     * 创建加密器, 默认创建了AES-CFB加密器
     * @return
     */
    protected StreamBlockCipher createBlockCipher(){
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
