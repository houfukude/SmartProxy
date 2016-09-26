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
public class AesCFBEncryptor extends ShadowsocksEncryptor {

    SecretKey secretKey;
    StreamBlockCipher encryptCipher;
    StreamBlockCipher decryptCipher;

    @Override
    protected void doInitEncryptor() {
        secretKey = new SecretKeySpec(shadowsocksKey.getEncoded(), "AES");

        encryptCipher = new CFBBlockCipher(new AESFastEngine(), method.ivLength * 8);

        ParametersWithIV parameterIV = new ParametersWithIV(new KeyParameter(secretKey.getEncoded()), getEncryptIV());
        encryptCipher.init(true, parameterIV);
    }

    @Override
    protected void doInitDecryptor() {
        decryptCipher = new CFBBlockCipher(new AESFastEngine(), method.ivLength * 8);

        ParametersWithIV parameterIV = new ParametersWithIV(new KeyParameter(secretKey.getEncoded()), decryptIV);
        decryptCipher.init(false, parameterIV);
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


    public static void main(String[] args) throws Exception{
        AesCFBEncryptor aesCFBEncryptor = new AesCFBEncryptor();

        String str = "Hello World";
        String pass = "helloworld";


        ByteBuffer buffer = ByteBuffer.allocate(1024);
        buffer.put(str.getBytes());
        buffer.flip();


        aesCFBEncryptor.initEncryptor(EncryptMethod.AES_128_CFB, pass);

        buffer.put(str.getBytes());
        buffer.flip();

        aesCFBEncryptor.encrypt(buffer);

        //如果iv不为空,则将iv放在前面
        byte[] iv = aesCFBEncryptor.getEncryptIV();
        if (iv != null && iv.length > 0){
            byte[] data = new byte[buffer.remaining()];
            buffer.get(data);

            //将iv放在头部
            buffer.clear();
            buffer.put(iv);
            buffer.put(data);
            buffer.flip();
        }


        byte[] decryptIV = new byte[aesCFBEncryptor.getIVLength()];
        buffer.get(decryptIV);
        aesCFBEncryptor.initDecryptor(decryptIV);


        aesCFBEncryptor.decrypt(buffer);
        byte[] decrypted = new byte[buffer.remaining()];

        buffer.get(decrypted);

        String decStr = new String(decrypted);

        System.out.println(decStr);
    }

}
