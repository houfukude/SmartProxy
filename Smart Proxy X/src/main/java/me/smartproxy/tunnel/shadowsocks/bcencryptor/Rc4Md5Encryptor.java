package me.smartproxy.tunnel.shadowsocks.bcencryptor;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;

import me.smartproxy.util.EncryptUtil;

/**
 * Created by hy on 9/26/16.
 */

public class Rc4Md5Encryptor extends BaseBouncyEncryptor {


    /**
     * RC4-MD5中, md5就体现在对Key的处理, 是把iv加在key后面,再计算一次md5<br/>
     * 跟RC4相比, 就多了个处理Key的步骤
     * @param iv
     * @return
     */
    @Override
    protected CipherParameters createCipherParameters(byte[] iv) {

        if (secretKey == null){
            secretKey = getSecretKey();
        }

        byte[] temp = new byte[secretKey.getEncoded().length + iv.length];
        System.arraycopy(secretKey.getEncoded(), 0, temp, 0 , secretKey.getEncoded().length);
        System.arraycopy(iv, 0, temp, secretKey.getEncoded().length, iv.length);

        byte[] hash = EncryptUtil.md5(temp);

        return new KeyParameter(hash);
    }


    @Override
    protected StreamCipher createCipher(){
        return new RC4Engine();
    }
}

