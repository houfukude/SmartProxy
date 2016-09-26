package me.smartproxy.tunnel.shadowsocks.bcencryptor;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;

/**
 * Created by hy on 9/26/16.
 */
public class AesCTREncryptor extends BaseBouncyEncryptor {

    @Override
    protected StreamCipher createCipher(){
        return new SICBlockCipher(new AESFastEngine());
    }

}