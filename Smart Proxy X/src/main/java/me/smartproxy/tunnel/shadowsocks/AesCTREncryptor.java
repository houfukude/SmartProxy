package me.smartproxy.tunnel.shadowsocks;

import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;

/**
 * Created by hy on 9/26/16.
 */
public class AesCTREncryptor extends BaseBouncyEncryptor {

    @Override
    protected StreamBlockCipher createBlockCipher(){
        return new SICBlockCipher(new AESFastEngine());
    }

}
