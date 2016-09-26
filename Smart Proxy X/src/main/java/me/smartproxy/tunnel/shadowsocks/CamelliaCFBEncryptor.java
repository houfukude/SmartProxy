package me.smartproxy.tunnel.shadowsocks;

import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;

/**
 * Created by hy on 9/26/16.
 */
public class CamelliaCFBEncryptor extends BaseBouncyEncryptor {

    @Override
    protected StreamBlockCipher createBlockCipher(){
        return new CFBBlockCipher(new CamelliaEngine(), method.ivLength * 8);
    }
}
