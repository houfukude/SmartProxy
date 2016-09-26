package me.smartproxy.tunnel.shadowsocks;

import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;

/**
 * Created by hy on 9/26/16.
 */

public class DesCFBEncryptor extends BaseBouncyEncryptor {

    @Override
    protected StreamBlockCipher createBlockCipher(){
        return new CFBBlockCipher(new DESEngine(), method.ivLength * 8);
    }
}
