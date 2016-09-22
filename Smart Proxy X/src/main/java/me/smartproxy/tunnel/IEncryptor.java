package me.smartproxy.tunnel;

import java.nio.ByteBuffer;

public interface IEncryptor {

	void encrypt(ByteBuffer buffer) throws Exception;
	void decrypt(ByteBuffer buffer) throws Exception;
	
}
