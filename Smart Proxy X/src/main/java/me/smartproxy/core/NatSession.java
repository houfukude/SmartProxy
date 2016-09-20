package me.smartproxy.core;


/**
 * NAT会话，记录远程IP/端口，远程主机名，以及发送的数据量和上次交互的时间
 */
public class NatSession{
	public int RemoteIP;
	public short RemotePort;
	public String RemoteHost;
	public int BytesSent;
	public int PacketSent;
	public long LastNanoTime;
}
