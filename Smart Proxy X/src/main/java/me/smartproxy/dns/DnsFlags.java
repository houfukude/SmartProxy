package me.smartproxy.dns;

/**
 * DNS标志位, 占头部两个字节
 */
public class DnsFlags {
    public boolean QR;//1 bits, 1为响应，0为查询
    public int OpCode;//4 bits, 定义查询或响应的类型（若为0则表示是标准的，若为1则是反向的，若为2则是服务器状态请求）
    public boolean AA;//1 bits, 授权回答的标志位。该位在响应报文中有效，1表示名字服务器是权限服务器（关于权限服务器以后再讨论）
    public boolean TC;//1 bits, 截断标志位。1表示响应已超过512字节并已被截断（依稀好像记得哪里提过这个截断和UDP有关，先记着）
    public boolean RD;//1 bits, 该位为1表示客户端希望得到递归回答（递归以后再讨论）
    public boolean RA;//1 bits, 只能在响应报文中置为1，表示可以得到递归响应。
    public int Zero;//3 bits, 保留字段,全部为0


    public int Rcode;//4 bits, 返回码，表示响应的差错状态，通常为0和3，各取值含义如下
//    0          无差错
//    1          格式差错
//    2          问题在域名服务器上
//    3          域参照问题
//    4          查询类型不支持
//    5          在管理上被禁止
//    6          -- 15 保留


    public static DnsFlags Parse(short value) {
        int m_Flags = value & 0xFFFF;
        DnsFlags flags = new DnsFlags();
        flags.QR = ((m_Flags >> 7) & 0x01) == 1;
        flags.OpCode = (m_Flags >> 3) & 0x0F;
        flags.AA = ((m_Flags >> 2) & 0x01) == 1;
        flags.TC = ((m_Flags >> 1) & 0x01) == 1;
        flags.RD = (m_Flags & 0x01) == 1;
        flags.RA = (m_Flags >> 15) == 1;
        flags.Zero = (m_Flags >> 12) & 0x07;
        flags.Rcode = ((m_Flags >> 8) & 0xF);
        return flags;
    }

    public short ToShort() {
        int m_Flags = 0;
        m_Flags |= (this.QR ? 1 : 0) << 7;
        m_Flags |= (this.OpCode & 0x0F) << 3;
        m_Flags |= (this.AA ? 1 : 0) << 2;
        m_Flags |= (this.TC ? 1 : 0) << 1;
        m_Flags |= this.RD ? 1 : 0;
        m_Flags |= (this.RA ? 1 : 0) << 15;
        m_Flags |= (this.Zero & 0x07) << 12;
        m_Flags |= (this.Rcode & 0x0F) << 8;
        return (short) m_Flags;
    }
}
