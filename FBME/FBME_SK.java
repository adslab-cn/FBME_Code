package com.encryption.BME.FBME;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class FBME_SK implements Serializable, CipherParameters {
    public transient Element sk_s1;
    public final byte[] sks1Byte;
    public transient Element[] sk_s2;
    public final byte[][] sks2Byte;

    public FBME_SK(Element sk_s1, Element[] sk_s2) {
        this.sk_s1 = sk_s1;
        this.sks1Byte = sk_s1.toBytes();
        this.sk_s2 = sk_s2;
        this.sks2Byte = PairingUtils.GetElementArrayBytes(sk_s2);
    }
}
