package com.encryption.BME.FBME;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;


public class FBME_SKPair implements Serializable, CipherParameters {
    public transient Element[] pk_s;
    public final byte[][] pksByte;
    public FBME_SK sk_s;

    public FBME_SKPair(Element[] pk_s, FBME_SK sk_s) {
        this.pk_s = pk_s;
        this.pksByte = PairingUtils.GetElementArrayBytes(pk_s);
        this.sk_s = sk_s;
    }
}
