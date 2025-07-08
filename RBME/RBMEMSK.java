package com.encryption.BME.RBME;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class RBMEMSK implements Serializable, CipherParameters {
    public transient Element r;
    public byte[] rByte;
    public transient Element s;
    public byte[] sByte;

    public RBMEMSK(Element r, Element s) {
        this.r = r;
        this.rByte = r.toBytes();
        this.s = s;
        this.sByte = s.toBytes();
    }
}
