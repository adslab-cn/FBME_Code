package com.encryption.BME.RBME;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class RBMERK implements Serializable, CipherParameters {
    public transient Element dk_1;
    public byte[] dk1Byte;
    public transient Element dk_2;
    public byte[] dk2Byte;

    public RBMERK(Element dk_1, Element dk_2) {
        this.dk_1 = dk_1;
        this.dk1Byte = dk_1.toBytes();
        this.dk_2 = dk_2;
        this.dk2Byte = dk_2.toBytes();
    }
}
