package com.encryption.BME.PSME;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class PSMEDK implements Serializable, CipherParameters {
    public transient Element dk_1;
    public final byte[] dk1Byte;
    public transient Element dk_2;
    public final byte[] dk2Byte;
    public transient Element dk_3;
    public final byte[] dk3Byte;

    public PSMEDK(Element dk_1, Element dk_2, Element dk_3) {
        this.dk_1 = dk_1;
        this.dk1Byte = dk_1.toBytes();
        this.dk_2 = dk_2;
        this.dk2Byte = dk_2.toBytes();
        this.dk_3 = dk_3;
        this.dk3Byte = dk_3.toBytes();
    }
}
