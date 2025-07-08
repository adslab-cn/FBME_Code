package com.encryption.BME.ElGamal;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class PKECT implements Serializable, CipherParameters {
    public transient Element C_1;
    public final byte[] C1Byte;
    public transient Element C_2;
    public final byte[] C2Byte;

    public PKECT(Element C_1, Element C_2) {
        this.C_1 = C_1;
        this.C1Byte = C_1.toBytes();
        this.C_2 = C_2;
        this.C2Byte = C_2.toBytes();
    }

}
