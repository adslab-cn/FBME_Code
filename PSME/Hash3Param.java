package com.encryption.BME.PSME;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class Hash3Param implements Serializable, CipherParameters {
    public transient Element d_1;
    public final byte[] d1Byte;
    public transient Element d_2;
    public final byte[] d2Byte;
    public transient Element C_0;
    public final byte[] C0Byte;
    public transient Element C_1;
    public final byte[] C1Byte;
    public transient Element C_2;
    public final byte[] C2Byte;

    public Hash3Param(Element d_1, Element d_2, Element c_0, Element c_1, Element c_2) {
        this.d_1 = d_1;
        this.d1Byte = d_1.toBytes();
        this.d_2 = d_2;
        this.d2Byte = d_2.toBytes();
        C_0 = c_0;
        this.C0Byte = c_0.toBytes();
        C_1 = c_1;
        this.C1Byte = c_1.toBytes();
        C_2 = c_2;
        this.C2Byte = c_2.toBytes();
    }
}
