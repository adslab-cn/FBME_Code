package com.encryption.BME.DSE;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class DSECT implements Serializable, CipherParameters {
    public transient Element A;
    public final byte[] AByte;
    public final byte[] B;

    public DSECT(Element A, byte[] B) {
        this.A = A;
        this.AByte = A.toBytes();
        this.B = B;
    }
}
