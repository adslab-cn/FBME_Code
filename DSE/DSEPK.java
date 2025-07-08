package com.encryption.BME.DSE;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class DSEPK implements Serializable, CipherParameters {
    public transient Element pk_1;
    public final byte[] pk1Byte;
    public transient Element pk_2;
    public final byte[] pk2Byte;
    public transient Element pk_3;
    public final byte[] pk3Byte;

    public DSEPK(Element pk_1, Element pk_2, Element pk_3) {
        this.pk_1 = pk_1;
        this.pk1Byte = pk_1.toBytes();
        this.pk_2 = pk_2;
        this.pk2Byte = pk_2.toBytes();
        this.pk_3 = pk_3;
        this.pk3Byte = pk_3.toBytes();
    }
}
