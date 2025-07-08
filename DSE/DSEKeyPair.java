package com.encryption.BME.DSE;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class DSEKeyPair implements Serializable, CipherParameters {
    public DSEPK pk;
    public transient Element sk;
    public final byte[] skByte;

    public DSEKeyPair(DSEPK pk, Element sk) {
        this.pk = pk;
        this.sk = sk;
        this.skByte = sk.toBytes();
    }
}
