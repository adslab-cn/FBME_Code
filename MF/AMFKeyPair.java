package com.encryption.BME.MF;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class AMFKeyPair implements Serializable, CipherParameters {
    public transient Element pk;
    public final byte[] pkByte;
    public transient Element sk;
    public final byte[] skByte;

    public AMFKeyPair(Element pk, Element sk) {
        this.pk = pk;
        this.pkByte = pk.toBytes();
        this.sk = sk;
        this.skByte = sk.toBytes();
    }
}
