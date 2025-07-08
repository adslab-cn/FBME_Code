package com.encryption.BME.PAEKS;

import it.unisa.dia.gas.jpbc.Element;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

@Getter
@Setter
public class PAEKSKeyPair implements Serializable, CipherParameters {
    public transient Element pk;
    public final byte[] pkByte;
    public transient Element sk;
    public final byte[] skByte;

    public PAEKSKeyPair(Element pk, Element sk) {
        this.pk = pk;
        this.pkByte = pk.toBytes();
        this.sk = sk;
        this.skByte = sk.toBytes();
    }
}
