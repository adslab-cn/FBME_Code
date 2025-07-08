package com.encryption.BME.PAEKS;

import it.unisa.dia.gas.jpbc.Element;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

@Getter
@Setter

public class PAEKSCT implements Serializable, CipherParameters {
    public transient Element A;
    public final byte[] AByte;
    public transient Element B;
    public final byte[] BByte;

    public PAEKSCT(Element A, Element B) {
        this.A = A;
        this.AByte = A.toBytes();
        this.B = B;
        this.BByte = B.toBytes();
    }
}
