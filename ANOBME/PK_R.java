package com.encryption.BME.ANOBME;

import it.unisa.dia.gas.jpbc.Element;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

@Getter
@Setter
public class PK_R implements Serializable, CipherParameters {
    public transient Element D_1;
    public byte[] D1Byte;
    public transient Element D_2;
    public byte[] D2Byte;
    public transient Element D_3;
    public byte[] D3Byte;

    public PK_R(Element d_1, Element d_2, Element d_3) {
        D_1 = d_1;
        this.D1Byte = D_1.toBytes();
        D_2 = d_2;
        this.D2Byte = D_2.toBytes();
        D_3 = d_3;
        this.D3Byte = D_3.toBytes();
    }
}
