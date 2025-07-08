package com.encryption.BME.ANOBME;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;
import java.util.ArrayList;

public class CTParam implements Serializable, CipherParameters {
    public transient Element u_1;
    public final byte[] u1Byte;
    public transient Element u_2;
    public final byte[] u2Byte;
    public ArrayList<byte[]> As;


    public CTParam(Element u_1, Element u_2, ArrayList<byte[]> As) {
        this.u_1 = u_1;
        this.u1Byte = u_1.toBytes();
        this.u_2 = u_2;
        this.u2Byte = u_2.toBytes();
        this.As = As;
    }
}
