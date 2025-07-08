package com.encryption.BME.PSME;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;
import java.util.ArrayList;

public class Hash4Param implements Serializable, CipherParameters {
    public transient it.unisa.dia.gas.jpbc.Element C_0;
    public final byte[] C0Byte;
    public transient it.unisa.dia.gas.jpbc.Element C_1;
    public final byte[] C1Byte;
    public transient it.unisa.dia.gas.jpbc.Element C_2;
    public final byte[] C2Byte;
    public transient byte[] C_3;

    public transient ArrayList<it.unisa.dia.gas.jpbc.Element> as;
    public final byte[][] asByte;
    public transient ArrayList<Element> bs;
    public final byte[][] bsByte;

    public Hash4Param(Element C_0, Element C_1, Element C_2, byte[] C_3, ArrayList<Element> as, ArrayList<Element> bs) {
        this.C_0 = C_0;
        this.C0Byte = C_0.toBytes();
        this.C_1 = C_1;
        this.C1Byte = C_1.toBytes();
        this.C_2 = C_2;
        this.C2Byte = C_2.toBytes();
        this.C_3 = C_3;
        this.as = as;
        this.asByte = PairingUtils.convertArrayListToByteArray(as);
        this.bs = bs;
        this.bsByte = PairingUtils.convertArrayListToByteArray(bs);
    }
}
