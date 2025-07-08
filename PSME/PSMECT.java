package com.encryption.BME.PSME;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;
import java.util.ArrayList;

public class PSMECT implements Serializable, CipherParameters {
    public transient Element sigma;
    public final byte[] sigmaByte;
    public transient Element C_0;
    public final byte[] C0Byte;
    public transient Element C_1;
    public final byte[] C1Byte;
    public transient Element C_2;
    public final byte[] C2Byte;
    public transient byte[] C_3;
    public transient Element C_4;
    public final byte[] C4Byte;

    public transient ArrayList<Element> as;
    public final byte[][] asByte;
    public transient ArrayList<Element> bs;
    public final byte[][] bsByte;

    public PSMECT(Element sigma, Element C_0, Element C_1, Element C_2, byte[] C_3, Element C_4, ArrayList<Element> as, ArrayList<Element> bs) {
        this.sigma = sigma;
        this.sigmaByte = sigma.toBytes();
        this.C_0 = C_0;
        this.C0Byte = C_0.toBytes();
        this.C_1 = C_1;
        this.C1Byte = C_1.toBytes();
        this.C_2 = C_2;
        this.C2Byte = C_2.toBytes();
        this.C_3 = C_3;
        this.C_4 = C_4;
        this.C4Byte = C_4.toBytes();
        this.as = as;
        this.asByte = PairingUtils.convertArrayListToByteArray(as);
        this.bs = bs;
        this.bsByte = PairingUtils.convertArrayListToByteArray(bs);
    }
}
