package com.encryption.BME.RBME;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;
import java.util.ArrayList;

public class RBMECT implements Serializable, CipherParameters {
    public transient Element C_0;
    public byte[] C0Byte;
    public transient Element C_2;
    public byte[] C2Byte;
    public transient Element C_3;
    public byte[] C3Byte;
    public transient ArrayList<Element> Us;
    public byte[][] UsByte;
    public transient ArrayList<Element> es;
    public byte[][] esByte;

    public RBMECT(Element C_0, Element C_2, Element C_3, ArrayList<Element> Us, ArrayList<Element> es) {
        this.C_0 = C_0;
        this.C0Byte = C_0.toBytes();
        this.C_2 = C_2;
        this.C2Byte = C_2.toBytes();
        this.C_3 = C_3;
        this.C3Byte = C_3.toBytes();
        this.Us = Us;
        this.UsByte = PairingUtils.convertArrayListToByteArray(Us);
        this.es = es;
        this.esByte = PairingUtils.convertArrayListToByteArray(es);
    }
}
