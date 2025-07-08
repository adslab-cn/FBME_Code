package com.encryption.BME.SPoK;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;
import java.util.ArrayList;

public class Proof_S implements Serializable, CipherParameters {
    public transient Element a_1;
    public final byte[] a1Byte;
    public transient Element a_2;
    public final byte[] a2Byte;
    public transient Element a_3;
    public final byte[] a3Byte;
    public transient Element a_4;
    public final byte[] a4Byte;
    public transient ArrayList<Element> a5s;
    public final byte[][] a5sByte;
    public transient Element z_1;
    public final byte[] z1Byte;
    public transient Element z_2;
    public final byte[] z2Byte;
    public transient Element z_3;
    public final byte[] z3Byte;
    public transient ArrayList<Element> z4s;
    public final byte[][] z4sByte;


    public Proof_S(Element a_1, Element a_2, Element a_3, Element a_4, ArrayList<Element> a5s, Element z_1, Element z_2, Element z_3, ArrayList<Element> z4s) {
        this.a_1 = a_1;
        this.a1Byte = a_1.toBytes();
        this.a_2 = a_2;
        this.a2Byte = a_2.toBytes();
        this.a_3 = a_3;
        this.a3Byte = a_3.toBytes();
        this.a_4 = a_4;
        this.a4Byte = a_4.toBytes();
        this.a5s = a5s;
        this.a5sByte = PairingUtils.convertArrayListToByteArray(a5s);
        this.z_1 = z_1;
        this.z1Byte = z_1.toBytes();
        this.z_2 = z_2;
        this.z2Byte = z_2.toBytes();
        this.z_3 = z_3;
        this.z3Byte = z_3.toBytes();
        this.z4s = z4s;
        this.z4sByte = PairingUtils.convertArrayListToByteArray(z4s);
    }
}
