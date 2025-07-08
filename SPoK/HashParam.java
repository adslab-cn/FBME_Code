package com.encryption.BME.SPoK;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class HashParam implements Serializable, CipherParameters {
    public transient Element pk_s;
    public byte[] pksByte;
    public transient Element pk_j;
    public byte[] pkjByte;
    public transient Element J;
    public byte[] JByte;
    public transient Element R;
    public byte[] RByte;
    public transient Element E_j;
    public byte[] EjByte;
    public transient Element a_1;
    public byte[] a1Byte;
    public transient Element a_2;
    public byte[] a2Byte;
    public transient Element a_3;
    public byte[] a3Byte;
    public transient Element a_4;
    public byte[] a4Byte;
    public transient Element a_5;
    public byte[] a5Byte;

    public HashParam(Element pk_s, Element pk_j, Element J, Element R, Element E_j, Element a_1, Element a_2, Element a_3, Element a_4, Element a_5) {
        this.pk_s = pk_s;
        this.pksByte = pk_s.toBytes();
        this.pk_j = pk_j;
        this.pkjByte = pk_j.toBytes();
        this.J = J;
        this.JByte = J.toBytes();
        this.R = R;
        this.RByte = R.toBytes();
        this.E_j = E_j;
        this.EjByte = E_j.toBytes();
        this.a_1 = a_1;
        this.a1Byte = a_1.toBytes();
        this.a_2 = a_2;
        this.a2Byte = a_2.toBytes();
        this.a_3 = a_3;
        this.a3Byte = a_3.toBytes();
        this.a_4 = a_4;
        this.a4Byte = a_4.toBytes();
        this.a_5 = a_5;
        this.a5Byte = a_5.toBytes();
    }
}
