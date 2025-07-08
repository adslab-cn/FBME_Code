package com.encryption.BME.SPoK;
import it.unisa.dia.gas.jpbc.Element;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

@Getter
@Setter

public class Proof implements Serializable, CipherParameters {
    public transient Element a_1;
    public final byte[] a1Byte;
    public transient Element a_2;
    public final byte[] a2Byte;
    public transient Element a_3;
    public final byte[] a3Byte;
    public transient Element a_4;
    public final byte[] a4Byte;
    public transient Element a_5;
    public final byte[] a5Byte;
    public transient Element z_1;
    public final byte[] z1Byte;
    public transient Element z_2;
    public final byte[] z2Byte;
    public transient Element z_3;
    public final byte[] z3Byte;
    public transient Element z_4;
    public final byte[] z4Byte;


    public Proof(Element a_1, Element a_2, Element a_3, Element a_4, Element a_5, Element z_1, Element z_2, Element z_3, Element z_4) {
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
        this.z_1 = z_1;
        this.z1Byte = z_1.toBytes();
        this.z_2 = z_2;
        this.z2Byte = z_2.toBytes();
        this.z_3 = z_3;
        this.z3Byte = z_3.toBytes();
        this.z_4 = z_4;
        this.z4Byte = z_4.toBytes();
    }
}
