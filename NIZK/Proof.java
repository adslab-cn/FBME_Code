package com.encryption.BME.NIZK;
import it.unisa.dia.gas.jpbc.Element;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

@Getter
@Setter

public class Proof implements Serializable, CipherParameters {
    public transient Element a;
    public final byte[] aByte;
    public transient Element a_1;
    public final byte[] a1Byte;
    public transient Element a_2;
    public final byte[] a2Byte;
    public transient Element a_3;
    public final byte[] a3Byte;
    public transient Element z_1;
    public final byte[] z1Byte;
    public transient Element z_2;
    public final byte[] z2Byte;
    public transient Element z;
    public final byte[] zByte;


    public Proof(Element a, Element a_1, Element a_2, Element a_3, Element z_1, Element z_2, Element z) {
        this.a = a;
        this.aByte = a.toBytes();
        this.a_1 = a_1;
        this.a1Byte = a_1.toBytes();
        this.a_2 = a_2;
        this.a2Byte = a_2.toBytes();
        this.a_3 = a_3;
        this.a3Byte = a_3.toBytes();
        this.z_1 = z_1;
        this.z1Byte = z_1.toBytes();
        this.z_2 = z_2;
        this.z2Byte = z_2.toBytes();
        this.z = z;
        this.zByte = z.toBytes();
    }
}
