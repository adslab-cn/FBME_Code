package com.encryption.BME.ANOBME;

import it.unisa.dia.gas.jpbc.Element;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;


@Getter
@Setter

public class SK_R implements Serializable, CipherParameters {
    public transient Element x_1;
    public final byte[] x1Byte;
    public transient Element x_2;
    public final byte[] x2Byte;
    public transient Element y_1;
    public final byte[] y1Byte;
    public transient Element y_2;
    public final byte[] y2Byte;
    public transient Element o;
    public final byte[] oByte;

    public SK_R(Element x_1, Element x_2, Element y_1, Element y_2, Element o) {
        this.x_1 = x_1;
        this.x1Byte = x_1.toBytes();
        this.x_2 = x_2;
        this.x2Byte = x_2.toBytes();
        this.y_1 = y_1;
        this.y1Byte = y_1.toBytes();
        this.y_2 = y_2;
        this.y2Byte = y_2.toBytes();
        this.o = o;
        this.oByte = o.toBytes();
    }
}
