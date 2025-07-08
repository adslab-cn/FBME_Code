package com.encryption.BME.HPSKEM;

import it.unisa.dia.gas.jpbc.Element;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;


@Getter
@Setter

public class HPSCT implements Serializable, CipherParameters {
    public transient Element v_1;
    public final byte[] v1Byte;
    public transient Element v_2;
    public final byte[] v2Byte;

    public HPSCT(Element v_1, Element v_2) {
        this.v_1 = v_1;
        this.v1Byte = v_1.toBytes();
        this.v_2 = v_2;
        this.v2Byte = v_2.toBytes();
    }

}
