package com.encryption.BME.NIZK;

import com.encryption.BME.HPSKEM.HPSCT;
import it.unisa.dia.gas.jpbc.Element;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

@Getter
@Setter

public class Statement implements Serializable, CipherParameters {
    public transient Element pk_s;
    public final byte[] pksByte;
    public transient Element pk_J;
    public final byte[] pkJByte;
    public transient HPSCT c;
    public transient Element k_J;
    public final byte[] kJByte;

    public Statement(Element pk_s, Element pk_J, HPSCT c, Element k_J) {
        this.pk_s = pk_s;
        this.pksByte = pk_s.toBytes();
        this.pk_J = pk_J;
        this.pkJByte = pk_J.toBytes();
        this.c = c;
        this.k_J = k_J;
        this.kJByte = k_J.toBytes();
    }
}
