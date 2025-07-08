package com.encryption.BME.SPoK;

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
    public transient Element pk_j;
    public final byte[] pkjByte;
    public transient Element J;
    public final byte[] JByte;
    public transient Element R;
    public final byte[] RByte;
    public transient Element E_J;
    public final byte[] EJByte;

    public Statement(Element pk_s, Element pk_j, Element J, Element R, Element E_J) {
        this.pk_s = pk_s;
        this.pksByte = pk_s.toBytes();
        this.pk_j = pk_j;
        this.pkjByte = pk_j.toBytes();
        this.J = J;
        this.JByte = J.toBytes();
        this.R = R;
        this.RByte = R.toBytes();
        this.E_J = E_J;
        this.EJByte = E_J.toBytes();
    }
}
