package com.encryption.BME.SPoK;

import it.unisa.dia.gas.jpbc.Element;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

@Getter
@Setter
public class Witness  implements Serializable, CipherParameters {
    public transient Element t;
    public transient Element u;
    public transient Element v;
    public transient Element w;

    public Witness(Element t, Element u, Element v, Element w) {
        this.t = t;
        this.u = u;
        this.v = v;
        this.w = w;
    }
}
