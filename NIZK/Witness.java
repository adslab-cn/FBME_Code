package com.encryption.BME.NIZK;

import it.unisa.dia.gas.jpbc.Element;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

@Getter
@Setter
public class Witness  implements Serializable, CipherParameters {
    public transient Element[] sk_s;
    public transient Element r;

    public Witness(Element[] sk_s, Element r) {
        this.sk_s = sk_s;
        this.r = r;
    }
}
