package com.encryption.BME.ANOBME;

import it.unisa.dia.gas.jpbc.Element;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

@Getter
@Setter

public class SKPair implements Serializable, CipherParameters {
    public transient Element pk_s;
    public final byte[] pksByte;
    public transient Element sk_s;
    public final byte[] sksByte;


    public SKPair(Element pk_s, Element sk_s) {
        this.pk_s = pk_s;
        this.pksByte = pk_s.toBytes();
        this.sk_s = sk_s;
        this.sksByte = sk_s.toBytes();
    }
}
