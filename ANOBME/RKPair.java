package com.encryption.BME.ANOBME;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

@Getter
@Setter

public class RKPair implements Serializable, CipherParameters {
    public PK_R pk_r;
    public SK_R sk_r;

    public RKPair(PK_R pk_r, SK_R sk_r) {
        this.pk_r = pk_r;
        this.sk_r = sk_r;
    }
}
