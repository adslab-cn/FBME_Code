package com.encryption.BME.FBME;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

@Getter
@Setter

public class mFrank implements Serializable, CipherParameters {
    public final byte[] m;
    public Sigma sigma;

    public mFrank(byte[] m, Sigma sigma) {
        this.m = m;
        this.sigma = sigma;
    }
}
