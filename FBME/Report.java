package com.encryption.BME.FBME;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

@Getter
@Setter

public class Report implements Serializable, CipherParameters {
    public final byte[] H_m;
    public Sigma sigma;

    public Report(byte[] H_m, Sigma sigma) {
        this.H_m = H_m;
        this.sigma = sigma;
    }
}
