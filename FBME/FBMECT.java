package com.encryption.BME.FBME;

import com.encryption.BME.ANOBME.ANOBMECT;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class FBMECT implements Serializable, CipherParameters {
    public ANOBMECT C;
    public Sigma sigma;

    public FBMECT(ANOBMECT C, Sigma sigma) {
        this.C = C;
        this.sigma = sigma;
    }
}
