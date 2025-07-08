package com.encryption.BME.Reclean;

import com.encryption.BME.ElGamal.PKECT;
import com.encryption.BME.MF.AMFSigma;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class CT implements Serializable, CipherParameters {
    public PKECT c;
    public AMFSigma sigma;
    public AMFSigma sigmaPrime;

    public CT(PKECT c, AMFSigma sigma, AMFSigma sigmaPrime) {
        this.c = c;
        this.sigma = sigma;
        this.sigmaPrime = sigmaPrime;
    }
}
