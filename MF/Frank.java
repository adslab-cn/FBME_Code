package com.encryption.BME.MF;

import cn.edu.buaa.crypto.utils.PairingUtils;
import com.encryption.BME.ElGamal.PKECT;
import org.bouncycastle.crypto.CipherParameters;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;

public class Frank implements Serializable, CipherParameters {
    public ArrayList<PKECT> c_S;
    public byte[][] csByte;
    public AMFSigmaS sigma;
    public AMFSigma sigmaPrime;

    public Frank(ArrayList<PKECT> c_S, AMFSigmaS sigma, AMFSigma sigmaPrime) throws IOException {
        this.c_S = c_S;
        this.csByte = PairingUtils.convertArrayListToByteArrayC(c_S);
        this.sigma = sigma;
        this.sigmaPrime = sigmaPrime;
    }
}
