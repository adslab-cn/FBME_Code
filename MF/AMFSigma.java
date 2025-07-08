package com.encryption.BME.MF;

import com.encryption.BME.SPoK.Proof;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class AMFSigma implements Serializable, CipherParameters {
    public Proof pi;
    public transient Element J;
    public final byte[] JByte;
    public transient Element R;
    public final byte[] RByte;
    public transient Element E_J;
    public final byte[] EJByte;
    public transient Element E_R;
    public final byte[] ERByte;

    public AMFSigma(Proof pi, Element J, Element R, Element E_J, Element E_R) {
        this.pi = pi;
        this.J = J;
        this.JByte = J.toBytes();
        this.R = R;
        this.RByte = R.toBytes();
        this.E_J = E_J;
        this.EJByte = E_J.toBytes();
        this.E_R = E_R;
        this.ERByte = E_R.toBytes();
    }
}
