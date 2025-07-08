package com.encryption.BME.MF;

import cn.edu.buaa.crypto.utils.PairingUtils;
import com.encryption.BME.SPoK.Proof_S;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;
import java.util.ArrayList;

public class AMFSigmaS implements Serializable, CipherParameters {
    public Proof_S pi;
    public transient Element J;
    public final byte[] JByte;
    public transient ArrayList<Element> Rs;
    public final byte[][] RsByte;
    public transient Element E_J;
    public final byte[] EJByte;
    public transient Element E_R;
    public final byte[] ERByte;

    public AMFSigmaS(Proof_S pi, Element J, ArrayList<Element> Rs, Element E_J, Element E_R) {
        this.pi = pi;
        this.J = J;
        this.JByte = J.toBytes();
        this.Rs = Rs;
        this.RsByte = PairingUtils.convertArrayListToByteArray(Rs);
        this.E_J = E_J;
        this.EJByte = E_J.toBytes();
        this.E_R = E_R;
        this.ERByte = E_R.toBytes();
    }
}
