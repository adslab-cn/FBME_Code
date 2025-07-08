package com.encryption.BME.SPoK;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;
import java.util.ArrayList;

public class Statement_S implements Serializable, CipherParameters {
    public transient Element pk_s;
    public final byte[] pksByte;
    public transient Element pk_j;
    public final byte[] pkjByte;
    public transient Element J;
    public final byte[] JByte;
    public transient ArrayList<Element> Rs;
    public final byte[][] RsByte;
    public transient Element E_J;
    public final byte[] EJByte;

    public Statement_S(Element pk_s, Element pk_j, Element J, ArrayList<Element> Rs, Element E_J) {
        this.pk_s = pk_s;
        this.pksByte = pk_s.toBytes();
        this.pk_j = pk_j;
        this.pkjByte = pk_j.toBytes();
        this.J = J;
        this.JByte = J.toBytes();
        this.Rs = Rs;
        this.RsByte = PairingUtils.convertArrayListToByteArray(Rs);
        this.E_J = E_J;
        this.EJByte = E_J.toBytes();
    }
}
