package com.encryption.BME.FBME;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;
import java.util.ArrayList;

public class mBar implements Serializable, CipherParameters {
    public final byte[] m;
    public transient ArrayList<Element> krs;
    public final byte[][] krsByte;

    public mBar(byte[] m, ArrayList<Element> krs) {
        this.m = m;
        this.krs = krs;
        this.krsByte = PairingUtils.convertArrayListToByteArray(krs);
    }
}
