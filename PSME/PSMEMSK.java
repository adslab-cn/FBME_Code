package com.encryption.BME.PSME;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class PSMEMSK implements Serializable, CipherParameters {
    public transient Element rho;
    public transient Element alpha;

    public PSMEMSK(Element rho, Element alpha) {
        this.rho = rho;
        this.alpha = alpha;
    }
}
