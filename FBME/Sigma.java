package com.encryption.BME.FBME;
import com.encryption.BME.HPSKEM.HPSCT;
import com.encryption.BME.NIZK.Proof;
import it.unisa.dia.gas.jpbc.Element;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;
import java.util.ArrayList;

@Getter
@Setter
public class Sigma implements Serializable, CipherParameters {
    public Proof pi;
    public HPSCT c;
    public transient Element k_J;
    public byte[] kJByte;

    public Sigma(Proof pi, HPSCT c, Element k_J) {
        this.pi = pi;
        this.c = c;
        this.k_J = k_J;
        this.kJByte = k_J.toBytes();
    }

    public static byte[][] convertArrayListToByteArray(ArrayList<Element> list) {
        byte[][] byteArray = new byte[list.size()][];

        for (int i = 0; i < list.size(); i++) {
            Element element = list.get(i);
            byteArray[i] = element.toBytes();
        }

        return byteArray;
    }
}
