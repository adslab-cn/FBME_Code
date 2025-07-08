package com.encryption.BME.ANOBME;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class Hint_c implements Serializable, CipherParameters {
    public transient Element[] Q;
    public byte[][] QByte;
    public byte[] A;


    public Hint_c(Element[] Q, byte[] A) {
        this.Q = Q;
        this.QByte = GetElementArrayBytes(Q);
        this.A = A;
    }


    public static byte[][] GetElementArrayBytes(Element[] elementArray) {
        byte[][] byteArrays = new byte[elementArray.length][];
        for (int i = 0; i < byteArrays.length; i++) {
            if (elementArray[i] == null) {
                byteArrays[i] = null;
                continue;
            }
            byteArrays[i] = elementArray[i].toBytes();
        }
        return byteArrays;
    }
}
