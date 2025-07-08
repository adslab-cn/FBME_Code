package com.encryption.BME.ElGamal;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class PKE {
    Pairing pairing;
    public Element g;

    public PKE(Pairing pairing, Element g) {
        this.pairing = pairing;
        this.g = g;
    }

    public PKECT Enc(Element pk, byte[] m){
        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element C_1 = g.powZn(t).getImmutable();

        Element element_m = PairingUtils.MapByteArrayToGroup(pairing, m, PairingUtils.PairingGroupType.G1).getImmutable();
        Element C_2 = pk.powZn(t).mul(element_m).getImmutable();

        return new PKECT(C_1, C_2);
    }


    public byte[] Dec(Element sk, PKECT C){
        Element element_m = C.C_1.powZn(sk.negate()).mul(C.C_2).getImmutable();
        byte[] mByte = element_m.toBytes();
        return mByte;
    }
}
