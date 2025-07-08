package com.encryption.BME.DSE;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class DSE {
    Pairing pairing;
    public Element g;
    public Element h;
    public Element u;
    public Element uPiao;

    public DSE(Pairing pairing, Element g, Element h, Element u, Element uPiao) {
        this.pairing = pairing;
        this.g = g;
        this.h = h;
        this.u = u;
        this.uPiao = uPiao;
    }

    public DSEKeyPair RKeyGen(){
        Element sk = pairing.getZr().newRandomElement().getImmutable();
        Element pk_1 = g.powZn(sk).getImmutable();
        Element pk_2 = h.powZn(sk.invert()).getImmutable();
        Element pk_3 = uPiao.powZn(sk).getImmutable();

        DSEPK pk = new DSEPK(pk_1, pk_2, pk_3);
        return new DSEKeyPair(pk, sk);
    }

    public DSEKeyPair CKeyGen(){
        Element sk = pairing.getZr().newRandomElement().getImmutable();
        Element pk_1 = g.powZn(sk).getImmutable();
        Element pk_2 = h.powZn(sk.invert()).getImmutable();
        Element pk_3 = u.powZn(sk).getImmutable();

        DSEPK pk = new DSEPK(pk_1, pk_2, pk_3);
        return new DSEKeyPair(pk, sk);
    }

    public DSECT dPEKS(DSEPK pk_c, DSEPK pk_r, String keyword){
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element A = pk_r.pk_1.powZn(r).getImmutable();

        Element element_w = PairingUtils.MapByteArrayToGroup(pairing, keyword.getBytes(), PairingUtils.PairingGroupType.G1).getImmutable();
        Element temp = pairing.pairing(pk_c.pk_1, element_w.powZn(r)).getImmutable();

        byte[] B = PairingUtils.hash(temp.toBytes());

        return new DSECT(A, B);
    }

    public Element Trapdoor(Element sk_r, String keyword){
        Element element_w = PairingUtils.MapByteArrayToGroup(pairing, keyword.getBytes(), PairingUtils.PairingGroupType.G1).getImmutable();
        Element trapdoor = element_w.powZn(sk_r.invert()).getImmutable();
        return trapdoor;
    }

    public boolean Test(Element sk_c, Element trapdoor, DSECT C){
        Element temp = pairing.pairing(C.A, trapdoor.powZn(sk_c)).getImmutable();
        byte[] BPrime = PairingUtils.hash(temp.toBytes());
        Element element_B = pairing.getG1().newElementFromBytes(C.B).getImmutable();
        Element element_BPrime = pairing.getG1().newElementFromBytes(BPrime).getImmutable();

//        if (Arrays.equals(C.B, BPrime)){
//            return true;
//        }
        if (element_B.isEqual(element_BPrime)){
            return true;
        }
        System.out.println("test fail");
        return false;
    }

}
