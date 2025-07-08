package com.encryption.BME.PAEKS;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class PAEKS {
    Pairing pairing;
    public PAEKSPP pp;


    public void Setup(Pairing pairing){
        this.pairing = pairing;
        Element g = pairing.getG1().newRandomElement().getImmutable();
        PAEKSPP pp = new PAEKSPP(g);
        this.pp = pp;
    }


    public PAEKSKeyPair SKGen(PAEKSPP pp){
        Element sk_S = pairing.getZr().newRandomElement().getImmutable();
        Element pk_S = pp.g.powZn(sk_S).getImmutable();
        PAEKSKeyPair ek = new PAEKSKeyPair(pk_S, sk_S);
        return ek;
    }

    public PAEKSKeyPair RKGen(PAEKSPP pp){
        Element sk_R = pairing.getZr().newRandomElement().getImmutable();
        Element pk_R = pp.g.powZn(sk_R).getImmutable();
        PAEKSKeyPair dk = new PAEKSKeyPair(pk_R, sk_R);
        return dk;
    }

    public PAEKSCT PAEKS(Element pk_R, Element sk_S, String keyword){
        Element H_w = PairingUtils.MapStringToGroup(pairing, keyword, PairingUtils.PairingGroupType.G1).getImmutable();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element A = H_w.powZn(sk_S) .mul(pp.g.powZn(r)).getImmutable();
        Element B = pk_R.powZn(r).getImmutable();

        PAEKSCT C = new PAEKSCT(A, B);
        return C;
    }

    public Element Trapdoor(Element pk_S, Element sk_R, String keyword){
        Element H_w = PairingUtils.MapStringToGroup(pairing, keyword, PairingUtils.PairingGroupType.G1).getImmutable();
        Element trapdoor = pairing.pairing(H_w.powZn(sk_R), pk_S);
        return trapdoor;
    }

    public boolean Test(Element pk_R, PAEKSCT C, Element trapdoor){
        Element A = C.A.getImmutable();
        Element B = C.B.getImmutable();
        Element temp1 = pairing.pairing(A, pk_R).getImmutable();
        Element temp2 = pairing.pairing(B, pp.g).mul(trapdoor).getImmutable();
        if(temp1.isEqual(temp2)){
            return true;
        }
        return false;
    }


    public static void main(String[] args) {
        Pairing pairing = PairingFactory.getPairing("params/a_80_256.properties");
        PAEKS PAEKS = new PAEKS();
        PAEKS.Setup(pairing);

        PAEKSKeyPair sender_key = PAEKS.SKGen(PAEKS.pp);
        PAEKSKeyPair receiver_key = PAEKS.RKGen(PAEKS.pp);
        String keyword = "security";

        PAEKSCT keyword_ct = PAEKS.PAEKS(receiver_key.pk, sender_key.sk, keyword);
        Element trapdoor = PAEKS.Trapdoor(sender_key.pk, receiver_key.sk, keyword);

        Boolean flag  = PAEKS.Test(receiver_key.pk, keyword_ct, trapdoor);

        if(flag){
            System.out.println("match success");
        }
    }
}
