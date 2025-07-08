package com.encryption.BME.HPSKEM;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class HPSKEM {
    Pairing pairing;
    public Element g_1;
    public Element g_2;

    public void KEMSetup(Pairing pairing, Element g_1, Element g_2){
        this.pairing = pairing;
        this.g_1 = g_1;
        this.g_2 = g_2;
    }

    public HPSKeyPair KG(){
        Element[] sk = new Element[2];
        sk[0]= pairing.getZr().newRandomElement().getImmutable();
        sk[1] = pairing.getZr().newRandomElement().getImmutable();

        Element pk = g_1.powZn(sk[0]).mul(g_2.powZn(sk[1])).getImmutable();

       HPSKeyPair hpsKeyPair = new HPSKeyPair(pk, sk);
       return  hpsKeyPair;
    }

    public HPSCT encap_c(Element r){
        Element v_1 = g_1.powZn(r).getImmutable();
        Element v_2 = g_2.powZn(r).getImmutable();
        HPSCT c = new HPSCT(v_1, v_2);
        return  c;
    }

    public HPSCT encap_c2(Element[] r){
        Element v_1 = g_1.powZn(r[0]).getImmutable();
        Element v_2 = g_2.powZn(r[1]).getImmutable();
        HPSCT c = new HPSCT(v_1, v_2);
        return  c;
    }

    public Element encap_k(Element pk, Element r){
        Element k = pk.powZn(r).getImmutable();
        return  k;
    }

    public Element decap_k(Element[] sk, HPSCT c){
        Element k = c.v_1.powZn(sk[0]).mul(c.v_2.powZn(sk[1])).getImmutable();
        return  k;
    }

    public boolean CheckKey(HPSKeyPair keyPair){
        Element temp = g_1.powZn(keyPair.sk[0]).mul(g_2.powZn(keyPair.sk[1]));
        if (temp.isEqual(keyPair.pk)){
            return true;
        }
        return  false;
    }

    public boolean CheckCwel(HPSCT c, Element r){
        if (g_2.powZn(r).isEqual(c.v_2)){
            return true;
        }
        return  false;
    }

    public static void main(String[] args) {
        Pairing pairing = PairingFactory.getPairing("params/a_80_256.properties");
        Element g_1 = pairing.getG1().newRandomElement().getImmutable();
        Element g_2 = pairing.getG1().newRandomElement().getImmutable();
        HPSKEM HPS = new HPSKEM();
        HPS.KEMSetup(pairing, g_1, g_2);
        HPSKeyPair keyPair = HPS.KG();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        HPSCT c = HPS.encap_c(r);
        Element k = HPS.encap_k(keyPair.pk, r);
        Element kPrime = HPS.decap_k(keyPair.sk, c);

        if (k.isEqual(kPrime)){
            System.out.println("success");
        }
    }
}
