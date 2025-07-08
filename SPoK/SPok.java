package com.encryption.BME.SPoK;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.IOException;
import java.util.ArrayList;

public class SPok {
    Pairing pairing;
    public Element g;

    public SPok(Pairing pairing, Element g) {
        this.pairing = pairing;
        this.g = g;
    }

    public Proof NIZK_Proof(byte[] m, Witness witness, Statement statement) throws IOException {
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element gamma = pairing.getZr().newRandomElement().getImmutable();
        Element delta = pairing.getZr().newRandomElement().getImmutable();

        Element a_1 = g.powZn(alpha).getImmutable();
        Element a_2 = g.powZn(beta).getImmutable();
        Element a_3 = statement.pk_j.powZn(gamma).getImmutable();
        Element a_4 = g.powZn(gamma).getImmutable();
        Element a_5 = g.powZn(delta).getImmutable();

        HashParam hashParam = new HashParam(statement.pk_s, statement.pk_j, statement.J, statement.R, statement.E_J, a_1, a_2, a_3, a_4, a_5);
        byte[] eByte = PairingUtils.SerCipherParameter(hashParam);
        Element e = PairingUtils.MapByteArrayToGroup(pairing, eByte, PairingUtils.PairingGroupType.Zr).getImmutable();

        Element z_1 = witness.t.mulZn(e).add(alpha).getImmutable();
        Element z_2 = witness.u.mulZn(e).add(beta).getImmutable();
        Element z_3 = witness.v.mulZn(e).add(gamma).getImmutable();
        Element z_4 = witness.w.mulZn(e).add(delta).getImmutable();


        return new Proof(a_1, a_2, a_3, a_4,a_5, z_1,z_2,z_3,z_4);
    }

    public boolean NIZK_Verify(byte[] m, Proof pi, Statement statement) throws IOException {
        HashParam hashParam = new HashParam(statement.pk_s, statement.pk_j, statement.J, statement.R, statement.E_J, pi.a_1, pi.a_2, pi.a_3, pi.a_4, pi.a_5);
        byte[] eByte = PairingUtils.SerCipherParameter(hashParam);
        Element e = PairingUtils.MapByteArrayToGroup(pairing, eByte, PairingUtils.PairingGroupType.Zr).getImmutable();

        Element temp_1 = pi.a_1.mul(statement.pk_s.powZn(e)).getImmutable();
        boolean b_1 = temp_1.isEqual(g.powZn(pi.z_1));
        if (!b_1){
            System.out.println("b_1 false");
        }

        Element temp_2 = pi.a_2.mul(statement.J.powZn(e)).getImmutable();
        boolean b_2 = temp_2.isEqual(g.powZn(pi.z_2));
//        if (!b_2){
//            System.out.println("b_2 false");
//        }


        Element temp_3 = pi.a_3.mul(statement.J.powZn(e)).getImmutable();
        Element temp_4 = pi.a_4.mul(statement.E_J.powZn(e)).getImmutable();
        boolean b_31 = temp_3.isEqual(statement.pk_j.powZn(pi.z_3)) && temp_4.isEqual(g.powZn(pi.z_3));
        if (!b_31){
            System.out.println("b_31 false");
        }

        Element temp_32 = pi.a_5.mul(statement.R.powZn(e));
        boolean b_32 = temp_32.isEqual(g.powZn(pi.z_4));
//        if (!b_32){
//            System.out.println("b_32 false");
//        }


        boolean flag = false;

        if(b_1 || b_2  || (b_31 || b_32)){
            flag = true;
            System.out.println("NIZK Verify success");
        }
        return flag;
    }


    //set S
    public Proof_S NIZK_Proof(byte[] m, Witness witness, Statement_S statement) throws IOException {
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element gamma = pairing.getZr().newRandomElement().getImmutable();
        ArrayList<Element> deltas = new ArrayList<>();
        ArrayList<Element> a5s = new ArrayList<>();
        ArrayList<Element> z4s = new ArrayList<>();

        Element a_1 = g.powZn(alpha).getImmutable();
        Element a_2 = g.powZn(beta).getImmutable();
        Element a_3 = statement.pk_j.powZn(gamma).getImmutable();
        Element a_4 = g.powZn(gamma).getImmutable();
        for (int i = 0; i < statement.Rs.size(); i++) {
            Element delta_i = pairing.getZr().newRandomElement().getImmutable();
            Element a_5 = g.powZn(delta_i).getImmutable();
            deltas.add(delta_i);
            a5s.add(a_5);
        }

        HashParam_S hashParam = new HashParam_S(statement.pk_s, statement.pk_j, statement.J, statement.Rs, statement.E_J, a_1, a_2, a_3, a_4, a5s);

        byte[] eByte = PairingUtils.SerCipherParameter(hashParam);
        Element e = PairingUtils.MapByteArrayToGroup(pairing, eByte, PairingUtils.PairingGroupType.Zr).getImmutable();

        Element z_1 = witness.t.mulZn(e).add(alpha).getImmutable();
        Element z_2 = witness.u.mulZn(e).add(beta).getImmutable();
        Element z_3 = witness.v.mulZn(e).add(gamma).getImmutable();
        for (Element delta_i: deltas){
            Element z_4 = witness.w.mulZn(e).add(delta_i).getImmutable();
            z4s.add(z_4);
        }

        return new Proof_S(a_1, a_2, a_3, a_4, a5s, z_1,z_2,z_3, z4s);
    }

    public boolean NIZK_Verify(byte[] m, Proof_S pi, Statement_S statement) throws IOException {
        HashParam_S hashParam = new HashParam_S(statement.pk_s, statement.pk_j, statement.J, statement.Rs, statement.E_J, pi.a_1, pi.a_2, pi.a_3, pi.a_4, pi.a5s);
        byte[] eByte = PairingUtils.SerCipherParameter(hashParam);
        Element e = PairingUtils.MapByteArrayToGroup(pairing, eByte, PairingUtils.PairingGroupType.Zr).getImmutable();

        Element temp_1 = pi.a_1.mul(statement.pk_s.powZn(e)).getImmutable();
        boolean b_1 = temp_1.isEqual(g.powZn(pi.z_1));
        if (!b_1){
            System.out.println("b_1 false");
        }

        Element temp_2 = pi.a_2.mul(statement.J.powZn(e)).getImmutable();
        boolean b_2 = temp_2.isEqual(g.powZn(pi.z_2));
//        if (!b_2){
//            System.out.println("b_2 false");
//        }


        Element temp_3 = pi.a_3.mul(statement.J.powZn(e)).getImmutable();
        Element temp_4 = pi.a_4.mul(statement.E_J.powZn(e)).getImmutable();
        boolean b_31 = temp_3.isEqual(statement.pk_j.powZn(pi.z_3)) && temp_4.isEqual(g.powZn(pi.z_3));
        if (!b_31){
            System.out.println("b_31 false");
        }

        ArrayList<Element> temps = new ArrayList<>();
        for (int i = 0; i < statement.Rs.size(); i++) {
            Element temp_32 = pi.a5s.get(i).mul(statement.Rs.get(i).powZn(e));
            boolean b_32 = temp_32.isEqual(g.powZn(pi.z4s.get(i)));
            if (!b_32){
                System.out.println("b_32 false");
            }
        }

        boolean flag = false;

        if(b_1 || b_2  || (b_31)){
            flag = true;
            System.out.println("NIZK Verify success");
        }
        return flag;
    }
}
