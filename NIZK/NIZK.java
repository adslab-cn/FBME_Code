package com.encryption.BME.NIZK;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class NIZK {
    Pairing pairing;
    public Element g_1;
    public Element g_2;

    public NIZK(Pairing pairing, Element g_1, Element g_2) {
        this.pairing = pairing;
        this.g_1 = g_1;
        this.g_2 = g_2;
    }

    public Proof NIZK_Proof(byte[] m, Witness witness, Statement statement){
        Element xi_1 = pairing.getZr().newRandomElement().getImmutable();
        Element xi_2 = pairing.getZr().newRandomElement().getImmutable();
        Element xi = pairing.getZr().newRandomElement().getImmutable();

        Element a = g_1.powZn(xi_1).mul(g_2.powZn(xi_2)).getImmutable();
        Element a_1 = g_1.powZn(xi).getImmutable();
        Element a_2 = g_2.powZn(xi).getImmutable();
        Element a_3 = statement.pk_J.powZn(xi).getImmutable();

        HashParam hashParam = new HashParam(statement.c.v_1,statement.c.v_2, statement.k_J, statement.pk_s, statement.pk_J, a, a_1,a_2,a_3);
        Element e = PairingUtils.MapByteArrayToGroup(pairing, hashParam.getHashBytes(), PairingUtils.PairingGroupType.Zr);

        Element z_1 = witness.sk_s[0].mul(e).add(xi_1).getImmutable();
        Element z_2 = witness.sk_s[1].mul(e).add(xi_2).getImmutable();
        Element z = witness.r.mul(e).add(xi).getImmutable();

        return new Proof(a,a_1,a_2,a_3,z_1,z_2,z);
    }

    public Boolean NIZK_Verify(byte[] m, Proof proof, Statement statement){
        HashParam hashParam = new HashParam(statement.c.v_1,statement.c.v_2, statement.k_J, statement.pk_s, statement.pk_J, proof.a, proof.a_1, proof.a_2, proof.a_3);
        Element e = PairingUtils.MapByteArrayToGroup(pairing, hashParam.getHashBytes(), PairingUtils.PairingGroupType.Zr);
        Element temp_0 = proof.a.mul(statement.pk_s.powZn(e)).getImmutable();
        Element temp_00 = g_1.powZn(proof.z_1).mul(g_2.powZn(proof.z_2)).getImmutable();

        Element temp_1 = proof.a_1.mul(statement.c.v_1.powZn(e)).getImmutable();
        Element temp_2 = proof.a_2.mul(statement.c.v_2.powZn(e)).getImmutable();
        Element temp_3 = proof.a_3.mul(statement.k_J.powZn(e)).getImmutable();

        if(temp_0.isEqual(temp_00) & temp_1.isEqual(g_1.powZn(proof.z)) & temp_2.isEqual(g_2.powZn(proof.z)) & temp_3.isEqual(statement.pk_J.powZn(proof.z))){
            return true;
        }
        System.out.println("NIZK Verify fail");
        return false;
    }
}
