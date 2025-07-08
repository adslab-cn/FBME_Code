package com.encryption.BME.MF;

import com.encryption.BME.SPoK.*;
import com.encryption.BME.DSE.DSEKeyPair;
import com.example.encryption.BME.SPoK.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.IOException;
import java.util.ArrayList;

public class AMF {
    Pairing pairing;
    public Element g;
    SPok SPoK;

    public AMF(Pairing pairing, Element g) {
        this.pairing = pairing;
        this.g = g;
        this.SPoK = new SPok(pairing, g);
    }

    public AMFKeyPair KeyGen(){
        Element sk = pairing.getZr().newRandomElement().getImmutable();
        Element pk = g.powZn(sk).getImmutable();
        return new AMFKeyPair(pk, sk);
    }

    public AMFSigma Frank(Element pk_s, Element sk_s, Element pk_r, Element pk_j, byte[] msg) throws IOException {
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element J = pk_j.powZn(alpha).getImmutable();
        Element R = pk_r.powZn(beta).getImmutable();
        Element E_J = g.powZn(alpha).getImmutable();
        Element E_R = g.powZn(beta).getImmutable();

        Element zero = pairing.getZr().newZeroElement().getImmutable();
        Witness x = new Witness(sk_s, zero, alpha, zero);
        Statement y = new Statement(pk_s, pk_j, J, R, E_J);
        Proof pi = SPoK.NIZK_Proof(msg, x, y);
        return new AMFSigma(pi, J, R, E_J, E_R);
    }

    public AMFSigmaS Frank_S(Element pk_s, Element sk_s, ArrayList<DSEKeyPair> S, Element pk_j, byte[] msg) throws IOException {
        ArrayList<Element> Rs = new ArrayList<>();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element J = pk_j.powZn(alpha).getImmutable();
        for (DSEKeyPair rk: S){
            Element R = rk.pk.pk_1.powZn(beta).getImmutable();
            Rs.add(R);
        }

        Element E_J = g.powZn(alpha).getImmutable();
        Element E_R = g.powZn(beta).getImmutable();

        Element zero = pairing.getZr().newZeroElement().getImmutable();
        Witness x = new Witness(sk_s, zero, alpha, zero);
        Statement_S y = new Statement_S(pk_s, pk_j, J, Rs, E_J);
        Proof_S pi = SPoK.NIZK_Proof(msg, x, y);
        return new AMFSigmaS(pi, J, Rs, E_J, E_R);
    }

    public AMFSigma FrankPrime(Element pk_s, Element sk_s, Element pk_j, byte[] msg) throws IOException {
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element J = pk_j.powZn(alpha).getImmutable();
        Element E_J = g.powZn(alpha).getImmutable();

        Element zero = pairing.getZr().newZeroElement().getImmutable();
        Element one = pairing.getG1().newOneElement().getImmutable();

        Witness x = new Witness(sk_s, zero, alpha, zero);
        Statement y = new Statement(pk_s, pk_j, J, one, E_J);
        Proof pi = SPoK.NIZK_Proof(msg, x, y);
        return new AMFSigma(pi, J, one, E_J, one);
    }



    public boolean Verify(Element pk_s, Element sk_r, Element pk_j, byte[] msg, AMFSigma sigma) throws IOException {
        Statement y = new Statement(pk_s, pk_j, sigma.J, sigma.R, sigma.E_J);
        boolean b_1 = true;
        boolean b_2 = true;
        if(!sigma.R.isEqual(sigma.E_R.powZn(sk_r))){
            b_1 = false;
        }
        if (!SPoK.NIZK_Verify(msg, sigma.pi, y)){
            b_2 = false;
        }
        return b_1 && b_2;
    }

    public boolean Judge(Element pk_s, Element pk_j, Element sk_j, byte[] msg, AMFSigma sigma) throws IOException {
        Statement y = new Statement(pk_s, pk_j, sigma.J, sigma.R, sigma.E_J);
        boolean b_1 = false;
        boolean b_2 = false;
        if(sigma.J.isEqual(sigma.E_J.powZn(sk_j))){
            b_1 = true;
        }
        if (SPoK.NIZK_Verify(msg, sigma.pi, y)){
            b_2 = true;
        }
        return b_1 && b_2;
    }


    public boolean Verify(Element pk_s, Element sk_r, Element pk_j, byte[] msg, AMFSigmaS sigma) throws IOException {
        Statement_S y = new Statement_S(pk_s, pk_j, sigma.J, sigma.Rs, sigma.E_J);
        boolean b_1 = true;
        boolean b_2 = true;
        for (Element R: sigma.Rs){
            if(!R.isEqual(sigma.E_R.powZn(sk_r))){
                b_1 = false;
            }
        }

        if (!SPoK.NIZK_Verify(msg, sigma.pi, y)){
            b_2 = false;
        }
        return b_1 && b_2;
    }

    public boolean Judge(Element pk_s, Element pk_j, Element sk_j, byte[] msg, AMFSigmaS sigma) throws IOException {
        Statement_S y = new Statement_S(pk_s, pk_j, sigma.J, sigma.Rs, sigma.E_J);
        boolean b_1 = false;
        boolean b_2 = false;
        if(sigma.J.isEqual(sigma.E_J.powZn(sk_j))){
            b_1 = true;
        }
        if (SPoK.NIZK_Verify(msg, sigma.pi, y)){
            b_2 = true;
        }
        return b_1 && b_2;
    }

}
