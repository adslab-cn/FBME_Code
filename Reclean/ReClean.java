package com.encryption.BME.Reclean;

import cn.edu.buaa.crypto.utils.PairingUtils;
import com.encryption.BME.DSE.DSE;
import com.encryption.BME.DSE.DSECT;
import com.encryption.BME.ElGamal.PKE;
import com.encryption.BME.ElGamal.PKECT;
import com.encryption.BME.DSE.DSEKeyPair;
import com.encryption.BME.DSE.DSEPK;
import com.encryption.BME.MF.*;
import com.example.encryption.BME.MF.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.util.ArrayList;

public class ReClean{
    public Pairing pairing;
    public com.encryption.BME.DSE.DSE DSE;
    public com.encryption.BME.ElGamal.PKE PKE;
    public com.encryption.BME.MF.AMF AMF;
    public Element g;
    public Element h;
    public Element u;
    public Element uPiao;

    public void Setup(Pairing pairing){
        this.pairing = pairing;
        this.g = pairing.getG1().newRandomElement().getImmutable();
        this.h = pairing.getG1().newRandomElement().getImmutable();
        this.u = pairing.getG1().newRandomElement().getImmutable();
        this.uPiao = pairing.getG1().newRandomElement().getImmutable();
        this.DSE = new DSE(pairing, g, h, u, uPiao);
        this.PKE = new PKE(pairing, g);
        this.AMF = new AMF(pairing, g);
    }

    /**
     * Key Generation Algorithms
     */

    public AMFKeyPair SKeyGen(){
        AMFKeyPair skPair = AMF.KeyGen();
        return skPair;
    }

    public DSEKeyPair RKeyGen(){
        return DSE.RKeyGen();
    }

    public DSEKeyPair CKeyGen(){
        return DSE.CKeyGen();
    }

    /**
     * Retrievability algorithms
     */
    public DSECT dPEKS(DSEPK pk_c, DSEPK pk_r, String keyword){
        return DSE.dPEKS(pk_c, pk_r, keyword);
    }

    public Element Trapdoor(Element sk_r, String keyword){
        return DSE.Trapdoor(sk_r, keyword);
    }

    public boolean Test(Element sk_r, Element trapdoor, DSECT C){
        return DSE.Test(sk_r, trapdoor, C);
    }

    /**
     * Accountability Algorithms
     */
    public CT Frank(Element pk_s, Element sk_s, DSEPK pk_c, DSEPK pk_r, byte[] m) throws IOException {
        PKECT c = PKE.Enc(pk_r.pk_1, m);
        AMFSigma sigma= AMF.Frank(pk_s, sk_s, pk_r.pk_1, pk_c.pk_1, m);

        byte[] cByte = PairingUtils.SerCipherParameter(c);
        AMFSigma sigmaPrime = AMF.FrankPrime(pk_s, sk_s, pk_c.pk_1, cByte);
        CT frank =  new CT(c, sigma, sigmaPrime);
        return frank;
    }

    public Frank Frank_S(Element pk_s, Element sk_s, DSEPK pk_c, ArrayList<DSEKeyPair> S, byte[] m) throws IOException {
        ArrayList<PKECT> c_S = new ArrayList<>();
        for (DSEKeyPair rkPair: S){
            DSEPK pk_r = rkPair.pk;
            PKECT c = PKE.Enc(pk_r.pk_1, m);
            c_S.add(c);
        }
        AMFSigmaS sigma_S= AMF.Frank_S(pk_s, sk_s, S, pk_c.pk_1, m);

        byte[][] cByte = PairingUtils.convertArrayListToByteArrayC(c_S);
        AMFSigma sigmaPrime = AMF.FrankPrime(pk_s, sk_s, pk_c.pk_1, null);
        Frank frank =  new Frank(c_S, sigma_S, sigmaPrime);

        return frank;
    }

    public boolean Clean(Element pk_s, Element sk_c, AMFSigma sigmaPrime, PKECT c) throws IOException {
        byte[] cByte = PairingUtils.SerCipherParameter(c);
        return AMF.Judge(pk_s, null, sk_c, cByte, sigmaPrime);
    }

    public byte[] Verify(Element pk_s, Element sk_r, DSEPK pk_c, AMFSigma sigma, PKECT c) throws IOException {
        byte[] cByte = PKE.Dec(sk_r, c);
        if(!AMF.Verify(pk_s, sk_r, pk_c.pk_1, cByte, sigma)){
            System.out.println("receiver verify fail");
            return null;
        }
        return cByte;
    }

    public byte[] Verify(Element pk_s, Element sk_r, DSEPK pk_c, AMFSigmaS sigma, PKECT c) throws IOException {
        byte[] cByte = PKE.Dec(sk_r, c);
        if(!AMF.Verify(pk_s, sk_r, pk_c.pk_1, cByte, sigma)){
            System.out.println("receiver verify fail");
            return null;
        }
        return cByte;
    }

    public boolean Judge(Element pk_s, Element pk_j, Element sk_c, AMFSigma sigma, byte[] msg) throws IOException {
        return AMF.Judge(pk_s, pk_j, sk_c, msg, sigma);
    }

    public boolean Judge(Element pk_s, Element pk_j, Element sk_c, AMFSigmaS sigma, byte[] msg) throws IOException {
        return AMF.Judge(pk_s, pk_j, sk_c, msg, sigma);
    }

    public static void main(String[] args) throws IOException {
        Pairing pairing = PairingFactory.getPairing("params/a_80_256.properties");
        ReClean reClean = new ReClean();
        reClean.Setup(pairing);

        AMFKeyPair SKPair = reClean.SKeyGen();
        DSEKeyPair RKPair = reClean.RKeyGen();
        DSEKeyPair CKPair = reClean.CKeyGen();

        String keyword = "security";
        DSECT keyword_ct = reClean.dPEKS(CKPair.pk, RKPair.pk, keyword);
        Element trapdoor = reClean.Trapdoor(RKPair.sk, keyword);
        boolean flag_1 = reClean.Test(RKPair.sk, trapdoor, keyword_ct);
        if (!flag_1){
            System.out.println("keyword test fail");
        }

        //Accountability Test
//        String m = "malicious message";
//        System.out.println("m:"+ m);
//        CT ct = reClean.Frank(SKPair.pk, SKPair.sk, CKPair.pk, RKPair.pk, m.getBytes());
//        byte[] mByte = reClean.Verify(SKPair.pk, RKPair.sk, CKPair.pk, ct.sigma, ct.c);
//        System.out.println("mPrime:"+ new String(mByte));
//        boolean flag_3 = reClean.Judge(SKPair.pk, CKPair.pk.pk_1, CKPair.sk, ct.sigma, mByte);
//        if (!flag_3){
//            System.out.println("Judge judge fail");
//        }
    }

}
