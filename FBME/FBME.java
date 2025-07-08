package com.encryption.BME.FBME;

import cn.edu.buaa.crypto.utils.CompressionUtils;
import cn.edu.buaa.crypto.utils.PairingUtils;
import com.encryption.BME.ANOBME.*;
import com.encryption.BME.HPSKEM.HPSKEM;
import com.encryption.BME.NIZK.NIZK;
import com.encryption.BME.NIZK.Statement;
import com.encryption.BME.NIZK.Witness;
import com.example.encryption.BME.ANOBME.*;
import com.encryption.BME.HPSKEM.HPSCT;
import com.encryption.BME.HPSKEM.HPSKeyPair;
import com.encryption.BME.NIZK.Proof;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CryptoException;

import java.io.IOException;
import java.util.ArrayList;

public class FBME {
    Pairing pairing;
    public Element g_1;
    public Element g_2;
    public ANOBME BME = new ANOBME();
    public HPSKEM HPS = new HPSKEM();
    public com.encryption.BME.NIZK.NIZK NIZK;

    /**
     * Setup
     */
    public void Setup(Pairing pairing, Element g_1, Element g_2){
        this.pairing = pairing;
        this.g_1 = g_1;
        this.g_2 = g_2;

        BME.Setup(pairing, g_1, g_2);
        HPS.KEMSetup(pairing, g_1, g_2);
        NIZK = new NIZK(pairing, g_1, g_2);
    }

    /**
     * Key Generation
     */
    public HPSKeyPair JKen(){
        HPSKeyPair JKPair = HPS.KG();
        return  JKPair;
    }

    public RKPair RKGen() throws IOException {
        RKPair rkPair = BME.RKGen();
        return rkPair;
    }

    public FBME_SKPair SKGen(){
        SKPair skPair_1 = BME.SKGen();
        HPSKeyPair skPair_2 = HPS.KG();

        Element[] pk_s = new Element[2];
        pk_s[0] = skPair_1.pk_s;
        pk_s[1] = skPair_2.pk;
        return new FBME_SKPair(pk_s, new FBME_SK(skPair_1.sk_s, skPair_2.sk));
    }

    /**
     * Data Matching
     */

    public Sigma Frank(Element[] pk_s, FBME_SK sk_s, Element pk_J, byte[] m) throws CryptoException, IOException {
        Element r = pairing.getZr().newRandomElement().getImmutable();
        HPSCT c = HPS.encap_c(r);
        Element k_J = HPS.encap_k(pk_J, r);

        //NIZK.Prove
        Witness w = new Witness(sk_s.sk_s2, r);
        Statement y = new Statement(pk_s[1], pk_J, c, k_J);
//        mBar mBar = new mBar(m, krs);
//        byte[] mbar = PairingUtils.SerCipherParameter(mBar);
        Proof pi = NIZK.NIZK_Proof(null, w, y);

        Sigma sigma = new Sigma(pi, c, k_J);
        return sigma;
    }


    public FBMECT Encrypt(Element[] pk_s, FBME_SK sk_s, ArrayList<PK_R> S, Element pk_J, byte[] m) throws CryptoException, IOException {
        Sigma sigma = Frank(pk_s, sk_s, pk_J, m);
        mFrank mFrank = new mFrank(m, sigma);
        byte[] m_frank = PairingUtils.SerCipherParameter(mFrank);
        byte[] short_mFrank = CompressionUtils.compress(m_frank);
        BME.m_len = short_mFrank.length;

        ANOBMECT ct = BME.Encrypt(pk_s[0], sk_s.sk_s1, S, short_mFrank);
        byte[] ctByte = PairingUtils.SerCipherParameter(ct);
        byte[] short_ctByte = CompressionUtils.compress(ctByte);
        System.out.println("ct Size:"+short_ctByte.length);
        return new FBMECT(ct, sigma);
    }

    public byte[] Decrypt(SK_R sk_r, Element pk_s, FBMECT ct) throws IOException, ClassNotFoundException {
        byte[] short_mFrank = BME.Decrypt(sk_r,pk_s,ct.C);
        byte[] m_frank = CompressionUtils.decompress(short_mFrank);
        mFrank mFrank = (com.encryption.BME.FBME.mFrank) PairingUtils.deserCipherParameters(m_frank);
        byte[] m = mFrank.m;
        System.out.println("Recover m:"+ new String(m));
        return m;
    }

    /**
     * Data Moderation
     */
    public Report Report(Element pk_s, Element pk_J, byte[] m, Sigma sigma) throws IOException {
        //NIZK.Verify
        Proof pi = sigma.pi;
        Statement y = new Statement(pk_s, pk_J, sigma.c, sigma.k_J);
//        mBar mBar = new mBar(report.m, report.sigma.krs);
//        byte[] mbar = PairingUtils.SerCipherParameter(mBar);
        if (NIZK.NIZK_Verify(null, pi, y)) {
            Report report = new Report(m, sigma);
            byte[] byte_report = PairingUtils.SerCipherParameter(report);
            byte[] short_report = CompressionUtils.compress(byte_report);
            System.out.println("report Size:"+ short_report.length);
            return report;
        }
        return null;
    }

    public Boolean Judge(Element pk_s, Element pk_J, Element[] sk_J, Report report) throws IOException {
        //NIZK.Verify
        Proof pi = report.sigma.pi;
        Statement y = new Statement(pk_s, pk_J, report.sigma.c, report.sigma.k_J);
//        mBar mBar = new mBar(report.m, report.sigma.krs);
//        byte[] mbar = PairingUtils.SerCipherParameter(mBar);

        if (!NIZK.NIZK_Verify(null, pi, y)) {
            return false;
        }

        //HPS-KEM.decap
        Element k_J = HPS.decap_k(sk_J, report.sigma.c);
        if(report.sigma.k_J.isEqual(k_J)){
                return true;
        }
        System.out.println("Judge HPS-KEM.decap fail");
        return false;
    }

    public static void main(String[] args) throws CryptoException, IOException, ClassNotFoundException {
        Pairing pairing = PairingFactory.getPairing("params/a_80_256.properties");
        Element g_1 = pairing.getG1().newRandomElement().getImmutable();
        Element g_2 = pairing.getG1().newRandomElement().getImmutable();
        FBME FBME = new FBME();
        FBME.Setup(pairing, g_1, g_2);
        FBME.BME.Setup(pairing, g_1, g_2);

        HPSKeyPair JkPair = FBME.JKen();
        FBME_SKPair skPair = FBME.SKGen();
        ArrayList<RKPair> rkPair = new ArrayList<>();
        ArrayList<PK_R> S = new ArrayList<>();
        for (int i = 0; i <10; i++) {
            RKPair rk = FBME.RKGen();
            rkPair.add(rk);
            S.add(rk.pk_r);
        }

        String m = "malicious harassment information";
        System.out.println("m:" + m);

        FBMECT ct = FBME.Encrypt(skPair.pk_s, skPair.sk_s, S, JkPair.pk, m.getBytes());

        RKPair rkPair1 = rkPair.get(0);
        byte[] m_byte = FBME.Decrypt(rkPair1.sk_r, skPair.pk_s[0], ct);
        System.out.println("Decrypt success");

        Element[] sk_r = new Element[2];
        sk_r[0] = rkPair1.sk_r.x_1.getImmutable();
        sk_r[1] = rkPair1.sk_r.x_2.getImmutable();

        Report report = FBME.Report(skPair.pk_s[1], JkPair.pk, m_byte, ct.sigma);
        if (report!=null){
            System.out.println("Receiver Verify Success");
        }
        Boolean flag = FBME.Judge(skPair.pk_s[1], JkPair.pk, JkPair.sk, report);
        if (flag){
            System.out.println("Moderator Judge Success");
        }

    }


}
