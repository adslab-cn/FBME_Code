package com.encryption.BME.RBME;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.ArrayList;

public class RBME {
    Pairing pairing;
    public Element g;
    public Element g_0;

    public RBME() {
    }

    public RBMEMSK Setup(Pairing pairing) {
        this.pairing = pairing;
        this.g = pairing.getG1().newRandomElement().getImmutable();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element s = pairing.getZr().newRandomElement().getImmutable();
        this.g_0 = g.powZn(r).getImmutable();
        return new RBMEMSK(r, s);
    }

    public Element SKGen(RBMEMSK msk, String id_s) {
        Element hashID = PairingUtils.MapByteArrayToGroup(pairing, id_s.getBytes(), PairingUtils.PairingGroupType.G1).getImmutable();
        Element ek = hashID.powZn(msk.s).getImmutable();
        return ek;
    }

    public RBMERK RKGen(RBMEMSK msk, String id_r) {
        Element hashID = PairingUtils.MapByteArrayToGroup(pairing, id_r.getBytes(), PairingUtils.PairingGroupType.G1).getImmutable();
        Element dk_1 = hashID.powZn(msk.r).getImmutable();
        Element dk_2 = hashID.powZn(msk.s).getImmutable();
        return new RBMERK(dk_1, dk_2);
    }

    public RBMECT Encrypt(Element ek, ArrayList<String> S, Element m) {
        Element eta_2 = pairing.getZr().newRandomElement().getImmutable();
        Element eta_3 = pairing.getZr().newRandomElement().getImmutable();
        Element omega = pairing.getZr().newRandomElement().getImmutable();
        Element v = pairing.getG1().newRandomElement().getImmutable();

        Element temp1 = g_0.powZn(eta_2).getImmutable();
        Element temp2 = g.powZn(eta_3).mul(ek).getImmutable();

        ArrayList<Element> xs = new ArrayList<>();
        ArrayList<Element> Bs = new ArrayList<>();
        ArrayList<Element> Ds = new ArrayList<>();
        for (String id_r : S) {
            Element x_i = PairingUtils.MapByteArrayToGroup(pairing, id_r.getBytes(), PairingUtils.PairingGroupType.Zr).getImmutable();
            xs.add(x_i);

            Element hashID = PairingUtils.MapByteArrayToGroup(pairing, id_r.getBytes(), PairingUtils.PairingGroupType.G1).getImmutable();

            Element temp = pairing.pairing(hashID, temp1).getImmutable();
            byte[] BiByte = mergeByteArrays(temp.toBytes(), id_r.getBytes());
            Element Bi = PairingUtils.MapByteArrayToGroup(pairing, BiByte, PairingUtils.PairingGroupType.G1).mul(v).getImmutable();
            Bs.add(Bi);

            Element Di = pairing.pairing(hashID, temp2).getImmutable();
            Element hash_Di = PairingUtils.MapByteArrayToGroup(pairing, Di.toBytes(), PairingUtils.PairingGroupType.Zr).getImmutable();
            Ds.add(hash_Di);
        }

        ArrayList<Element> Us = new ArrayList<>();

 
        ArrayList<ArrayList<Element>> as = new ArrayList<>();
        for (int i = 0; i < xs.size(); i++) {
            ArrayList<Element> ai = computeLagrangeCoefficients(xs, i);
            as.add(ai);
        }
        Us = computeSum(as, Bs);

        ArrayList<Element> coef_es = calculatePolynomialCoefficients(Ds, omega);
        Element C_0 = PairingUtils.MapByteArrayToGroup(pairing, omega.toBytes(), PairingUtils.PairingGroupType.G1).mul(v).mul(m).getImmutable();
        Element C_2 = g.powZn(eta_2).getImmutable();
        Element C_3 = g.powZn(eta_3).getImmutable();

        return new RBMECT(C_0, C_2, C_3, Us, coef_es);
    }

    public Element Decrypt(RBMECT ct, RBMERK dk, String id_s, String id_r) {
        Element x = PairingUtils.MapByteArrayToGroup(pairing, id_r.getBytes(), PairingUtils.PairingGroupType.Zr).getImmutable();
        Element U = computeU(ct.Us, x);

        Element temp = pairing.pairing(dk.dk_1, ct.C_2);
        byte[] bytes = mergeByteArrays(temp.toBytes(), id_r.getBytes());
        Element v = U.div(PairingUtils.MapByteArrayToGroup(pairing, bytes, PairingUtils.PairingGroupType.G1)).getImmutable();

        Element hash_ids = PairingUtils.MapByteArrayToGroup(pairing, id_s.getBytes(), PairingUtils.PairingGroupType.G1).getImmutable();
        Element hash_idr = PairingUtils.MapByteArrayToGroup(pairing, id_r.getBytes(), PairingUtils.PairingGroupType.G1).getImmutable();
        Element E = pairing.pairing(dk.dk_2, hash_ids).mul(pairing.pairing(hash_idr, ct.C_3)).getImmutable();
        Element hashE = PairingUtils.MapByteArrayToGroup(pairing, E.toBytes(), PairingUtils.PairingGroupType.Zr).getImmutable();
        Element omega = computeOmega(ct.es, hashE);
        Element hash_omega = PairingUtils.MapByteArrayToGroup(pairing, omega.toBytes(), PairingUtils.PairingGroupType.G1).getImmutable();
        Element m = ct.C_0.div(hash_omega).div(v).getImmutable();
        return m;
    }

    public static void main(String[] args) {
        Pairing pairing = PairingFactory.getPairing("params/a_80_256.properties");
        RBME RBME = new RBME();
        RBMEMSK msk = RBME.Setup(pairing);

        Element ek = RBME.SKGen(msk, "sender");
        RBMERK dk = RBME.RKGen(msk, "0");

        ArrayList<String> S = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            S.add(i + "");
        }

        Element m = pairing.getG1().newRandomElement().getImmutable();
        System.out.println("m: " + m);

        RBMECT ct = RBME.Encrypt(ek, S, m);
        Element mPrime = RBME.Decrypt(ct, dk, "sender", "0");
        System.out.println("mPrime: " + mPrime);
    }

    public Element computeOmega(ArrayList<Element> es, Element Ei) {
        Element result = pairing.getZr().newElement().setToZero();
        Element EiPower = pairing.getZr().newElement().setToOne();

        for (int j = 0; j < es.size(); j++) {
            Element term = es.get(j).duplicate().mul(EiPower);
            result.add(term);
            EiPower.mul(Ei); 
        }

        return result.getImmutable();
    }

    public Element computeU(ArrayList<Element> Us, Element xi) {
        Element result = pairing.getG1().newOneElement();
        Element xiPower = pairing.getZr().newOneElement();

        System.out.println("Us.size: " + Us.size());
        for (int i = 0; i < Us.size(); i++) {
            Element term = Us.get(i).powZn(xiPower);
            result.mul(term);
            xiPower.mul(xi);
        }

        return result.getImmutable();
    }

    public ArrayList<Element> calculatePolynomialCoefficients(ArrayList<Element> Ds, Element omega) {
        int t = Ds.size();

        // 初始化多项式，开始时是常数1
        ArrayList<Element> coefficients = new ArrayList<>();
        for (int i = 0; i <= t; i++) {
            coefficients.add(pairing.getZr().newElement().setToZero());
        }
        coefficients.set(0, pairing.getZr().newElement().setToOne());

        // 计算乘积 ∏(x - D[i])
        for (int i = 0; i < t; i++) {
            ArrayList<Element> newCoefficients = new ArrayList<>();
            for (int j = 0; j < coefficients.size(); j++) {  
                newCoefficients.add(pairing.getZr().newElement().setToZero());
            }

            for (int j = 0; j < coefficients.size() - 1; j++) {  
                newCoefficients.set(j, newCoefficients.get(j).add(coefficients.get(j)));
                newCoefficients.set(j + 1, newCoefficients.get(j + 1).sub(coefficients.get(j).mul(Ds.get(i))));
            }
            newCoefficients.set(coefficients.size() - 1, coefficients.get(coefficients.size() - 1));
            coefficients = newCoefficients;
        }

        coefficients.set(0, coefficients.get(0).add(omega));

        return coefficients;
    }


    public ArrayList<Element> computeLagrangeCoefficients(ArrayList<Element> xValues, int i) {
        int n = xValues.size();
        ArrayList<Element> coefficients = new ArrayList<>();
        Element one = pairing.getZr().newOneElement();

        for (int k = 0; k < n; k++) {
            coefficients.add(pairing.getZr().newZeroElement());
        }
        coefficients.set(0, one.duplicate());

        // 计算拉格朗日基函数 l_i(x)
        for (int j = 0; j < n; j++) {
            if (j == i) continue;

            Element xj = xValues.get(j).duplicate();  
            Element xi = xValues.get(i).duplicate();

            Element xiMinusXj = xi.duplicate().sub(xj);


            ArrayList<Element> newCoefficients = new ArrayList<>();
            for (int k = 0; k < n; k++) {  
                newCoefficients.add(pairing.getZr().newZeroElement());
            }

            for (int k = n - 2; k >= 0; k--) {  
                newCoefficients.set(k + 1, newCoefficients.get(k + 1).add(coefficients.get(k)));
                newCoefficients.set(k, newCoefficients.get(k).sub(coefficients.get(k).duplicate().mul(xj).div(xiMinusXj)));
            }

            coefficients = newCoefficients;
        }

        return coefficients;
    }

    public static byte[] mergeByteArrays(byte[] array1, byte[] array2) {
        byte[] mergedArray = new byte[array1.length + array2.length];

        System.arraycopy(array1, 0, mergedArray, 0, array1.length);
        System.arraycopy(array2, 0, mergedArray, array1.length, array2.length);

        return mergedArray;
    }

    public ArrayList<Element> computeSum(ArrayList<ArrayList<Element>> aij, ArrayList<Element> As) {
        ArrayList<Element> Us = new ArrayList<>();

        for (int i = 0; i < aij.size(); i++) {
            Element Qi = pairing.getG1().newOneElement().getImmutable();  
            ArrayList<Element> aijRow = aij.get(i);

            for (int j = 0; j < aijRow.size(); j++) {
                Element term = As.get(j).powZn(aijRow.get(j)).getImmutable();
                Qi.mul(term);
            }

            Us.add(Qi);  
        }

        return Us;
    }

}
