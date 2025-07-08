package com.encryption.BME.PSME;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

public class PSME {
    Pairing pairing;
    public Element g, h, u, v, w, g_1, h_0, h_1;
    public int m_len;

    public PSMEMSK Setup(Pairing pairing) {
        this.pairing = pairing;
        this.g = pairing.getG1().newRandomElement().getImmutable();
        this.h = pairing.getG2().newRandomElement().getImmutable();
        this.u = pairing.getG2().newRandomElement().getImmutable();
        this.v = pairing.getG2().newRandomElement().getImmutable();
        this.w = pairing.getG2().newRandomElement().getImmutable();

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element rho = pairing.getZr().newRandomElement().getImmutable();

        this.g_1 = g.powZn(rho).getImmutable();
        this.h_0 = h.powZn(rho).getImmutable();
        this.h_1 = h.powZn(beta).getImmutable();

        return new PSMEMSK(rho, alpha);
    }

    public Element EKGen(PSMEMSK msk, String id) {
        return PairingUtils.MapByteArrayToGroup(pairing, id.getBytes(), PairingUtils.PairingGroupType.G2).powZn(msk.alpha).getImmutable();
    }

    public PSMEDK DKGen(PSMEMSK msk, String id) {
        Element dk_1 = PairingUtils.MapByteArrayToGroup(pairing, id.getBytes(), PairingUtils.PairingGroupType.G1).powZn(msk.rho).getImmutable();
        Element dk_2 = PairingUtils.MapByteArrayToGroup(pairing, id.getBytes(), PairingUtils.PairingGroupType.G1).powZn(msk.alpha).getImmutable();
        Element dk_3 = PairingUtils.MapByteArrayToGroup(pairing, id.getBytes(), PairingUtils.PairingGroupType.G1).getImmutable();
        return new PSMEDK(dk_1, dk_2, dk_3);
    }

    public PSMECT Encrypt(ArrayList<String> S, Element ek, String m) throws IOException {
        m_len = m.getBytes().length;
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element d_1 = pairing.getZr().newRandomElement().getImmutable();
        Element d_2 = pairing.getZr().newRandomElement().getImmutable();
        Element sigma = pairing.getZr().newRandomElement().getImmutable();
        Element tau = pairing.getZr().newRandomElement().getImmutable();

        Element C_0 = h.powZn(s).getImmutable();
        Element C_1 = g.powZn(s).getImmutable();
        Element C_2 = h_1.powZn(tau).getImmutable();

        ArrayList<Element> Us = new ArrayList<>();
        ArrayList<Element> Vs = new ArrayList<>();

        for (String id : S) {
            Element element_id = PairingUtils.MapByteArrayToGroup(pairing, id.getBytes(), PairingUtils.PairingGroupType.G1).getImmutable();
            Element temp_1 = pairing.pairing(element_id.powZn(s), h_0).getImmutable();
            Us.add(PairingUtils.MapByteArrayToGroup(pairing, temp_1.toBytes(), PairingUtils.PairingGroupType.Zr).getImmutable());

            Element temp_2 = pairing.pairing(element_id, ek.mul(C_2)).getImmutable();
            Vs.add(PairingUtils.MapByteArrayToGroup(pairing, temp_2.toBytes(), PairingUtils.PairingGroupType.Zr).getImmutable());
        }

        // 计算多项式的系数
        ArrayList<Element> coef_as = calculatePolynomialCoefficients(Us, d_1);
        ArrayList<Element> coef_bs = calculatePolynomialCoefficients(Vs, d_2);

        Hash3Param hash3Param = new Hash3Param(d_1, d_2, C_0, C_1, C_2);
        byte[] Hash_3 = PairingUtils.hash(PairingUtils.SerCipherParameter(hash3Param));
        byte[] C_3 = calculateH3(Hash_3, m.getBytes(), m_len);

        Hash4Param hash4Param = new Hash4Param(C_0, C_1, C_2, C_3, coef_as, coef_bs);
        byte[] hash4Byte = PairingUtils.SerCipherParameter(hash4Param);
        Element phi = PairingUtils.MapByteArrayToGroup(pairing, hash4Byte, PairingUtils.PairingGroupType.Zr).getImmutable();

        Element C_4 = (u.powZn(phi).mul(v.powZn(sigma).mul(w))).powZn(s).getImmutable();
        return new PSMECT(sigma, C_0, C_1, C_2, C_3, C_4, coef_as, coef_bs);
    }

    public byte[] Decrypt(PSMEDK dk, String id, PSMECT ct) throws IOException {
        Hash4Param hash4Param = new Hash4Param(ct.C_0, ct.C_1, ct.C_2, ct.C_3, ct.as, ct.bs);
        byte[] hash4Byte = PairingUtils.SerCipherParameter(hash4Param);
        Element phi = PairingUtils.MapByteArrayToGroup(pairing, hash4Byte, PairingUtils.PairingGroupType.Zr).getImmutable();
        Element temp_1 = pairing.pairing(ct.C_1, u.powZn(phi).mul(v.powZn(ct.sigma).mul(w))).getImmutable();

        if (temp_1.isEqual(pairing.pairing(g, ct.C_4))) {
            System.out.println("verify success");
            Element temp_2 = pairing.pairing(dk.dk_1, ct.C_0).getImmutable();
            Element U = PairingUtils.MapByteArrayToGroup(pairing, temp_2.toBytes(), PairingUtils.PairingGroupType.Zr).getImmutable();
            Element d_1 = calculateD(U, ct.as);

            Element element_id = PairingUtils.MapByteArrayToGroup(pairing, id.getBytes(), PairingUtils.PairingGroupType.G2).getImmutable();
            Element temp_3 = pairing.pairing(dk.dk_3, ct.C_2).mul(pairing.pairing(dk.dk_2, element_id)).getImmutable();
            Element V = PairingUtils.MapByteArrayToGroup(pairing, temp_3.toBytes(), PairingUtils.PairingGroupType.Zr).getImmutable();
            Element d_2 = calculateD(V, ct.bs);

            Hash3Param hash3Param = new Hash3Param(d_1, d_2, ct.C_0, ct.C_1, ct.C_2);
            byte[] Hash_3 = PairingUtils.hash(PairingUtils.SerCipherParameter(hash3Param));
            byte[] H3Last = getLastBytes(Hash_3, m_len);
            byte[] C3Last = getLastBytes(ct.C_3, m_len);

            if (!Arrays.equals(C3Last, H3Last)) {
//                System.out.println("不相等");
                // return null;
            }
            byte[] m = xorByteArrays(getFirstBytes(Hash_3, m_len), getFirstBytes(ct.C_3, m_len));
            return m;
        }
        return null;
    }

    public static void main(String[] args) throws IOException {
        Pairing pairing = PairingFactory.getPairing("params/MNT224.properties");
        PSME IBBME = new PSME();
        PSMEMSK msk = IBBME.Setup(pairing);

        Element ek = IBBME.EKGen(msk, "sender");
        PSMEDK dk = IBBME.DKGen(msk, "0");

        ArrayList<String> S = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            S.add(i + "");
        }

        String m = "malicious message";
        System.out.println("m: " + m);
        PSMECT ct = IBBME.Encrypt(S, ek, m);

        byte[] mPrime = IBBME.Decrypt(dk, "sender", ct);
        System.out.println("mPrime: " + new String(mPrime));
    }

    /**
     * utils
     */

    public ArrayList<Element> calculatePolynomialCoefficients(ArrayList<Element> Uid, Element d1) {
        int t = Uid.size();
        ArrayList<Element> coefficients = new ArrayList<>();
        for (int i = 0; i <= t; i++) {
            coefficients.add(pairing.getZr().newElement().setToZero());
        }
        coefficients.set(0, pairing.getZr().newElement().setToOne());

        for (int i = 0; i < t; i++) {
            ArrayList<Element> newCoefficients = new ArrayList<>();
            for (int j = 0; j <= coefficients.size(); j++) {
                newCoefficients.add(pairing.getZr().newElement().setToZero());
            }

            for (int j = 0; j < coefficients.size(); j++) {
                newCoefficients.set(j, newCoefficients.get(j).add(coefficients.get(j)));
                newCoefficients.set(j + 1, newCoefficients.get(j + 1).sub(coefficients.get(j).mul(Uid.get(i))));
            }
            coefficients = newCoefficients;
        }

        coefficients.set(0, coefficients.get(0).add(d1));

        return coefficients;
    }

    public byte[] calculateH3(byte[] H3, byte[] m, int l1) {
        if (l1 > H3.length) {
            throw new IllegalArgumentException("l1 cannot be greater than the length of H3");
        }

        byte[] xorResult = new byte[l1];
        for (int i = 0; i < l1; i++) {
            xorResult[i] = (byte) (H3[i] ^ m[i]);
        }

        byte[] tailBits = Arrays.copyOfRange(H3, l1, H3.length);

 
        byte[] result = new byte[xorResult.length + tailBits.length];
        System.arraycopy(xorResult, 0, result, 0, xorResult.length);
        System.arraycopy(tailBits, 0, result, xorResult.length, tailBits.length);

        return result;
    }

    public Element calculateD(Element Uid, ArrayList<Element> as) {
        Element d = pairing.getZr().newElement().setToZero();
        Element uidPower = pairing.getZr().newElement().setToOne(); 

        for (int j = 0; j < as.size(); j++) {
            Element aj = as.get(j);
            Element ajTerm = aj.mul(uidPower);
            d = d.add(ajTerm);
            uidPower = uidPower.mul(Uid); // 计算 (U_{id_i})^(j+1)
        }

        Element uidPowerT = uidPower.mul(Uid);
        d = d.add(uidPowerT);

        return d;
    }

    public byte[] getFirstBytes(byte[] array, int l1) {
        if (l1 <= 0) {
            return new byte[0];
        }

        int resultBytes = Math.min(l1, array.length); 
        byte[] result = new byte[resultBytes];
        System.arraycopy(array, 0, result, 0, resultBytes);

        return result;
    }

    public byte[] getLastBytes(byte[] array, int l1) {
        if (l1 <= 0) {
            return new byte[0]; 
        }

        int resultBytes = Math.min(l1, array.length); 
        byte[] result = new byte[resultBytes];
        System.arraycopy(array, array.length - resultBytes, result, 0, resultBytes);

        return result;
    }

    public byte[] xorByteArrays(byte[] array1, byte[] array2) {
        if (array1.length != array2.length) {
            throw new IllegalArgumentException("数组长度必须相同");
        }

        byte[] result = new byte[array1.length];

        for (int i = 0; i < array1.length; i++) {
            result[i] = (byte) (array1[i] ^ array2[i]);
        }

        return result;
    }
}
