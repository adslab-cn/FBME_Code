package com.encryption.BME.ANOBME;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.signature.pks.PairingDigestSigner;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01SignKeyPairGenerationParameter;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01SignKeyPairGenerator;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01Signer;
import cn.edu.buaa.crypto.utils.CompressionUtils;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.io.IOException;
import java.util.ArrayList;

public class ANOBME {
    Pairing pairing;
    public int m_len;
    public Element g_1;
    public Element g_2;

    PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_f_160);
    private PairingKeyPairGenerator asymmetricKeySerPairGenerator = new BLS01SignKeyPairGenerator();
    private Signer signer = new PairingDigestSigner(new BLS01Signer(), new SHA256Digest());

    public void Setup(Pairing pairing, Element g_1, Element g_2){
        this.pairing = pairing;
        this.g_1 = g_1;
        this.g_2 = g_2;
        asymmetricKeySerPairGenerator.init(new BLS01SignKeyPairGenerationParameter(pairingParameters));
    }

    public SKPair SKGen(){
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element pk_s = g_1.powZn(s).getImmutable();
        SKPair skPair = new SKPair(pk_s, s);
        return skPair;
    }

    public RKPair RKGen() throws IOException {
        Element x_1 = pairing.getZr().newRandomElement().getImmutable();
        Element x_2 = pairing.getZr().newRandomElement().getImmutable();
        Element y_1 = pairing.getZr().newRandomElement().getImmutable();
        Element y_2 = pairing.getZr().newRandomElement().getImmutable();
        Element o = pairing.getZr().newRandomElement().getImmutable();

        Element D_1 = g_1.powZn(x_1).mul(g_2.powZn(x_2)).getImmutable();
        Element D_2 = g_1.powZn(y_1).mul(g_2.powZn(y_2)).getImmutable();
        Element D_3 = g_1.powZn(o).getImmutable();

        SK_R sk_r = new SK_R(x_1,x_2,y_1,y_2, o);
        PK_R pk_r = new PK_R(D_1, D_2, D_3);

        RKPair rkPair = new RKPair(pk_r, sk_r);
        return rkPair;
    }

    public ANOBMECT Encrypt(Element pk_s, Element sk_s, ArrayList<PK_R> S, byte[] m) throws CryptoException, IOException {
        PairingKeySerPair keyPair = this.asymmetricKeySerPairGenerator.generateKeyPair();
        PairingKeySerParameter svk = keyPair.getPublic();
        PairingKeySerParameter ssk = keyPair.getPrivate();

        Element omega = pairing.getZr().newRandomElement().getImmutable();

        Element u_1 = g_1.powZn(omega).getImmutable();
        Element u_2 = g_2.powZn(omega).getImmutable();
        byte[] temp = concatenateBytes(u_1, u_2, svk);
        Element alpha = PairingUtils.MapByteArrayToGroup(pairing, temp, PairingUtils.PairingGroupType.Zr).getImmutable();

        Element K_rj;
        Element K_sj;
        ArrayList<byte[]> As = new ArrayList<>();

        Element h2_alpha = PairingUtils.MapByteArrayToGroup(pairing, alpha.toBytes(), PairingUtils.PairingGroupType.G1).getImmutable();
        for (int i = 0; i < S.size(); i++) {
            PK_R pk_r = S.get(i);
            K_rj = pk_r.D_1.mul(pk_r.D_2.powZn(alpha)).powZn(omega).getImmutable();
            Element D_3 = pk_r.D_3.getImmutable();
            K_sj = pairing.pairing(h2_alpha.powZn(sk_s), D_3).getImmutable();
            byte[] temp1 = PairingUtils.Xor(m, K_rj.toBytes());
            byte[] Aj = PairingUtils.Xor(temp1, K_sj.toBytes());
            byte[] shortAj = CompressionUtils.compress(Aj);
            As.add(shortAj);
        }

        //DS.Sign
        CTParam ctParam = new CTParam(u_1, u_2, As);
        byte[] ctParamByte = PairingUtils.SerCipherParameter(ctParam);
        signer.init(true, ssk);
        signer.update(ctParamByte, 0, ctParamByte.length);
        byte[] signature = signer.generateSignature();
        ANOBMECT C = new ANOBMECT(svk, u_1, u_2, As, signature);

        return C;

    }

    public byte[] Decrypt(SK_R sk_r, Element pk_s, ANOBMECT C) throws IOException {
        //DS.verify
        CTParam ctParam = new CTParam(C.u_1, C.u_2, C.As);
        byte[] ctParamByte = PairingUtils.SerCipherParameter(ctParam);
        signer.init(false, C.svk);
        signer.update(ctParamByte, 0, ctParamByte.length);
        if (!signer.verifySignature(C.signature)) {
            System.out.println("cannot verify valid signature, test abort...");
            System.exit(0);
        }

        byte[] temp1 = concatenateBytes(C.u_1, C.u_2, C.svk);
        Element alpha = PairingUtils.MapByteArrayToGroup(pairing, temp1, PairingUtils.PairingGroupType.Zr).getImmutable();
        Element h2_alpha = PairingUtils.MapByteArrayToGroup(pairing, alpha.toBytes(), PairingUtils.PairingGroupType.G1).getImmutable();
        Element K_r = C.u_1.powZn(sk_r.x_1.add(alpha.mulZn(sk_r.y_1))).mul(C.u_2.powZn(sk_r.x_2.add(alpha.mulZn(sk_r.y_2)))).getImmutable();
        Element K_s = pairing.pairing(h2_alpha.powZn(sk_r.o), pk_s).getImmutable();

        byte[] shortA = C.As.get(0);
        byte[] longA = CompressionUtils.decompress(shortA);

        byte[] temp2 = PairingUtils.Xor(longA, K_r.toBytes());
        byte[] temp = PairingUtils.Xor(temp2, K_s.toBytes());
        byte[] m = getFirstNBytes(temp, m_len);
        return m;
    }


    public static void main(String[] args) throws CryptoException, IOException {
        Pairing pairing = PairingFactory.getPairing("params/a_80_256.properties");
        Element g_1 = pairing.getG1().newRandomElement().getImmutable();
        Element g_2 = pairing.getG1().newRandomElement().getImmutable();
        ANOBME BME = new ANOBME();
        BME.Setup(pairing, g_1, g_2);

        SKPair skPair = BME.SKGen();
        ArrayList<RKPair> rkPair = new ArrayList<>();
        ArrayList<PK_R> S = new ArrayList<>();
        for (int i = 0; i <10; i++) {
            RKPair rk = BME.RKGen();
            rkPair.add(rk);
            S.add(rk.pk_r);
        }

//        String m = "malicious harassment information";
        String m = "messagemessagemessagemessagemessagemessage";
        BME.m_len = m.length();

        System.out.println("m:" + m);
//        System.out.println("m length:" + m.length());

        ANOBMECT C = BME.Encrypt(skPair.pk_s, skPair.sk_s, S, m.getBytes());

        RKPair rkPair1 = rkPair.get(0);
        byte[] mPrime = BME.Decrypt(rkPair1.sk_r, skPair.pk_s, C);
        System.out.println("mPrime:" + new String(mPrime));
    }



    public static byte[] locateA(ArrayList<Hint_c> hint_cs, Element[] Q) {
        for (Hint_c hint_c: hint_cs){
            if (hint_c.Q[0].isEqual(Q[0])){
                return hint_c.A;
            }
        }
        System.out.println("not find, return null");
        return null;
    }

    public static byte[] getFirstNBytes(byte[] array, int n) {
        if (n < 0 || n > array.length) {
            throw new IllegalArgumentException("n must be between 0 and the length of the array");
        }
        byte[] result = new byte[n];
        System.arraycopy(array, 0, result, 0, n);
        return result;
    }

    public byte[] concatenateBytes(Element u_1, Element u_2, PairingKeySerParameter svk){
        // 获取各元素的字节表示
        byte[] u1Bytes = u_1.toBytes();
        byte[] u2Bytes = u_2.toBytes();
        byte[] svkBytes = svk.toString().getBytes();

        int totalLength = u1Bytes.length + u2Bytes.length + svkBytes.length;

        byte[] combinedBytes = new byte[totalLength];

        // 合并字节数组
        System.arraycopy(u1Bytes, 0, combinedBytes, 0, u1Bytes.length);
        System.arraycopy(u2Bytes, 0, combinedBytes, u1Bytes.length, u2Bytes.length);
        System.arraycopy(svkBytes, 0, combinedBytes, u1Bytes.length + u2Bytes.length, svkBytes.length);

        // 返回合并后的字节数组
        return combinedBytes;
    }

    private void SignTest() throws CryptoException {
        //KeyGen
        PairingKeySerPair keyPair = this.asymmetricKeySerPairGenerator.generateKeyPair();
        PairingKeySerParameter publicKey = keyPair.getPublic();
        PairingKeySerParameter secretKey = keyPair.getPrivate();

        System.out.println("Test signer functionality");
        try {
            //signature
            byte[] message = "Message".getBytes();
            signer.init(true, secretKey);
            signer.update(message, 0, message.length);
            byte[] signature = signer.generateSignature();
            System.out.println("Signature length = " + signature.length);

            //verify
            signer.init(false, publicKey);
            signer.update(message, 0, message.length);
            if (!signer.verifySignature(signature)) {
                System.out.println("cannot verify valid signature, test abort...");
                System.exit(0);
            }

        } catch (CryptoException e) {
            e.printStackTrace();
        }
        System.out.println("Pairing signer functionality test pass.");
    }

}
