package com.encryption.BME.ANOBME;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.utils.Timer;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import jxl.Workbook;
import jxl.write.Label;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;
import jxl.write.WriteException;
import org.bouncycastle.crypto.CryptoException;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

public class ANOBMETest extends TestCase {
    public static final String default_path = "benchmarks/encryption/ANOBME/";
    Pairing pairing = PairingFactory.getPairing("params/ss768.properties");
    public ANOBME engine = new ANOBME();
    public double[] timeAll = new double[4];
    public double[] storageAll = new double[3];

    void round_one(int num_S, String m) throws IOException, CryptoException {
        Timer timer = new Timer(10);
        Element g_1 = pairing.getG1().newRandomElement().getImmutable();
        Element g_2 = pairing.getG1().newRandomElement().getImmutable();
        engine.Setup(pairing, g_1, g_2);

        timer.start(0);
        SKPair skPair = engine.SKGen();
        timeAll[0] += timer.stop(0);
        storageAll[0] = PairingUtils.SerCipherParameter(skPair).length;

        timer.start(0);
        RKPair rk1 = engine.RKGen();
        timeAll[1] += timer.stop(0);
        storageAll[1] = PairingUtils.SerCipherParameter(rk1).length;

        ArrayList<RKPair> rkPair = new ArrayList<>();
        ArrayList<PK_R> S = new ArrayList<>();
        for (int l = 0; l < num_S; l++) {
            RKPair rk = engine.RKGen();
            rkPair.add(rk);
            S.add(rk.pk_r);
        }

        timer.start(0);
        ANOBMECT C = engine.Encrypt(skPair.pk_s, skPair.sk_s, S, m.getBytes());
        timeAll[2] += timer.stop(0);
        storageAll[2] = PairingUtils.SerCipherParameter(C).length;

        RKPair rkPair1 = rkPair.get(1);
        timer.start(0);
        byte[] mPrime = engine.Decrypt(rkPair1.sk_r, skPair.pk_s, C);
        timeAll[3] += timer.stop(0);
    }

    public void testANOBMEPerformance() throws IOException, WriteException, CryptoException {
        File file = new File(default_path + "ANOBME_96bit_240708.xls");
        //创建文件
        file.createNewFile();
        //创建工作薄
        WritableWorkbook workbook = Workbook.createWorkbook(file);
        //创建sheet
        WritableSheet sheetC = workbook.createSheet("ANOBME_Compute", 0);
        WritableSheet sheetS = workbook.createSheet("ANOBME_Storage", 1);
        int index = 1;
        int index_head = 1;

        int t=10;
        int max = 50;
        for (int i = 10; i <= max; i = i + 10) {

            for (int k = 0; k < timeAll.length; k++) {
                timeAll[k] = 0;
            }
            for (int k = 0; k < storageAll.length; k++) {
                storageAll[k] = 0;
            }

            for (int j = 0; j < t; j++) {
                round_one(i, "malicious message");
            }

            Label label_C = new Label(index_head, 0, String.valueOf(i));
            sheetC.addCell(label_C);
            for (int l = 0; l < timeAll.length; l++) {
                Label label = new Label(index, l+1, String.valueOf(timeAll[l] / t));
                sheetC.addCell(label);
            }
            Label label_S = new Label(index_head, 0, String.valueOf(i));
            sheetS.addCell(label_S);
            for (int k = 0; k < storageAll.length; k++) {
                Label label = new Label(index, k + 1, String.valueOf(storageAll[k]));
                sheetS.addCell(label);
            }
            index++;
            index_head++;
        }

        workbook.write();
        workbook.close();

    }
}
