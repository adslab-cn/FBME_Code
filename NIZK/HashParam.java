package com.encryption.BME.NIZK;

import it.unisa.dia.gas.jpbc.Element;

public class HashParam {
    public byte[][] HashBytes;

    public HashParam(Element v_1, Element v_2, Element k_J, Element pk_s, Element pk_J, Element a, Element a_1, Element a_2, Element a_3){
        HashBytes = new byte[9][];
        HashBytes[0] = v_1.toBytes();
        HashBytes[1] = v_2.toBytes();
        HashBytes[2] = k_J.toBytes();
        HashBytes[3] = pk_s.toBytes();
        HashBytes[4] = pk_J.toBytes();
        HashBytes[5] = a.toBytes();
        HashBytes[6] = a_1.toBytes();
        HashBytes[7] = a_2.toBytes();
        HashBytes[8] = a_3.toBytes();
    }

    public int getlen(){
        int len = HashBytes[0].length;
        for(int i=1;i<HashBytes.length;i++){
            len+=HashBytes[i].length;
        }
        return len;
    }

    public byte[] getHashBytes() {
        int len = getlen();
        byte[] res = new byte[len];
        int strat = 0;
        for (int i = 0; i < HashBytes.length; i++) {
            System.arraycopy(HashBytes[i], 0, res, strat, HashBytes[i].length);
            strat += HashBytes[i].length;
        }
        return res;
    }

}
