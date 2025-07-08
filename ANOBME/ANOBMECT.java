package com.encryption.BME.ANOBME;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;
import java.util.ArrayList;

@Getter
@Setter

public class ANOBMECT implements Serializable, CipherParameters {
    public transient PairingKeySerParameter svk;
    public transient Element u_1;
    public byte[] u1Byte;
    public transient Element u_2;
    public byte[] u2Byte;
    public ArrayList<byte[]> As;
    public byte[] signature;

    public ANOBMECT(PairingKeySerParameter svk, Element u_1, Element u_2, ArrayList<byte[]> As, byte[] signature) {
        this.svk = svk;
        this.u_1 = u_1;
        this.u1Byte = u_1.toBytes();
        this.u_2 = u_2;
        this.u2Byte = u_2.toBytes();
        this.As = As;
        this.signature = signature;
    }



}
