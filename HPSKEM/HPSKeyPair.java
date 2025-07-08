package com.encryption.BME.HPSKEM;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;


@Getter
@Setter
public class HPSKeyPair implements Serializable, CipherParameters {
    public transient Element pk;
    public final byte[] pkByte;
    public transient Element[] sk;
    public final byte[][] skByte;

    public HPSKeyPair(Element pk, Element[] sk) {
        this.pk = pk;
        this.pkByte = pk.toBytes();
        this.sk = sk;
        this.skByte = PairingUtils.GetElementArrayBytes(sk);
    }

}
