package de.androidcrypto.nfcemvkeytest.keys;

import de.androidcrypto.nfcemvkeytest.utils.EmvParsingException;
import de.androidcrypto.nfcemvkeytest.utils.EmvUtils;
import de.androidcrypto.nfcemvkeytest.utils.jackson.BigIntegerHexDeserializer;
import de.androidcrypto.nfcemvkeytest.utils.jackson.BigIntegerHexSerializer;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Getter;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

/**
 * @author Johannes Zweng (johannes@zweng.at) on 23.10.17.
 */
public abstract class EmvPublicKey implements RSAPublicKey {

    static final String ALGORITHM_RSA = "RSA";
    static final String FORMAT_ISSUER_PUBKEY = "IssuerPublicKeyCertificate";
    static final String FORMAT_CA_MODULUS = "CA-Certificate-Public-Modulus";
    static final String HASH_ALGORITHM_SHA1 = "SHA-1";

    @Getter
    @JsonSerialize(using = BigIntegerHexSerializer.class)
    @JsonDeserialize(using = BigIntegerHexDeserializer.class)
    private final BigInteger publicExponent;

    @Override
    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    @Getter
    @JsonSerialize(using = BigIntegerHexSerializer.class)
    @JsonDeserialize(using = BigIntegerHexDeserializer.class)
    private final BigInteger modulus;

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    @Getter
    @JsonIgnore
    private final byte[] encoded;

    //@Override
    //public byte[] getEncoded() {
    //    return encoded;
    //}

    @Getter
    private final Date expirationDate;

    /**
     * Constructor
     *
     * @param publicExponent
     * @param modulus
     * @param encodedBytes
     * @param expirationDate
     */
    EmvPublicKey(BigInteger publicExponent, BigInteger modulus, byte[] encodedBytes, Date expirationDate) {
        this.publicExponent = publicExponent;
        this.modulus = modulus;
        this.encoded = encodedBytes;
        this.expirationDate = expirationDate;
    }

    @Override
    public abstract String getAlgorithm();

    @Override
    public abstract String getFormat();

    @JsonIgnore
    public byte[] getModulusBytes() throws EmvParsingException {
        if (getModulus() == null) {
            System.out.println("*** EmvPublicKey.getModulusBytes = NULL");
        } else {
            System.out.println("*** EmvPublicKey.getModulusBytes: " + getModulus());
        }
        return EmvUtils.getUnsignedBytes(getModulus());
    }

    @JsonIgnore
    public byte[] getPublicExponentBytes() throws EmvParsingException {
        return EmvUtils.getUnsignedBytes(getPublicExponent());
    }

    public Date getExpirationDate() {
        return expirationDate;
    }
}
