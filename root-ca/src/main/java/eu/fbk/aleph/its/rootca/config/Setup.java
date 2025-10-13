package eu.fbk.aleph.its.rootca.config;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Startup
@Singleton
public class Setup {

    private static final Logger LOGGER = Logger.getLogger(Setup.class);

    private final static int SWEDEN = 752;
    protected static KeyPair rootCASigningKeys;
    protected static KeyPair rootCAEncryptionKeys;
    protected static EtsiTs103097Certificate rootCACertificate;

    @PostConstruct
    public void init() throws BadArgumentException, NoSuchAlgorithmException, IOException, SignatureException, NoSuchProviderException, BadCredentialsException, InvalidKeyException {

        Ieee1609Dot2CryptoManager cryptoManager = new DefaultCryptoManager();
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        ETSIAuthorityCertGenerator authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager);

        rootCASigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        rootCAEncryptionKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);

        ValidityPeriod rootCAValidityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, 45);
        List<Integer> countries = new ArrayList<>();
        countries.add(SWEDEN);
        GeographicRegion region = GeographicRegion.generateRegionForCountrys(countries);

        rootCACertificate = authorityCertGenerator.genRootCA("testrootca.test.com", // caName
                rootCAValidityPeriod, // ValidityPeriod
                region,             // GeographicRegion
                3,                  // minChainDepth
                -1,                 // chainDepthRange
                Hex.decode("0138"), // cTLServiceSpecificPermissions, 2 octets
                Signature.SignatureChoices.ecdsaNistP256Signature, // signingPublicKeyAlgorithm
                rootCASigningKeys.getPublic(),  // signPublicKey
                rootCASigningKeys.getPrivate(), // signPrivateKey
                SymmAlgorithm.aes128Ccm,          // symmAlgorithm
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                rootCAEncryptionKeys.getPublic()); // encPublicKey

        LOGGER.info("Root CA: " + rootCACertificate.toString());
        LOGGER.info("Encoded: " + Hex.toHexString(rootCACertificate.getEncoded()));
    }

    public static EtsiTs103097Certificate getRootCACertificate() {
        return rootCACertificate;
    }

    public static KeyPair getRootCASigningKeys() {
        return rootCASigningKeys;
    }

    public static KeyPair getRootCAEncryptionKeys() {
        return rootCAEncryptionKeys;
    }
}
