package eu.fbk.aleph.its.rootca.services;

import eu.fbk.aleph.its.rootca.config.Setup;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.dto.RequestCertificateDto;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class CertSig {

    public static EtsiTs103097Certificate generateCA(
            String caName,
            int validityPeriod,
            int region_code,
            int subjectAssuranceLevel,
            int subjectConfidenceLevel,
            String signingPublicKey,
            String encryptionPublicKey
    ) throws Exception {
        Ieee1609Dot2CryptoManager cryptoManager = new DefaultCryptoManager();
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        ETSIAuthorityCertGenerator authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager);

        List<Integer> countries = new ArrayList<Integer>();
        countries.add(region_code);
        GeographicRegion region = GeographicRegion.generateRegionForCountrys(countries);

        ValidityPeriod enrollmentCAValidityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, validityPeriod);

        return authorityCertGenerator.genEnrollmentCA(
                caName, // CA Name
                enrollmentCAValidityPeriod,
                region,  //GeographicRegion
                new SubjectAssurance(subjectAssuranceLevel, subjectConfidenceLevel), // subject assurance (optional)
                Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                RequestCertificateDto.decodePublicKey(signingPublicKey), // signPublicKey, i.e public key in certificate
                Setup.getRootCACertificate(), // signerCertificate
                Setup.getRootCASigningKeys().getPublic(), // signCertificatePublicKey, must be specified separately to support implicit certificates.
                Setup.getRootCASigningKeys().getPrivate(),
                SymmAlgorithm.aes128Ccm, // symmAlgorithm
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                RequestCertificateDto.decodePublicKey(encryptionPublicKey)// encryption public key
        );
    }
}