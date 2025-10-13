package eu.fbk.aleph.its.domain.authorization;

import eu.fbk.aleph.its.utils.constant.ConfigConstants;
import eu.fbk.aleph.its.config.Setup;
import eu.fbk.aleph.its.domain.enrollment.EnrollmentCredentials;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.util.Arrays;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.etsits102941.v131.DecryptionFailedException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageParsingException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageProcessingException;
import org.certificateservices.custom.c2x.etsits102941.v131.SignatureVerificationException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.SharedAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateFormat;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.PublicKeys;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.PreSharedKeyReceiver;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.jboss.logging.Logger;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.DENBasicService;

public class AuthorizationCredentials {
    private static final Logger LOGGER = Logger.getLogger(Setup.class);
    private final SecureRandom secureRandom = new SecureRandom();
    private final EtsiTs103097Certificate authorizationTicket;
    private final KeyPair authTicketSignKeys;
    private final KeyPair authTicketEncKeys;

    private static final int SWEDEN = 752;

    public AuthorizationCredentials() throws Exception {

        Ieee1609Dot2CryptoManager cryptoManager = Setup.getCryptoManager();
        ETSITS102941MessagesCaGenerator messagesCaGenerator = Setup.getMessagesCaGenerator();

        EnrollmentCredentials enrollmentCredentials = Setup.getEnrollmentCredentials();

        authTicketSignKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        authTicketEncKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);

        try (Client client = ClientBuilder.newClient()) {
            PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(
                    Setup.getSignAlg(),
                    authTicketSignKeys.getPublic(),
                    SymmAlgorithm.aes128Ccm,
                    Setup.getEncAlg(),
                    authTicketEncKeys.getPublic()
            );
            byte[] hmacKey = genHmacKey();
            SharedAtRequest sharedAtRequest = genSharedAtRequest(publicKeys, hmacKey);

            EncryptResult authRequestMessageResult = messagesCaGenerator.genAuthorizationRequestMessage(
                    new Time64(new Date()), // generation Time
                    publicKeys,
                    hmacKey,
                    sharedAtRequest,
                    Setup.getEnrollmentCAChain(), // Certificate chain of enrolment credential to sign outer message to AA
                    enrollmentCredentials.getEnrollmentCredentialSigningKeys().getPrivate(), // Private key used to sign message.
                    authTicketSignKeys.getPublic(), //The public key of the auth ticket, used to create POP, null if no POP should be generated.
                    authTicketSignKeys.getPrivate(), // The private key of the auth ticket, used to create POP, null if no POP should be generated.
                    Setup.getAuthorizationAuthorityCertificate(), // The AA certificate to encrypt outer message to.
                    enrollmentCredentials.getEnrollmentCertificate(), // Encrypt inner ecSignature with given certificate, required if withPrivacy is true.
                    true // Encrypt the inner ecSignature message sent to EA
            );
            EtsiTs103097DataEncryptedUnicast authRequestMessage = (EtsiTs103097DataEncryptedUnicast) authRequestMessageResult.getEncryptedData();
            byte[] encodedMessage = authRequestMessage.getEncoded();

            Response response = client.target(ConfigConstants.DEFAULT_AUTHORIZATION_URL)
                    .request(MediaType.TEXT_PLAIN)
                    .post(Entity.entity(encodedMessage, MediaType.TEXT_PLAIN));
            authorizationTicket = handleResponse(response, authRequestMessageResult);

            if (authorizationTicket != null) {
                LOGGER.info("Authorization Ticket obtained successfully: " + authorizationTicket);
            }
        }
    }

    private EtsiTs103097Certificate handleResponse(Response response, EncryptResult authRequestMessageResult) throws BadArgumentException, IOException, GeneralSecurityException, MessageParsingException, SignatureVerificationException, DecryptionFailedException, MessageProcessingException {
        EtsiTs103097Certificate extractedCert = null;
        if (response.getStatus() == 200) {
            byte[] authorizationResponseMessageEncoded = response.readEntity(byte[].class);
            EtsiTs103097DataEncryptedUnicast authorizationResponseMessage = new EtsiTs103097DataEncryptedUnicast(authorizationResponseMessageEncoded);

            Map<HashedId8, Receiver> authTicketSharedKeyReceivers =
                    Setup.getMessagesCaGenerator().buildRecieverStore(
                            new Receiver[] {
                                    new PreSharedKeyReceiver(
                                            SymmAlgorithm.aes128Ccm,
                                            authRequestMessageResult.getSecretKey()
                                    )
                            });
            CertStore authCACertStore = Setup.getMessagesCaGenerator().buildCertStore(Setup.getAuthorizationCAChain());

            VerifyResult<InnerAtResponse> authResponseResult =
                    Setup.getMessagesCaGenerator().decryptAndVerifyAuthorizationResponseMessage(
                            authorizationResponseMessage,
                            authCACertStore, // certificate store containing certificates for auth cert.
                            Setup.getTrustStore(),
                            authTicketSharedKeyReceivers
                    );
            extractedCert = authResponseResult.getValue().getCertificate();

        } else {
            String errorResponse = response.readEntity(String.class);
            LOGGER.error("Failed to retrieve Authorization Ticket. Status: " + response.getStatus());
            LOGGER.error("Error response: " + errorResponse);
        }
        return extractedCert;
    }

    private SharedAtRequest genSharedAtRequest(PublicKeys publicKeys, byte[] hmacKey) throws Exception {
        HashedId8 eaId = new HashedId8(Setup.getCryptoManager().digest(Setup.getEnrollmentAuthorityCertificate().getEncoded(), HashAlgorithm.sha256));
        byte[] keyTag = genKeyTag(hmacKey,publicKeys.getVerificationKey(),publicKeys.getEncryptionKey());
        PsidSsp appPermDenm = new PsidSsp(DENBasicService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.bitmapSsp, new BitmapSsp(new byte[]{0x01, 0x5F, 0x07, 0x25})));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermDenm};

        CertificateSubjectAttributes certificateSubjectAttributes =
                genCertificateSubjectAttributes(
                        "obu.example.com", // Hostname
                        new ValidityPeriod( // Define requested validity period
                                new SimpleDateFormat("yyyyMMdd HH:mm:ss").parse("20181202 12:12:21"), // Start time
                                Duration.DurationChoices.years, 25 // Duration
                        ),
                        GeographicRegion.generateRegionForCountrys(List.of(SWEDEN)),
                        new SubjectAssurance(2, 0),
                        appPermissions,
                        null
                );

        return new SharedAtRequest(eaId, keyTag, CertificateFormat.TS103097C131, certificateSubjectAttributes);
    }

    private CertificateSubjectAttributes genCertificateSubjectAttributes(
            String hostname,
            ValidityPeriod validityPeriod,
            GeographicRegion region,
            SubjectAssurance assuranceLevel,
            PsidSsp[] appPermissions,
            PsidGroupPermissions[] certIssuePermissions
    ) throws Exception {

        return new CertificateSubjectAttributes(
                (hostname != null ? new CertificateId(new Hostname(hostname)): new CertificateId()),
                validityPeriod,
                region,
                assuranceLevel,
                new SequenceOfPsidSsp(appPermissions),
                (certIssuePermissions != null ?
                new SequenceOfPsidGroupPermissions(certIssuePermissions) : null)
        );
    }

    private byte[] genKeyTag(byte[] hmacKey, PublicVerificationKey verificationKey, PublicEncryptionKey encryptionKey) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream daos = new DataOutputStream(baos);
        daos.write(hmacKey);
        verificationKey.encode(daos);
        if(encryptionKey != null){
            encryptionKey.encode(daos);
        }
        daos.close();
        byte[] data = baos.toByteArray();
        Digest digest = new SHA256Digest();
        HMac hMac = new HMac(digest);
        hMac.update(data,0,data.length);

        byte[] macData = new byte[hMac.getMacSize()];
        hMac.doFinal(data,0);

        return Arrays.copyOf(macData,16);
    }

    private byte[] genHmacKey(){
        byte[] hmacKey = new byte[32];
        secureRandom.nextBytes(hmacKey);
        return hmacKey;
    }

    public EtsiTs103097Certificate getAuthorizationTicket() {
        return authorizationTicket;
    }

    public KeyPair getAuthTicketSignKeys() {
        return authTicketSignKeys;
    }
    public KeyPair getAuthTicketEncKeys() {
        return authTicketEncKeys;
    }
}