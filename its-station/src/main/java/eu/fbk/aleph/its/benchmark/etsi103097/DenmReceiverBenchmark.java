package eu.fbk.aleph.its.benchmark.etsi103097;

import eu.fbk.aleph.its.config.Setup;
import eu.fbk.aleph.its.domain.authorization.AuthorizationCredentials;
import eu.fbk.aleph.its.domain.denm.transmission.etsi103097.DenmGenerator;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(3)
@Warmup(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 250, time = 1, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class DenmReceiverBenchmark {

    private ETSISecuredDataGenerator securedMessageGenerator;
    private CertStore trustStore;
    private CertStore certStore;
    private EtsiTs103097DataSigned sampleMessage;

    @org.openjdk.jmh.annotations.Setup(Level.Trial)
    public void setUp() throws Exception {
        Setup setup = new Setup();
        setup.init();
        this.securedMessageGenerator = Setup.getSecuredMessageGenerator();
        this.trustStore = Setup.getTrustStore();
        this.certStore = Setup.getAuthTicketCertStore();
        AuthorizationCredentials authorizationCredentials = Setup.getAuthorizationCredentials();
        byte[] payload = Hex.decode("010203040506");
        DenmGenerator generator = new DenmGenerator(
                authorizationCredentials,
                payload
        );
        this.sampleMessage = generator.genDENMessage();
    }

    @Benchmark
    public void verifyMessage(Blackhole bh) throws Exception {
        securedMessageGenerator.verifySignedData(sampleMessage, certStore, trustStore);
        bh.consume(sampleMessage);
    }

}
