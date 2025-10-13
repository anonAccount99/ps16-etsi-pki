package eu.fbk.aleph.its.benchmark.etsi103097;

import eu.fbk.aleph.its.config.Setup;
import eu.fbk.aleph.its.domain.authorization.AuthorizationCredentials;
import eu.fbk.aleph.its.domain.denm.transmission.etsi103097.DenmGenerator;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(3)
@Warmup(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 250, time = 1, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class DenmGeneratorBenchmark {
    private DenmGenerator generator;
    private AuthorizationCredentials authorizationCredentials;
    private byte[] payload;

    @org.openjdk.jmh.annotations.Setup(Level.Trial)
    public void setUp() throws Exception {
        new Setup().init();
        authorizationCredentials = Setup.getAuthorizationCredentials();
        payload = Hex.decode("010203040506");
        generator = new DenmGenerator(authorizationCredentials, payload);
    }

    @Benchmark
    public void generateMessage(Blackhole bh) throws Exception {
        EtsiTs103097DataSigned message = generator.genDENMessage();
        bh.consume(message.getEncoded());
        bh.consume(message);
    }
}
