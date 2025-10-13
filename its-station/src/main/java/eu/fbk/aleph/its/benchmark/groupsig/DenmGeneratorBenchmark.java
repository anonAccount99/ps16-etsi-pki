package eu.fbk.aleph.its.benchmark.groupsig;

import com.ibm.jgroupsig.MemKey;
import com.ibm.jgroupsig.PS16;
import eu.fbk.aleph.its.config.Setup;
import eu.fbk.aleph.its.domain.denm.transmission.groupsig.DenmGenerator;
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

    @org.openjdk.jmh.annotations.Setup(Level.Trial)
    public void setUp() throws Exception {
        Setup setup = new Setup();
        setup.init();
        PS16 userGroup = setup.getUserGroup();
        MemKey memKey = setup.getUserMemKey();
        byte[] payload = Hex.decode("010203040506");
        this.generator = new DenmGenerator(
                userGroup,
                memKey,
                payload
        );
    }

    @Benchmark
    public void generateMessage(Blackhole bh) throws Exception {
        EtsiTs103097DataSigned message = generator.genDENMessage();
        byte[] encoded = message.getEncoded();
        bh.consume(encoded);
        bh.consume(message);
    }
}