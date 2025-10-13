package eu.fbk.aleph.its;

import com.ibm.jgroupsig.MemKey;
import com.ibm.jgroupsig.PS16;
import eu.fbk.aleph.its.config.Setup;
import eu.fbk.aleph.its.domain.authorization.AuthorizationCredentials;
import eu.fbk.aleph.its.domain.denm.transmission.groupsig.DenmGenerator;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.io.IOException;
import java.security.SignatureException;
import java.util.logging.Logger;

public class Main {
    static Logger logger = Logger.getLogger(Main.class.getName());
    //private DenmGenerator generator;
    //private AuthorizationCredentials authorizationCredentials;
    //private byte[] payload;

    public static void main(String[] args) throws Exception {

        /*
        new Setup().init();
        AuthorizationCredentials authorizationCredentials = Setup.getAuthorizationCredentials();
        byte[] payload = Hex.decode("010203040506");
        eu.fbk.aleph.its.domain.denm.transmission.etsi103097.DenmGenerator generatorEtsi =
                new eu.fbk.aleph.its.domain.denm.transmission.etsi103097.DenmGenerator(authorizationCredentials, payload);
        EtsiTs103097DataSigned messageEtsi = generatorEtsi.genDENMessage();
        System.out.println("Etsi message is " + messageEtsi);
        System.out.println("ETSI message generated, length: " + messageEtsi.getEncoded().length);
        Setup setup = new Setup();
        setup.init();
        PS16 userGroup = setup.getUserGroup();
        MemKey memKey = setup.getUserMemKey();
        eu.fbk.aleph.its.domain.denm.transmission.groupsig.DenmGenerator generatorGroupsig =
                new eu.fbk.aleph.its.domain.denm.transmission.groupsig.DenmGenerator(
                        userGroup,
                        memKey,
                        payload
                );
        EtsiTs103097DataSigned messageGroupsig = generatorGroupsig.genDENMessage();
        System.out.println("Groupsig message is " + messageGroupsig);
        System.out.println("Groupsig message generated, length: " + messageGroupsig.getEncoded().length);
        */
/*
        DenmGenerator generator;

        Setup setup = new Setup();
        setup.init();
        PS16 userGroup = setup.getUserGroup();
        MemKey memKey = setup.getUserMemKey();
        byte[] payload = Hex.decode("010203040506");
        generator = new DenmGenerator(
                userGroup,
                memKey,
                payload
        );
        EtsiTs103097DataSigned message = generator.genDENMessage();
        System.out.println(message.toString());
        */

        try {
            Options opt = new OptionsBuilder()
                    .include(eu.fbk.aleph.its.benchmark.etsi103097.DenmGeneratorBenchmark.class.getSimpleName())
                    .include(eu.fbk.aleph.its.benchmark.etsi103097.DenmReceiverBenchmark.class.getSimpleName())
                    .include(eu.fbk.aleph.its.benchmark.groupsig.DenmGeneratorBenchmark.class.getSimpleName())
                    .include(eu.fbk.aleph.its.benchmark.groupsig.DenmReceiverBenchmark.class.getSimpleName())
                    .jvmArgs("-Xms2G", "-Xmx2G")
                    .resultFormat(org.openjdk.jmh.results.format.ResultFormatType.JSON)
                    .result("/app/results/benchmark-results.json")
                    .build();

            new Runner(opt).run().forEach(r ->
                    logger.info("Benchmark result: " + r.getPrimaryResult().getScore() + " " + r.getPrimaryResult().getScoreUnit())
            );

            logger.info("Benchmark results saved to results/benchmark-results.json");
        } catch (Exception e) {
            logger.severe("Failed to run benchmark: " + e.getMessage());
            System.exit(1);
        }

    }


}