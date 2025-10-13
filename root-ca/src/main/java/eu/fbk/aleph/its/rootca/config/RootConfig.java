package eu.fbk.aleph.its.rootca.config;

import eu.fbk.aleph.its.rootca.api.RootCert;
import eu.fbk.aleph.its.rootca.api.SignCaCert;
import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

import java.util.HashSet;
import java.util.Set;

@ApplicationPath("/api")
public class RootConfig extends Application {
    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new HashSet<>();
        classes.add(RootCert.class);
        classes.add(SignCaCert.class);
        return classes;
    }
}