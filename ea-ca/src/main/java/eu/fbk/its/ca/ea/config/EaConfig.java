package eu.fbk.its.ca.ea.config;

import eu.fbk.its.ca.ea.api.*;
import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

import java.util.HashSet;
import java.util.Set;

@ApplicationPath("/api")
public class EaConfig extends Application {
    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new HashSet<>();
        classes.add(Resource.class);
        classes.add(EaCertificate.class);
        classes.add(EnrollmentCertificate.class);
        classes.add(EnrollmentVerification.class);
        classes.add(AuthorizationValidation.class);
        return classes;
    }
}