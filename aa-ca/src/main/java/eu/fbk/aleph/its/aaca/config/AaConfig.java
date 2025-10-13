package eu.fbk.aleph.its.aaca.config;

import eu.fbk.aleph.its.aaca.api.*;
import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

import java.util.HashSet;
import java.util.Set;

@ApplicationPath("/api")
public class AaConfig extends Application {
    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new HashSet<>();
        classes.add(AuthorizationAuthorityCert.class);
        classes.add(AuthorizationTicket.class);
        classes.add(GroupMembership.class);
        classes.add(GroupInteraction.class);
        return classes;
    }
}