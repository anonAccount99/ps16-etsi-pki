package eu.fbk.its.ca.ea.api;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

@Path("/hello-world-ea")
public class Resource {
    @GET
    @Produces("text/plain")
    public String hello() {
        return "Hello, World!";
    }
}