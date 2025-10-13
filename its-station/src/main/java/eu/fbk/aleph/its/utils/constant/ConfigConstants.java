package eu.fbk.aleph.its.utils.constant;

public class ConfigConstants {
    public static final String DEFAULT_EA_CA_URL = "http://ea-ca:8080/ea/api";
    public static final String DEFAULT_RA_CA_URL = "http://root-ca:8080/root/api";
    public static final String DEFAULT_AA_CA_URL = "http://aa-ca:8080/aa/api";

    public static final String DEFAULT_ENROLL_URL = DEFAULT_EA_CA_URL + "/enrollment-certificate";
    public static final String DEFAULT_AUTHORIZATION_URL = DEFAULT_AA_CA_URL + "/authorization-ticket";
    public static final String GROUP_AUTHORIZATION_URL = DEFAULT_AA_CA_URL + "/group-membership";
    public static final String GROUP_INTERACTION_URL = DEFAULT_AA_CA_URL + "/group-interaction";

    public static final String DEFAULT_EA_CERTIFICATE_URL = DEFAULT_EA_CA_URL + "/certificate";
    public static final String DEFAULT_RA_CERTIFICATE_URL = DEFAULT_RA_CA_URL + "/certificate";
    public static final String DEFAULT_AA_CERTIFICATE_URL = DEFAULT_AA_CA_URL + "/certificate";
    public static final String TEST_VIN = "0102030405060708";

    public static final int DENM_PORT = 30000;

    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_RESET = "\u001B[0m";
}
