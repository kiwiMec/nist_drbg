package io.kiwimec.nist.drbg;

import java.util.UUID;

//TDO: should be abstract or interface
public class DrbgAlgorithm {

    public final int highest_supported_security_strength;
    public final int max_personalization_string_length;
    public final String handle; 

    public DrbgAlgorithm() {
            highest_supported_security_strength = 256;
            max_personalization_string_length = 256;
            handle = UUID.randomUUID().toString();
    }

    public DrbgAlgorithm Instantiate_algorithm(byte[] entropy_input, String nonce, 
            String personalization_string, int security_strength) {

        return this;
    }
}