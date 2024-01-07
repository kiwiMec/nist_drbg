package io.kiwimec.nist.drbg;

import java.util.UUID;

public class State { 

    public final String handle = UUID.randomUUID().toString(); 
    public boolean prediction_resistance_flag = false;
    public boolean reseed_required_flag = false;
    public int security_strength = 0;
}
