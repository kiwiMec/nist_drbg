package io.kiwimec.nist.drbg;

import java.util.UUID;

public class State {

    // The following are required by the DRBG Mechanism.

    // Identifier for this State instance.
    public final String handle = UUID.randomUUID().toString();
    // Desired default for resistence setting.
    public boolean prediction_resistance_flag = false;
    // Internal reseed indicator.
    public boolean reseed_required_flag = false;
    // Agreed security strength set at initialisation. Required minimum entropy for
    // instantiate and reseed.
    public int security_strength = 0;
}
