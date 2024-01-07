package io.kiwimec.nist.drbg;

import io.kiwimec.nist.util.Status;
import io.kiwimec.nist.util.Tuple3;

//TODO: should be abstract or interface.
public class Algorithm extends State {

    // These are determined by the algorithm design and implementation.
    public final int highest_supported_security_strength;
    public final int max_number_of_bits_per_request;
    public final int max_personalization_string_length;
    public final boolean prediction_resistance_flag;
    public final int max_additional_input_length;

    // TODO: refactor to correct sizes for the implemented algorithm.
    public Algorithm() {
        highest_supported_security_strength = 256;
        max_number_of_bits_per_request = 256;
        max_personalization_string_length = 256;
        prediction_resistance_flag = true;
        max_additional_input_length = 256;
    }

    public State Instantiate_algorithm(byte[] entropy_input, String nonce, 
            String personalization_string, int security_strength) {

        return this;
    }

    public Algorithm Reseed_algorithm(
        State internal_state, byte[] entropy_input, String additional_input) {

            return this;
        }

    public Tuple3<Status, byte[], State> Generate_algorithm(State working_state, 
        int requested_number_of_bits, String additional_input) {
            
        return null;
    }
}