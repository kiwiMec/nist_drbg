package io.kiwimec.nist.drbg;

import io.kiwimec.nist.util.Status;
import io.kiwimec.nist.util.Tuple3;

public abstract class Algorithm {

    // These are determined by the algorithm design and implementation and set by
    // the implementation constructor. The package scope is appropriate here for the
    // consuming and derivative class access.
    final int highest_supported_security_strength;
    final int max_additional_input_length;
    final int max_number_of_bits_per_request;
    final int max_personalization_string_length;
    final boolean prediction_resistance_flag;

    /**
     * The algorithm is initialised by the specific implementation that extends this
     * class.
     */
    public Algorithm(int highest_supported_security_strength, int max_additional_input_length,
            int max_number_of_bits_per_request, int max_personalization_string_length,
            boolean prediction_resistance_flag) {

        this.highest_supported_security_strength = highest_supported_security_strength;
        this.max_number_of_bits_per_request = max_number_of_bits_per_request;
        this.max_personalization_string_length = max_personalization_string_length;
        this.prediction_resistance_flag = prediction_resistance_flag;
        this.max_additional_input_length = max_additional_input_length;
    }

    /**
     * Initialises the internal working state of the algorithm.
     * 
     * @param entropy_input
     * @param nonce
     * @param personalization_string
     * @param security_strength
     * @return
     */
    public abstract State Instantiate_algorithm(byte[] entropy_input, String nonce,
            String personalization_string, int security_strength);

    /**
     * Reinitises the internal working state of the algorithm, if the algorithm
     * supports it.
     * 
     * @param internal_state
     * @param entropy_input
     * @param additional_input
     * @return
     */
    public abstract State Reseed_algorithm(
            State internal_state, byte[] entropy_input, String additional_input);

    /**
     * Requests <code>requested_number_of_bits</code> of entropy from the algorithm.
     * If the algorithm requires a reseed the <code>response.first</code> will
     * contain <code>Status.RESEED_REQUIRED</code>.
     * 
     * @param working_state
     * @param requested_number_of_bits
     * @param additional_input
     * @return
     */
    public abstract Tuple3<Status, byte[], State> Generate_algorithm(State working_state,
            int requested_number_of_bits, String additional_input);
}