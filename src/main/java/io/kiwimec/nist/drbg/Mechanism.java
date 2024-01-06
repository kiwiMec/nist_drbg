package io.kiwimec.nist.drbg;

import io.kiwimec.util.Status;
import io.kiwimec.util.Tuple2;

public class Mechanism {

    // components
    private EntropySource entropy_source;
    private NonceSource nonce_source;
    private DrbgAlgorithm drbg_algorithm;
    private DrbgAlgorithm internal_state;

    private int security_strength;

    public Mechanism(EntropySource entropy_source, NonceSource nonce_source, 
            DrbgAlgorithm drbg_algorithm) {

        this.entropy_source = entropy_source;
        this.nonce_source = nonce_source;
        this.drbg_algorithm = drbg_algorithm;

        // TODO: set configuration
        // TODO: add health check
    }
    
    public Tuple2<Status, String> Instantiate(
        int requested_instantiation_security_strength, 
        boolean prediction_resistance_flag, 
        String personalization_string) {

        // Comment: Check the validity of the input parameters.

        // 1. If requested_instantiation_security_strength > 
        // highest_supported_security_strength, then return (ERROR_FLAG, Invalid).
        if (requested_instantiation_security_strength > 
                drbg_algorithm.highest_supported_security_strength)
            return new Tuple2<Status,String>(Status.ERROR_FLAG, "Invalid");
        // 2. If prediction_resistance_flag is set, and prediction resistance is not supported, 
        // then return (ERROR_FLAG, Invalid).
        if (prediction_resistance_flag == true)
            return new Tuple2<Status,String>(Status.ERROR_FLAG, "Invalid");
        // 3. If the length of the personalization_string > max_personalization_string_length, 
        // return (ERROR_FLAG, Invalid).
        if (personalization_string.length() > drbg_algorithm.max_personalization_string_length)
            return new Tuple2<Status,String>(Status.ERROR_FLAG, "Invalid");

        // 4. Set security_strength to the lowest security strength greater than or equal to 
        // requested_instantiation_security_strength from the set {112, 128, 192, 256}.
        if(requested_instantiation_security_strength > 192) {
            security_strength = 256;
        } else if (requested_instantiation_security_strength > 128) {
            security_strength = 192;
        } else if (requested_instantiation_security_strength > 112) {
            security_strength = 128;
        } else {
            security_strength = 112;
        }

        // 5. Null step. Comment: This null step replaces a step from the original version of 
        // SP 800-90 without changing the step numbers.

        // 6. (status, entropy_input) = Get_entropy_input (security_strength, min_length, 
        // max_length, prediction_resistance_request).
        Tuple2<Status, byte[]> entropy_input = entropy_source.Get_entropy_input(
            requested_instantiation_security_strength, 
            requested_instantiation_security_strength, 
            requested_instantiation_security_strength, 
            prediction_resistance_flag);

        // 7. If (status ≠ SUCCESS), return (status, Invalid).
        if(entropy_input.first != Status.SUCCESS)
            return new Tuple2<Status, String>(Status.ERROR_FLAG, "Invalid");

        // 8. Obtain a nonce. Comment: This step shall include any appropriate checks on the 
        // acceptability of the nonce. See Section 8.6.7.
        //
        // Note the prototype for the nonce call is not provided.
        String nonce = nonce_source.Get_nonce();

        // 9. initial_working_state = Instantiate_algorithm (entropy_input, nonce, 
        // personalization_string, security_strength).
        DrbgAlgorithm initial_working_state = drbg_algorithm.Instantiate_algorithm(entropy_input.second, nonce, 
            personalization_string, security_strength);

        // 10. Get a state_handle for a currently empty internal state. If an empty internal 
        // state cannot be found, return (ERROR_FLAG, Invalid).
        if(initial_working_state.handle == null)
            return new Tuple2<Status, String>(Status.ERROR_FLAG, "Invalid");

        // 11. Set the internal state for the new instantiation (e.g., as indicated by 
        // state_handle) to the initial values for the internal state (i.e., set the working_state
        // to the values returned as initial_working_state in step 9) and any other values 
        // required for the working_state (see Section 10), and set the administrative information 
        // to the appropriate values (e.g., the values of security_strength and the 
        // prediction_resistance_flag).
        internal_state = initial_working_state;

        // 12. Return (SUCCESS, state_handle).
        return new Tuple2<Status,String>(Status.SUCCESS, internal_state.handle);
    }
}
