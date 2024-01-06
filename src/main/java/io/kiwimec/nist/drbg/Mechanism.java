package io.kiwimec.nist.drbg;

import io.kiwimec.nist.source.Entropy;
import io.kiwimec.nist.source.Nonce;
import io.kiwimec.util.Status;
import io.kiwimec.util.Tuple2;

public class Mechanism {

    // components
    private Entropy entropy_source;
    private Nonce nonce_source;
    private Algorithm drbg_algorithm;
    private State internal_state;

    private int security_strength;

    public Mechanism(Entropy entropy_source, Nonce nonce_source, 
            Algorithm drbg_algorithm) {

        this.entropy_source = entropy_source;
        this.nonce_source = nonce_source;
        this.drbg_algorithm = drbg_algorithm;

        // TODO: set configuration
        // TODO: add health check
    }
    
    // p.12 The instantiate function acquires entropy input and may combine it with a nonce and a 
    // personalization string to create a seed from which the initial internal state is created.
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
        if (prediction_resistance_flag && !drbg_algorithm.prediction_resistance_flag)
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
            security_strength, 
            security_strength, 
            security_strength, 
            prediction_resistance_flag);

        // 7. If (status ≠ SUCCESS), return (status, Invalid).
        if(entropy_input.first != Status.SUCCESS)
            return new Tuple2<Status, String>(entropy_input.first, "Invalid");

        // 8. Obtain a nonce. Comment: This step shall include any appropriate checks on the 
        // acceptability of the nonce. See Section 8.6.7.
        //
        // Note the prototype for the nonce call is not provided.
        String nonce = nonce_source.Get_nonce();

        // 9. initial_working_state = Instantiate_algorithm (entropy_input, nonce, 
        // personalization_string, security_strength).
        State initial_working_state = drbg_algorithm.Instantiate_algorithm(entropy_input.second, nonce, 
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

    public Status Reseed_function (String state_handle, boolean prediction_resistance_request, 
            String additional_input) {

        // 1. Using state_handle, obtain the current internal state. If state_handle indicates an 
        // invalid or unused internal state, return (ERROR_FLAG).
        //
        // NOTE a. This state management makes sense in a context where multiple states may 
        // be maintained by a single object. See steps 6. and 7. for use. 
        //
        // NOTE b. No consideration is given to thread, data or memory safety in the specification. 
        // Quite rightly this is left to the implementer to consider given that this is a generic 
        // specification and such things are implementation context dependent and therefore 
        // unbounded in scope. As long as the state get and set are atomic and get creates a copy 
        // of the state reseeding could be done in parallel with generation with minimal 
        // interruption to generation in some circumstances. Here I just use a single state.
        if(internal_state.handle != state_handle)
                return Status.ERROR_FLAG;
        State working_state = internal_state;

        // 2. If prediction_resistance_request is set, and prediction_resistance_flag is not set, 
        // then return (ERROR_FLAG).
        if(prediction_resistance_request && !drbg_algorithm.prediction_resistance_flag)
            return Status.ERROR_FLAG;

        // 3. If the length of the additional_input > max_additional_input_length, 
        // return (ERROR_FLAG).
        if(additional_input.length() > drbg_algorithm.max_additional_input_length)
            return Status.ERROR_FLAG;

        // Comment: Obtain the entropy input.
        // 4. (status, entropy_input) = Get_entropy_input (security_strength, min_length,
        // max_length, prediction_resistance_request).
        Tuple2<Status, byte[]> entropy_input = entropy_source.Get_entropy_input(
            security_strength, 
            security_strength, 
            security_strength, 
            prediction_resistance_request);

        // Comment: status indications other than SUCCESS could be ERROR_FLAG or 
        // CATASTROPHIC_ERROR_FLAG, in which case, the status is returned to the consuming 
        // application to handle. The Get_entropy_input call could return a status of ERROR_FLAG 
        // to indicate that entropy is currently unavailable, and could return 
        // CATASTROPHIC_ERROR_FLAG to indicate that an entropy source failed.
        // 5. If (status ≠ SUCCESS), return (status).
        if(entropy_input.first != Status.SUCCESS)
            return entropy_input.first;

        // Comment: Get the new working_state using the appropriate reseed algorithm in Section 10.
        // 6. new_working_state = Reseed_algorithm (working_state, entropy_input, additional_input).
        Algorithm new_working_state = drbg_algorithm.Reseed_algorithm(
            working_state, entropy_input.second, additional_input);

        // 7. Replace the working_state in the internal state for the DRBG instantiation (e.g., as
        // indicated by state_handle) with the values of new_working_state obtained in step 6. 
        internal_state = new_working_state;

        // 8. Return (SUCCESS).
        return Status.SUCCESS;
    }
}
