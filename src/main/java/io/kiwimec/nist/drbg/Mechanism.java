package io.kiwimec.nist.drbg;

import io.kiwimec.nist.source.Entropy;
import io.kiwimec.nist.source.Nonce;
import io.kiwimec.nist.util.Status;
import io.kiwimec.nist.util.Tuple2;
import io.kiwimec.nist.util.Tuple3;

public class Mechanism {

    // Components need to be final to make instantiation unbreakable.
    private final Entropy entropy_source;
    private final Nonce nonce_source;
    private final Algorithm drbg_algorithm;

    // The standard makes the state one or more addressable units. I'm just using
    // one here. If you want more create more Mechanism's.
    private State internal_state = null;

    // It is the responsibility of the constructor to correctly configure the type
    // of mechnism with the required combination of sources and algorithm.
    public Mechanism(Entropy entropy_source, Nonce nonce_source,
            Algorithm drbg_algorithm) {

        this.entropy_source = entropy_source;
        this.nonce_source = nonce_source;
        this.drbg_algorithm = drbg_algorithm;

        // TODO: add health check

        this.internal_state = new State();
    }

    //
    /**
     * The instantiate function acquires entropy input and may combine it with a
     * nonce and a personalization string to create a seed from which the initial
     * internal state is created.
     * 
     * @param requested_instantiation_security_strength
     * @param prediction_resistance_flag
     * @param personalization_string
     * @return
     */
    public Tuple2<Status, String> Instantiate_function(
            int requested_instantiation_security_strength, boolean prediction_resistance_flag,
            String personalization_string) {

        // Comment: Check the validity of the input parameters.

        // 1. If requested_instantiation_security_strength >
        // highest_supported_security_strength, then return (ERROR_FLAG, Invalid).
        if (requested_instantiation_security_strength > drbg_algorithm.highest_supported_security_strength)
            return new Tuple2<Status, String>(Status.ERROR_FLAG, "Invalid");

        // 2. If prediction_resistance_flag is set, and prediction resistance is not
        // supported, then return (ERROR_FLAG, Invalid).
        //
        // NOTE a. Although ambiguous it appears from step 9.2 in the Generate_function
        // that the prediction_resistance_flag set here is an overriding default and is
        // assumed to be stored in the internal state as per p. 27 of the specification.
        if (prediction_resistance_flag && !drbg_algorithm.prediction_resistance_flag)
            return new Tuple2<Status, String>(Status.ERROR_FLAG, "Invalid");
        internal_state.prediction_resistance_flag = prediction_resistance_flag;

        // 3. If the length of the personalization_string >
        // max_personalization_string_length,
        // return (ERROR_FLAG, Invalid).
        if (personalization_string.length() > drbg_algorithm.max_personalization_string_length)
            return new Tuple2<Status, String>(Status.ERROR_FLAG, "Invalid");

        // 4. Set security_strength to the lowest security strength greater than or
        // equal to requested_instantiation_security_strength from the set {112, 128,
        // 192, 256}.
        if (requested_instantiation_security_strength > 192) {
            internal_state.security_strength = 256;
        } else if (requested_instantiation_security_strength > 128) {
            internal_state.security_strength = 192;
        } else if (requested_instantiation_security_strength > 112) {
            internal_state.security_strength = 128;
        } else {
            internal_state.security_strength = 112;
        }

        // 5. Null step. Comment: This null step replaces a step from the original
        // version of SP 800-90 without changing the step numbers.

        // 6. (status, entropy_input) = Get_entropy_input (security_strength,
        // min_length, max_length, prediction_resistance_request).
        Tuple2<Status, byte[]> entropy_input = entropy_source.Get_entropy_input(
                internal_state.security_strength,
                internal_state.security_strength,
                internal_state.security_strength,
                prediction_resistance_flag);

        // 7. If (status ≠ SUCCESS), return (status, Invalid).
        if (entropy_input.first != Status.SUCCESS)
            return new Tuple2<Status, String>(entropy_input.first, "Invalid");

        // 8. Obtain a nonce. Comment: This step shall include any appropriate checks on
        // the acceptability of the nonce. See Section 8.6.7.
        //
        // NOTE a. The prototype for the nonce call is not provided.
        String nonce = nonce_source.Get_nonce();

        // 9. initial_working_state = Instantiate_algorithm (entropy_input, nonce,
        // personalization_string, security_strength).
        State initial_working_state = drbg_algorithm.Instantiate_algorithm(entropy_input.second, nonce,
                personalization_string, internal_state.security_strength);

        // 10. Get a state_handle for a currently empty internal state. If an empty
        // internal state cannot be found, return (ERROR_FLAG, Invalid).
        if (initial_working_state.handle == null)
            return new Tuple2<Status, String>(Status.ERROR_FLAG, "Invalid");

        // 11. Set the internal state for the new instantiation (e.g., as indicated by
        // state_handle) to the initial values for the internal state (i.e., set the
        // working_state to the values returned as initial_working_state in step 9) and
        // any other values required for the working_state (see Section 10), and set the
        // administrative information to the appropriate values (e.g., the values of
        // security_strength and the prediction_resistance_flag).
        internal_state = initial_working_state;

        // 12. Return (SUCCESS, state_handle).
        return new Tuple2<Status, String>(Status.SUCCESS, internal_state.handle);
    }

    /**
     * Refreshes the RDBG from entropy sources. This method is optional. But it can
     * be called by the application on an ad-hoc basis. It is also called by
     * Generate_function if the algorithm indicates that the RDBG needs a refresh.
     * Not all algorithms or implementations support refresh.
     * 
     * @param state_handle
     * @param prediction_resistance_request
     * @param additional_input
     * @return
     */
    public Status Reseed_function(String state_handle, boolean prediction_resistance_request,
            String additional_input) {

        // 1. Using state_handle, obtain the current internal state. If state_handle
        // indicates an invalid or unused internal state, return (ERROR_FLAG).
        //
        // NOTE a. This state management makes sense in a context where multiple states
        // may be maintained by a single object. See steps 6. and 7. for use.
        //
        // NOTE b. No consideration is given to thread, data or memory safety in the
        // specification. Quite rightly this is left to the implementer to consider
        // given that this is a generic specification and such things are implementation
        // context dependent and therefore unbounded in scope. As long as the state get
        // and set are atomic and get creates a copy of the state reseeding could be
        // done in parallel with generation with minimal interruption to generation in
        // some circumstances. Here I just use a single state.
        if (internal_state.handle != state_handle)
            return Status.ERROR_FLAG;
        State working_state = internal_state;

        // 2. If prediction_resistance_request is set, and prediction_resistance_flag is
        // not set, then return (ERROR_FLAG).
        if (prediction_resistance_request && !drbg_algorithm.prediction_resistance_flag)
            return Status.ERROR_FLAG;

        // 3. If the length of the additional_input > max_additional_input_length,
        // return (ERROR_FLAG).
        if (additional_input.length() > drbg_algorithm.max_additional_input_length)
            return Status.ERROR_FLAG;

        // Comment: Obtain the entropy input.
        // 4. (status, entropy_input) = Get_entropy_input (security_strength,
        // min_length, max_length, prediction_resistance_request).
        Tuple2<Status, byte[]> entropy_input = entropy_source.Get_entropy_input(
                internal_state.security_strength,
                internal_state.security_strength,
                internal_state.security_strength,
                prediction_resistance_request);

        // Comment: status indications other than SUCCESS could be ERROR_FLAG or
        // CATASTROPHIC_ERROR_FLAG, in which case, the status is returned to the
        // consuming application to handle. The Get_entropy_input call could return a
        // status of ERROR_FLAG to indicate that entropy is currently unavailable, and
        // could return CATASTROPHIC_ERROR_FLAG to indicate that an entropy source
        // failed.
        // 5. If (status ≠ SUCCESS), return (status).
        if (entropy_input.first != Status.SUCCESS)
            return entropy_input.first;

        // Comment: Get the new working_state using the appropriate reseed algorithm in
        // Section 10.
        // 6. new_working_state = Reseed_algorithm (working_state, entropy_input,
        // additional_input).
        Algorithm new_working_state = drbg_algorithm.Reseed_algorithm(
                working_state, entropy_input.second, additional_input);

        // 7. Replace the working_state in the internal state for the DRBG instantiation
        // (e.g., as indicated by state_handle) with the values of new_working_state
        // obtained in step 6.
        internal_state = new_working_state;

        // 8. Return (SUCCESS).
        return Status.SUCCESS;
    }

    /**
     * Create a random stream of bits of <code>requested_number_of_bits</code> in
     * length.
     * 
     * @param state_handle
     * @param requested_number_of_bits
     * @param requested_security_strength
     * @param prediction_resistance_request
     * @param additional_input
     * @return
     */
    public Tuple2<Status, byte[]> Generate_function(String state_handle,
            int requested_number_of_bits, int requested_security_strength,
            boolean prediction_resistance_request, String additional_input) {

        // NOTE: This function required a few locals for control logic and scoping. I
        // only get
        // away with masking by reference because of the simplicity of this
        // investigation's scope.
        // In a production implementation more care would need to be taken.
        String working_additional_input = additional_input;
        boolean working_prediction_resistance_request = prediction_resistance_request;
        boolean entropy_has_not_been_generated = true;
        byte[] generated_entropy = null;

        // Comment: Get the internal state and check the input parameters.
        // 1. Using state_handle, obtain the current internal state for the
        // instantiation. If state_handle indicates an invalid or unused internal state,
        // then return (ERROR_FLAG, Null).
        if (internal_state.handle != state_handle)
            return new Tuple2<Status, byte[]>(Status.ERROR_FLAG, null);
        State working_state = internal_state;

        // 2. If requested_number_of_bits > max_number_of_bits_per_request, then return
        // (ERROR_FLAG, Null).
        if (requested_number_of_bits > drbg_algorithm.max_number_of_bits_per_request)
            return new Tuple2<Status, byte[]>(Status.ERROR_FLAG, null);

        // 3. If requested_security_strength > the security_strength indicated in the
        // internal state, then return (ERROR_FLAG, Null).
        if (requested_security_strength > internal_state.security_strength)
            return new Tuple2<Status, byte[]>(Status.ERROR_FLAG, null);

        // 4. If the length of the additional_input > max_additional_input_length, then
        // return (ERROR_FLAG, Null).
        if (working_additional_input.length() > drbg_algorithm.max_additional_input_length)
            return new Tuple2<Status, byte[]>(Status.ERROR_FLAG, null);

        // 5. If prediction_resistance_request is set, and prediction_resistance_flag is
        // not set, then return (ERROR_FLAG, Null).
        if (working_prediction_resistance_request && !drbg_algorithm.prediction_resistance_flag)
            return new Tuple2<Status, byte[]>(Status.ERROR_FLAG, null);

        // 6. Clear the reseed_required_flag.
        internal_state.reseed_required_flag = false;

        // NOTE a. See step 9.3.
        while (entropy_has_not_been_generated) {

            // Comment: See Section 9.3.2 for a discussion.
            // Comment: Reseed if necessary (see Section 9.2).
            // 7. If reseed_required_flag is set, or if prediction_resistance_request is
            // set, then
            if (internal_state.reseed_required_flag || working_prediction_resistance_request) {

                // 7.1 status = Reseed_function (state_handle, prediction_resistance_request,
                // additional_input).
                Status status = Reseed_function(state_handle, working_prediction_resistance_request,
                        working_additional_input);

                // Comment: status indications other than SUCCESS could be ERROR_FLAG or
                // CATASTROPHIC_ERROR_FLAG, in which case, the status is returned to the
                // consuming application to handle. The Get_entropy_input call could return a
                // status of ERROR_FLAG to indicate that entropy is currently unavailable, and
                // could return CATASTROPHIC_ERROR_FLAG to indicate that an entropy source
                // failed.
                // 7.2 If (status ≠ SUCCESS), then return (status, Null).
                if (status != Status.SUCCESS)
                    return new Tuple2<Status, byte[]>(status, null);

                // 7.3 Using state_handle, obtain the new internal state.
                working_state = internal_state;

                // 7.4 additional_input = the Null string.
                working_additional_input = null;

                // 7.5 Clear the reseed_required_flag.
                internal_state.reseed_required_flag = false;
            }

            // Comment: Request the generation of pseudorandom_bits using the appropriate
            // generate algorithm in Section 10.
            // 8. (status, pseudorandom_bits, new_working_state) = Generate_algorithm
            // (working_state, requested_number_of_bits, additional_input).
            //
            // NOTE a. The psuedocode in the standard doesn't deal with exceptions from
            // Generate_algorithm.
            Tuple3<Status, byte[], State> generated = drbg_algorithm.Generate_algorithm(working_state,
                    requested_number_of_bits, working_additional_input);

            if (!(generated.first == Status.SUCCESS || generated.first == Status.RESEED_REQUIRED))
                return new Tuple2<Status, byte[]>(generated.first, null);

            // 9. If status indicates that a reseed is required before the requested bits
            // can be generated, then
            if (generated.first == Status.RESEED_REQUIRED) {

                // 9.1 Set the reseed_required_flag.
                working_state.reseed_required_flag = true;

                // 9.2 If the prediction_resistance_flag is set, then set the
                // prediction_resistance
                // request indication.
                if (working_state.prediction_resistance_flag)
                    working_prediction_resistance_request = true;

                // 9.3 Go to step 7.
            } else {

                entropy_has_not_been_generated = false;
                generated_entropy = generated.second;
                working_state = generated.third;
            }

        }

        // 10. Replace the old working_state in the internal state of the DRBG
        // instantiation (e.g., as indicated by state_handle) with the values of
        // new_working_state.
        internal_state = working_state;

        // 11. Return (SUCCESS, pseudorandom_bits).
        return new Tuple2<Status, byte[]>(Status.SUCCESS, generated_entropy);
    }

    /**
     * Erase the internal state of the DRBG.
     * 
     * @param state_handle
     * @return
     */
    public Status Uninstantiate_function(String state_handle) {

        // 1. If state_handle indicates an invalid state, then return (ERROR_FLAG).
        if (state_handle != internal_state.handle)
            return Status.ERROR_FLAG;

        // 2. Erase the contents of the internal state indicated by state_handle.
        // TODO: Think about options for secure deletion.
        this.internal_state = new State();

        // 3. Return (SUCCESS).
        return Status.SUCCESS;
    }
}
