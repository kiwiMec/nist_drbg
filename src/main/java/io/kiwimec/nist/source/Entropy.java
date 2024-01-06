package io.kiwimec.nist.source;

import io.kiwimec.util.Status;
import io.kiwimec.util.Tuple2;

public class Entropy {

        public final int highest_supported_security_strength;
        public final int max_personalization_string_length;    

        public Entropy() {
                highest_supported_security_strength = 256;
                max_personalization_string_length = 256;
        }
    
        // (status, entropy_input) = Get_entropy_input (security_strength, min_length, max_length,
        // prediction_resistance_request).
        //
        // Comment: status indications other than SUCCESS could be ERROR_FLAG or 
        // CATASTROPHIC_ERROR_FLAG, in which case, the status is returned to the consuming 
        // application to handle. The Get_entropy_input call could return a status of 
        // ERROR_FLAG to indicate that entropy is currently unavailable, and could return 
        // CATASTROPHIC_ERROR_FLAG to indicate that an entropy source failed.
        public Tuple2<Status, byte[]> Get_entropy_input(
                int requested_instantiation_security_strength, 
                int min_length,
                int max_length,
                boolean prediction_resistance_request){

                return new Tuple2<Status, byte[]>(Status.SUCCESS, null);
        }
}
