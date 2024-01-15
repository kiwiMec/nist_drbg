package io.kiwimec.nist.source;

import java.security.SecureRandom;

import io.kiwimec.nist.util.Status;
import io.kiwimec.nist.util.Tuple2;

public class Entropy {

        private final SecureRandom random = new SecureRandom();

        // (status, entropy_input) = Get_entropy_input (security_strength, min_length,
        // max_length, prediction_resistance_request).
        //
        // Comment: status indications other than SUCCESS could be ERROR_FLAG or
        // CATASTROPHIC_ERROR_FLAG, in which case, the status is returned to the
        // consuming application to handle. The Get_entropy_input call could return a
        // status of ERROR_FLAG to indicate that entropy is currently unavailable, and
        // could return CATASTROPHIC_ERROR_FLAG to indicate that an entropy source
        // failed.
        public Tuple2<Status, byte[]> Get_entropy_input(
                        int requested_instantiation_security_strength,
                        int min_length,
                        int max_length,
                        boolean prediction_resistance_request) {

                // If we want prediction resistence force the use of the reseed algorithm to
                // involve the hardware.
                if (prediction_resistance_request == true)
                        return new Tuple2<Status, byte[]>(Status.SUCCESS, random.generateSeed(max_length));

                // Otherwise we simply want the next amount of random data.
                byte bytes[] = new byte[max_length];
                random.nextBytes(bytes);
                return new Tuple2<Status, byte[]>(Status.SUCCESS, bytes);
        }
}
