package io.kiwimec.nist.drbg;

import java.util.BitSet;

import io.kiwimec.nist.util.Status;
import io.kiwimec.nist.util.Tuple3;

public class Aes256CtrNoDf extends Algorithm {

    // Algorithm configuration.

    // Input and output block length. Also inlen and outlen.
    private final int blocklen = 128;

    // Counter field length.
    private final int ctr_len = blocklen;

    // Key length.
    private final int keylen = 256;

    // Required minimum entropy for instantiate and reseed. See
    // <code>State.security_strength</code>.

    // Seed length.
    private final int seedlen = blocklen + keylen;

    // Minimum entropy input length (No dervation function).
    private final int min_length = seedlen;

    // Maximum entropy input length (No dervation function).
    private final int max_length = seedlen;

    // Maximum personalization string length (No dervation function). Ref.
    // <code>Algorithm.max_personalization_string_length</code>.

    // Maximum additional_input length (No dervation function). Ref.
    // <code>Algorithm.max_additional_input_length</code>.

    // Maximum number of bits per request, min((2ctr_len - 4) × blocklen, 2^19) =
    // min(32256,524288) = 32256. Ref.
    // <code>Algorithm.max_number_of_bits_per_request</code>.

    // Maximum number of requests between reseeds (2^48).
    private final int reseed_interval = 48;

    // Working state.

    private BitSet V = new BitSet(256);
    private BitSet Key = new BitSet(1024);
    private BitSet reseed_counter = new BitSet(48);

    /**
     * Initialises the configuration for this Algorithm instance.
     * 
     * @param prediction_resistance_flag
     */
    public Aes256CtrNoDf(boolean prediction_resistance_flag) {

        super(
                256,
                384,
                32256,
                384,
                true);
    }

    @Override
    public State Instantiate_algorithm(byte[] entropy_input, String nonce, String personalization_string,
            int security_strength) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'Instantiate_algorithm'");
    }

    @Override
    public State Reseed_algorithm(State internal_state, byte[] entropy_input, String additional_input) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'Reseed_algorithm'");
    }

    @Override
    public Tuple3<Status, byte[], State> Generate_algorithm(State working_state, int requested_number_of_bits,
            String additional_input) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'Generate_algorithm'");
    }

}
