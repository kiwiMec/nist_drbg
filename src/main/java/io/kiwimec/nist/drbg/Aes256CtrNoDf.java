package io.kiwimec.nist.drbg;

import java.util.BitSet;

import io.kiwimec.nist.util.Status;
import io.kiwimec.nist.util.Tuple2;
import io.kiwimec.nist.util.Tuple3;

public class Aes256CtrNoDf extends Algorithm {

    // ----- Algorithm configuration.

    // Input and output block length. Also inlen and outlen.
    private final int blocklen = 128;

    // Counter field length.
    private final int ctr_len = blocklen - 1;

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

    // ----- Working state.

    private BitSet V = new BitSet(256);
    private BitSet Key = new BitSet(1024);
    private BitSet reseed_counter = new BitSet(48);

    /**
     * Initialises the configuration for this Algorithm instance.
     * 
     * @param prediction_resistance_flag
     */
    public Aes256CtrNoDf(boolean prediction_resistance_flag) {

        super(256, 384, 32256, 384, true);
    }

    // ----- Abstract Algorithm implementation.

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

    // ----- Local implementation

    /**
     * Updates the internal state of the CTR_DRBG using the provided_data.
     * 
     * @param provided_data
     * @param Key
     * @param V
     * @return
     */
    private Tuple2<BitSet, BitSet> CTR_DRBG_Update(BitSet provided_data, BitSet Key, BitSet V) {

        // 1. temp = Null.
        BitSet temp = new BitSet();

        // 2. While (len (temp) < seedlen) do
        while (temp.length() < seedlen) {

            // 2.1 If ctr_len < blocklen
            if (ctr_len < blocklen) {

                // 2.1.1 inc = (rightmost (V, ctr_len) + 1) mod 2ctr_len.
                BitSet inc = V.get(ctr_len, V.size() - 1);

                // 2.1.2 V = leftmost (V, blocklen-ctr_len) || inc.
            }

            // Else V = (V+1) mod 2blocklen.

            // 2.2 output_block = Block_Encrypt (Key, V).

            // 2.3 temp = temp || output_block.
        }

        // 3. temp = leftmost (temp, seedlen).

        // 4 temp = temp ⊕ provided_data.

        // 5. Key = leftmost (temp, keylen).

        // 6. V = rightmost (temp, blocklen).

        // 7. Return (Key, V).
        return new Tuple2<BitSet, BitSet>(Key, V);
    }
}
