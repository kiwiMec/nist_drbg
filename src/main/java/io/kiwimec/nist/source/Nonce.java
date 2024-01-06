package io.kiwimec.nist.source;

/* 
8.6.7 Nonce

A nonce may be required in the construction of a seed during instantiation in order to provide a
security cushion to block certain attacks. The nonce shall be either:

a. A value with at least (security_strength/2) bits of entropy, or
b. A value that is expected to repeat no more often than a (security_strength/2)-bit random string
   would be expected to repeat.

Each nonce shall be unique to the cryptographic module in which instantiation is performed, but
need not be secret. When used, the nonce shall be considered to be a critical security parameter.

A nonce may be composed of one (or more) of the following components (other components may also be
appropriate):

1. A random value that is generated anew for each nonce, using an approved random bit generator.
2. A timestamp of sufficient resolution (detail) so that it is different each time it is used. 
3. A monotonically increasing sequence number, or
3. A combination of a timestamp and a monotonically increasing sequence number, such that the 
   sequence number is reset when and only when the timestamp changes. For example, a timestamp may 
   show the date but not the time of day, so a sequence number is appended that will not repeat 
   during a particular day.

For case 1 above, the random value could be acquired from the same source and at the same time 
as the entropy input. In this case, the seed could be considered to be constructed from an “extra 
strong” entropy input and the optional personalization string, where the entropy for the entropy
input is equal to or greater than (3/2 security_strength) bits.

For case 2 above, the timestamp must be trusted. A trusted timestamp is generated and signed by an
entity that is trusted to provide accurate time information.

The nonce provides greater assurance that the DRBG provides security_strength bits of security to 
the consuming application. If a DRBG were instantiated many times without a nonce, a compromise 
could become more likely. In some consuming applications, a single DRBG compromise could reveal 
long-term secrets (e.g., a compromise of the DSA per-message secret could reveal the signing key).

A nonce shall be generated within a cryptographic module boundary. This requirement does not 
preclude the generation of the nonce within a cryptographic module that is different from the 
cryptographic boundary containing the DRBG function with which the nonce is used (e.g., the 
cryptographic module boundary containing an instantiate function). However, in this scenario, 
there needs to be a secure channel to transport the nonce between the cryptographic-module 
boundaries. See the discussion of distributed DRBGs in Section 8.5 and distributed RBGs in 
[SP 800-90C].

B.1 Hash_DRBG Example

This example of Hash_DRBG uses the SHA-1 hash function, and prediction resistance is supported. 
Both a personalization string and additional input are supported. A 32-bit incrementing counter 
is used as the nonce for instantiation (instantiation_nonce); the nonce is initialized when the 
DRBG is instantiated (e.g., by a call to the clock or by setting it to a fixed value) and is 
incremented for each instantiation.

B.2 HMAC_DRBG Example

This example of HMAC_DRBG uses the SHA-256 hash function. Reseeding and prediction resistance are 
not supported. The nonce for instantiation consists of a random value with security_strength/2 bits
of entropy; the nonce is obtained by increasing the call for entropy bits via the Get_entropy_input
call by security_strength/2 bits (i.e., by adding security_strength/2 bits to the security_strength
value). The HMAC_DRBG_Update function is specified in Section 10.1.2.2.

B.3 CTR_DRBG Example Using a Derivation Function

The nonce for instantiation (instantiation_nonce) consists of a 32-bit incrementing counter. The 
nonce is initialized when the DRBG is instantiated (e.g., by a call to the clock or by setting it 
to a fixed value) and is incremented for each instantiation.
*/

// TODO: code a real nonce generator illustrating the options above.
public class Nonce {
    
    public String Get_nonce() {

        return "nonce";
    }
}
