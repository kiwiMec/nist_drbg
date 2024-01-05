# nist_drbg
An exploration of a DRBG based on the NIST 800-90 specification.

>**Note**
This repository is only for personal investigation into the DRBG space. It's just an experiment to see how close to the standard's psuedo code I can get. Please feel free to read and learn with me but don't use this in any production setting.

# Approach

I intend to implement the pseudo algorithms in such a way that they will be immediately recognisable to the reader of the code familiar with the standard. Basically I'm just curious as to how well pseudo code in standards translates to real code. A consequence is that the code should work. But I'm not fussed if it actually accomplishes the objectives of the standard.

The following is my interpretation of the architecture of the drbg mechanism.

![basic architecture](/nist%20drbg%20-%20data%20flow.png)

* Arrows represent primary data flow.
* Light blue boxes represent mechanism functions.
* Light blue cylinders show mechanism storage.

# References

The following references are links to the standards followed by links to commentary on the standards that are useful for their comprehension.

## Standards

* [**NIST 800-90A r1** Recommendation for Random Number Generation Using Deterministic Random Bit Generators](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)
* [**NIST 800-90B** Recommendation for the Entropy Sources Used for Random Bit Generation](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90B.pdf)
* [**NIST 800-90C public draft 3** Recommendation for Random Bit Generator (RBG) Constructions ](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90C.3pd.pdf)

## Commentary

* [**NIST IR 8427** Discussion on the Full Entropy Assumption of the SP 800-90 Series](https://nvlpubs.nist.gov/nistpubs/ir/2023/NIST.IR.8427.pdf)
* [An Analysis of the NIST SP 800-90A Standard](https://eprint.iacr.org/2018/349.pdf)
* [A Security Analysis of the NIST SP 800-90 Elliptic Curve Random Number Generator](https://eprint.iacr.org/2007/048.pdf)
