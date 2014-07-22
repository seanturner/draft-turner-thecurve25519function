---
title: The Curve25519 Function
abbrev: The Curve25519 Function
docname: draft-turner-thecurve25519function-latest
date: 2014-07-18
category: info

ipr: trust200902
area: Security
workgroup: Network Working Group
keyword: Internet-Draft

stand_alone: yes
pi:
   toc: no
   sortrefs: yes
   symrefs: yes

author:
-
    ins: W. Ladd
    name: Watson Ladd
    org: Grad Student UC Berkley
    email: watsonbladd@gmail.com
-
    ins: R. Salz
    name: Rich Salz
    org: Akamai
    email: rsalz@akamai.com
-
    ins: S. Turner
    name: Sean Turner
    org: IECA, Inc.
    street: 3057 Nutley Street
    street: Suite 106
    city: Fairfax
    region: VA 22031
    country: USA
    phone: +1-703-628-3180
    email: turners@ieca.com

normative:
    RFC2119:
    RFC6090:
    Curve25519:
        target: http://www.iacr.org/cryptodb/archive/2006/PKC/3351/3351.pdf
        title: Curve25519 - new Diffie-Hellman speed records
        author:
            name: Daniel J. Bernstein
            ins: D.J. Bernstein
        date: 2006-04-01
    Mont:
        target: http://www.ams.org/journals/mcom/1987-48-177/S0025-5718-1987-0866113-7/S0025-5718-1987-0866113-7.pdf
        title: Speeding the Pollard and elliptic curve methods of factorization
        author:
            name: Peter L. Montgomery
            ins: P. Montgomery
        date: 1983

informative:
    NaCl:
        target: http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
        title: Cryptography in NaCl
        author:
            name: Daniel J. Bernstein
            ins: D.J. Bernstein
        date: 2013

--- abstract

This document specifies the Curve25519 function, an ECDH (Elliptic-Curve Diffie-Hellman) key-agreement scheme for use in cryptographic applications.  It was designed with performance and security in mind.

--- middle

# Introduction

This document specifies the Curve25519 function, an ECDH (Elliptic-curve Diffie-Hellman) key-agreement scheme for use in cryptographic applications.  It was designed with performance and security in mind.

This document provides a stable reference for the Curve25519 function {{Curve25519}} to which other specifications may refer when defining their use of Curve25519  This document does not specify the use of Curve25519 in any other specific protocol, such as TLS (Transport Layer Security) or IPsec (Internet Protocol Security).  This document specifies how to use Curve25519 for key exchange; it does not specify how to use Curve25519 for use with digital signatures. This document
defines the algorithm, expected "wire format," and provides some implementation
guidance to avoid known side-channel exposures.

Readers are assumed to be familiar with the concepts of elliptic curves, modular arithmetic, group operations, and finite fields {{RFC6090}} as well as rings {{Curve25519}}.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}.

# Notation and Definitions

The following notation and definitions are used in this document (notation is to the left of the ":"):

A: A value used in the elliptic-curve equation E.

E: An elliptic-curve equation.

p: A prime.

GF(p): The field with p elements.

mod: An abbreviation for modulo.

_#: Subscript notation, where # is a number or letter

=: Denotes equal to.

^: Denotes exponentiation.

+, -, *, /: Denotes addition, subtraction, multiplication, and division.

Note that all operations are performed mod p.

# The Curve25519 Function

Let p=2^255-19. Let E be the elliptic curve with the equation y^2=x^3+486662*x^2+x over GF(p).

Each element x of GF(p) has a unique little-endian representation as 32 bytes s[0] ... s[31], such that s[0]+256*s[1]+256^2*s[2]+...+256^31*s[31] is congruent to x modulo p, and s[31] is minimal. Implementations MUST only produce points in this form, and MUST mask the high bit of byte 31 to zero on receiving a point.  The high bit is, following convention, 0x80.

Let X denote the projection map from a point (x,y) on E, to x, extended so that X of the point at infinity is zero.  X is surjective onto GF(p) if the y coordinate takes on values in GF(p) and in a quadratic extension of GF(p).

Then Curve25519(s, X(Q))=X(sQ) is a function defined for all elements of GF(p). The remainder of this document describes how to compute this function quickly and securely, and use it in a Diffie-Hellman scheme.

# Implementing Curve25519

Let s be a 255 bits long integer, where s=sum s_i2^i with s_i in {0,1}. 

Computing Curve25519(s, x)  is done by the following procedure, taken from {{Curve25519}} based on formulas from {{Mont}}. All calculations are done over GF(p), i.e., they are performed modulo p. The parameter a24 is a24 = (486662 - 2)/4 = 121665. 

~~~~~~~~~~
Let x_1 = 1
    x_2 = 1
    z_2 = 0
    x_3 = x
    z_3 = 1
    For t = 254 to 0:
            Do constant time conditional swap of (x_2, z_2) and (x_3, z_3) if s_t is set
            A = x_2 + z_2
            AA = A^2
            B = x_2 - z_2
            BB = B^2
            E = AA - BB
            C = x_3 + z_3
            D = x_3 - z_3
            DA = D * A
            CB = C * B
            x_3 = (DA + CB)^2
            z_3 = x_1 * (DA - CB)^2
            x_2 = AA * BB
            z_2 = E * (AA + a24 * E)
            Do constant time conditional swap of (x_2, z_2) and (x_3, z_3) if s_t is set
    Return x_2*(z_2^(p-1))
~~~~~~~~~~

In implementing this procedure, due to the existence of side-channels in commodity hardware, it is vital that the pattern of memory accesses and jumps not depend on the bits of s. It is also essential that the arithmetic used not leak information about words.

To compute the conditional swap in constant time (independent of s_t) use
      dummy = s_t*(x_2-x_3)
      x_2 = x_2 - dummy
      x_3 = x_3 + dummy
where s_t is 1 or 0, or 
      dummy = s_t & (x_2 XOR x_3)
      x_2 = x_2 XOR x_3
      x_3 = x_3 XOR x_2
where s_t is regarded as the all-1 word of 255 bits. The latter version is more efficient on most architectures.


# Use of the Curve25519 function

The Curve25519 function can be used in an ECDH protocol as follows:

Alice takes 32 random bytes in s[0] to s[32]. She masks the lower three bits of s[0] and the top bit of s[31] to zero and sets the second top most bit of s[31] to 1. This means that s is of the form 2^254+8*{0,1, ...., 2^(251)-1} as a little-endian integer.

Alice then transmits K_A = Curve25519(s, 9) to Bob, where 9 is the number 9. As a sequence of 32 bytes, t, the representation of 9 is t[0]=9, and the remaining bytes are all zero. The natural wire-format representation of the value is in little-endian
byte order.

Bob picks a random g, and computes K_B = Curve25519(g, 9) similarly, and transmits it to Alice.

Alice computes Curve25519(s, Curve25519(g, 9)); Bob computes Curve25519(g, Curve25519(s, 9)) using their secret values and the received input.

Both of them now share K=Curve25519(s, Curve25519(g, 9))=Curve25519(g, Curve25519(s, 9)) as a shared secret.  Alice and Bob use a key-derivation function, such as hashing K, to compute a shared secret.

# Test Vectors

The following test vectors are taken from {{NaCl}}:

Alice's public key:

  0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a

Alice's secret key

  0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a

Bob's public key:

  0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f

Bob's secret key:

  0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb

Shared secret:

  0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742

# Security Considerations

Curve25519 meets all standard assumptions on DH and DLP difficulty. 

In addtion, Curve25519 is twist secure: the co-factor of the curve is 8, that of the twist is 4. Protocols that require contributory behavior must ban outputs K_A =0, K_B = 0 or K = 0.  

Curve25519 is designed to enable very high performance software implementations, thus reducing the cost of highly secure cryptography to a point where it can be used more widely.

# IANA Considerations

None.

--- back

--- fluf
   
