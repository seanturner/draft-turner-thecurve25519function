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

This document provides a stable reference for the Curve25519 function {{Curve25519}} to which other specifications will refer when defining their use of Curve25519  This document does not specify the use of Curve25519 and any other specific protocol, such as TLS (Transport Layer Security) or IPsec (Internet Protocol Security).  This document specifies how to use Curve25519 for key exchange; it does not specify how to use Curve25519 for use with digital signatures.

Readers are assumed to be familiar with the concepts of elliptic curves, modular arithmetic, group operations, and finite fields {{RFC6090}} as well as rings {{Curve25519}}.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}.

# Notation and Definitions

The following notation and definitions are used in this document (notation is to the left of the ":"):

A: A value used in the elliptic-curve equation E.

E: An elliptic-curve equation.

F(p): The field with p elements.

GF(p): The finite field with p elements.

p: is a public key.  Also known as a generator point defined over GF(p).  A prime number defining the base field.

mod: An abbreviation for modulo.

_#: Subscript notation, where # is a number.

=: Denotes equal to.

>=: Denotes greater than or equal to.

^: Denotes exponentiation.

+, -, *, /: Denotes addition, subtraction, multiplication, and division.

Note that all operations are performed mod p.

# The Curve25519 Function

Let p=2^255-19. Let E be the elliptic curve with the equation y^2=x^3+486662*x^2+x over GF(p).

Each element x of GF(p) has a unique little-endian representation as 32 bytes s[0] ... s[31], such that s[0]+256*s[1]+256^2*s[2]+...+256^31*s[31] is congruent to x modulo p, and s[31] is minimal. Implementations MUST only produce points in this form, and MUST mask the high bit of byte 31 to zero on receiving a point.  The high bit is, according to convention, 0x80.

Let X denote the projection map from a point (x,y) on E, to x, extended so that X of the point at infinity is zero.  X is surjective onto GF(p) if we include y coordinate in some quadratic extension of GF(p).

Then Curve25519(s, X(Q))=X(sQ) is a function for all elements of GF(p). The remainder of this document describes how to compute this function quickly and securely, and use it in a Diffie-Hellman scheme.

# Implementing Curve25519

Suppose we wish to compute Curve25519(s, x), where s is 256 bits long. The following procedure, taken from {{Curve25519}} based on formulas from {{Mont}} does so.

All calculations are modulo p. The parameter a24 = (486662 - 2)/4 = 121665.

~~~~~~~~~~
Let x_1 = x
    z_1 = 1
    x_k = 1
    z_k = 0
    x_p = x
    z_p = 1
    For t=255 to 0:
        Let b be the tth bit of s
        Swap (x_k, z_k) and (x_p, z_p) if b is set
        Let:
            A = x_k + z_k
            AA = A^2
            B = x_k - z_k
            BB = B^2
            E = AA - BB
            C = x_p + z_p
            D = x_p - z_p
            DA = D * A
            CB = C * B
            x_p = (DA + CB)^2
            z_p = x_1 * (DA - CB)^2
            x_k = AA * BB
            z_k = E * (BB + a24 * E)
       Swap (x_k, z_k) and (x_p, z_p) if b is set
Return x_k*z_k^(p-1)
~~~~~~~~~~

In implementing this procedure, due to the existence of side-channels in commodity hardware, it is vital that the pattern of memory accesses and jumps not depend on the bits of s. It is also essential that the arithmetic used not leak information about words.

# Use of the Curve25519 function

The Curve25519 function can be used in an ECDH protocol as follows:

Alice takes 32 random bytes in s[0] to s[32]. She masks the lower three bytes, s[0] through s[2], to zero. This is necessary to avoid small-subgroup confinement attacks.

Alice then transmits Curve25519(s, 9) to Bob, where 9 is the number 9. As a sequence of 32 bytes, t, the representation of 9 is t[0]=9, and the remaining bytes are all zero.

Bob picks a random g, and computes Curve25519(g, 9) similarly, and transmits it to Alice.

Both of them now share Curve25519(s, Curve25519(g, 9))=Curve25519(g, Curve25519(s, 9)) as a shared secret.  It cannot be used directly, but must be hashed to avoid certain attacks, just like any other Diffie-Hellman (DH) primitive.

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

Curve25519 meets all standard assumptions on DH difficulty. Protocols that require contributory behavior must ban low-order points separately.  Curve25519 is designed to enable very high performance software implementations, thus reducing the cost of highly secure cryptography to a point where it can be used more widely.

# IANA Considerations

None.

--- back

--- fluf