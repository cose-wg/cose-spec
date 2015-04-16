---
stand_alone: true
ipr: trust200902
docname: draft-schaad-cose-latest
cat: info
pi:
  toc: 'yes'
  symrefs: 'yes'
  sortrefs: 'yes'
  comments: 'yes'
title: CBOR Encoded Message Syntax
area: Security
author:
- ins: J. Schaad
  name: Jim Schaad
  org: August Cellars
  email: ietf@augustcellars.com
normative:
  I-D.greevenbosch-appsawg-cbor-cddl:
  I-D.ietf-jose-json-web-algorithms:
  RFC7049:
informative:
  I-D.ietf-jose-json-web-encryption:
  I-D.ietf-jose-json-web-signature:
  I-D.ietf-jose-json-web-key:
  I-D.mcgrew-aead-aes-cbc-hmac-sha2:
  RFC2119:
  RFC3394:
  RFC3447:
  RFC3610:
  RFC5752:
  RFC5990:
  RFC5652:
  RFC7159:
  AES-GCM:
    title: 'NIST Special Publication 800-38D: Recommendation for Block Cipher Modes
      of Operation: Galois/Counter Mode (GCM) and GMAC.'
    author:
    - ins: M. Dworkin
      org: U.S. National Institute of Standards and Technology
    date: ''

--- abstract

Concise Binary Object Representation (CBOR) is data format designed for small code size and small message size.
There is a need for the ability to have the basic security services defined for this data format.
This document specifies how to do signatures, message authentication codes and encryption using this data format.
The work in this document is derived in part from the JSON web security documents using the same parameters and algorithm identifiers as they do.

--- middle

# Introduction

The JOSE working group produced a set of documents that defined how to
perform encryption, signatures and message authentication (MAC)
operations for JavaScript Object Notation (JSON) documents and then to encode the results using the
JSON format {{RFC7159}}.
This document does the same work for use with the Concise Binary Object Representation (CBOR) {{RFC7049}} document format.
While there is a strong attempt to keep the flavor of the original
JOSE documents, two considerations are taking into account:

* CBOR has capabilities that are not present in JSON and should be used.
  One example of this is the fact that CBOR has a method of encoding binary directly without first converting it into a base64 encoded sting. 

* The authors did not always agree with some of the decisions made by the JOSE working group.
  Many of these decisions have been re-examined, and where it seems to the authors to be superior or simpler, replaced.

## Design changes from JOSE

* Define a top level message structure so that encrypted, signed and MAC-ed messages can easily identified and still have a consistent view.

* Switch from using a map to using an array at the message level.
  While this change means that it is no longer possible to add new named parameters to
  the top level message, it also means that there is not a need to define how older
  implementations are defined to behave when new fields are present. 
  Most of the reasons that a new field would need to be defined are adequately addressed
  by defining a new parameter instead.

* Signed messages separate the concept of protected and unprotected attributes that are for the content and the signature.

* Key management has been made to be more uniform.  All key management techniques are represented as a recipient rather than only have some of them be so.

* MAC messages are separated from signed messages.

* MAC messages have the ability to do key management on the MAC key.

* Use binary encodings for binary data rather than base64url encodings.

* Remove the authentiction tag for encryption algorithms as a separate item.

## Requirements Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

When the words appear in lower case, their natural language meaning is used.

## CBOR Grammar

There currently is no standard CBOR grammar available for use by
specifications.
In this document, we use the grammar defined in the CBOR data
definition language (CDDL) 
{{I-D.greevenbosch-appsawg-cbor-cddl}}.


# The COSE_MSG structure

The COSE_MSG structure is a top level CBOR object which corresponds to
the DataContent type in {{RFC5652}}.
This structure allows for a top level message to be sent which could
be any of the different security services, where the security service
is identified.
The presence of this structure does not preclude a protocol to use one
of the individual structures as a stand alone component.

~~~~ CDDL

COSE_MSG = [sign:1, COSE_Sign] / [encrypt:2, COSE_encrypt] / [mac:3, COSE_mac]

~~~~

The top level of each of the COSE message structures are encoded as arrays.  
We use an integer to distingish bettwen the different security message types.
By looking at the integer in the first element, one can determine which security message is
being used and thus what the syntax is for the rest of the elements in the array.

Implementations SHOULD be prepared to find an integer in the location which does not correspond to the values 0 to 2.
If this is found then the client MUST stop attempting to parse the structure and fail.
Clients need to recognize that the set of values could be extended at a later date, but should not provide a security service based on guesses of what is there.

NOTE: Alternative syntax with tags would be

~~~~  

COSE_MSG = COSE_SignedMessage / #6.998([COSE_encrypt]) / #6.999([COSE_mac])


~~~~

Where we would need to define the latter two as tagged arrays like is currently done for COSE_SignedMessage.  
There is no space savings in CBOR, this is strictly about using CBOR paradymes.  It is not clear what would happen if a JOSE serialization appeared, but that is probably not interesting.
If this path is used, then there is no extensibility for new messages types.  They would need to be defined on their own.

# Signing Structure

The signature structure allows for one or more signatures to be applied to a message payload.
There are provisions for  attributes about the content and attributes about the signature to be
carried along with the signature itself.
These attributes may be authenticated by the signature, or just present.
Examples of attributes about the content would be the type of content, when the content 
was created, and who created the content.
Examples of attributes about the signature would be the algorithm and key used to create 
the signature, when the signature was created, and counter-signatures.

When more than one signature is present, the successful validation of
one signature associated with a given signer is usually treated as a
successful signature by that signer.  However, there are some
application environments where other rules are needed.  An
application that employs a rule other than one valid signature for
each signer must specify those rules.  Also, where simple matching of
the signer identifier is not sufficient to determine whether the
signatures were generated by the same signer, the application
specification must describe how to determine which signatures were
generated by the same signer.  Support of different communities of
recipients is the primary reason that signers choose to include more
than one signature.  For example, the COSE_Sign structure might
include signatures generated with the RSA signature algorithm and
with the Elliptic Curve Digital Signature Algorithm (ECDSA) signature
algorithm.  This allows recipients to verify the signature associated
with one algorithm or the other. (Source of text is {{RFC5652}}.)
More detailed information on multiple signature evaluation can be found in {{RFC5752}}.

The CDDL grammar structure for a signature message is:

~~~~ CDDL

COSE_Sign = (
    protected : bstr / nil,
    unprotected : header_map / nil,
    payload : bstr / nil,
    signatures: [+[COSE_signature]] / COSE_signature
)

COSE_SignMessage = #6.997([ COSE_Sign ])

keys = int / tstr
header_map = {+ keys => any }

~~~~

The fields is the structure have the following semantics:

protected
: contains attributes about the payload which are to be protected by the signature.
  An example of such an attribute would be the content type ('cty') attribute.
  The content is a CBOR map of attributes which is encoded to a byte stream.
  This field MUST NOT contain attributes about the signature, even if
  those attributes are common across multiple signatures.

unprotected
: contains attributes about the payload which are not protected by the signature.
  An example of such an attribute would be the content type ('cty') attribute.
  This field MUST NOT contain attributes about a signature, even if
  the attributes are common across multiple signatures.


payload
: contains the serialized content to be signed.  
  If the payload is not present in the message, the application is required to 
  supply the payload separately.  
  The payload is wrapped in a bstr to ensure that it is transported without changes, 
  if the payload is transported separately it is the responsibility of the application
  to ensure that it will be transported without changes.

signatures
: is either a single signature or an array of signature values.  
  A single signature value can be represented using either data type.
  Implementations MUST be able to parse both data types.


The CDDL grammar structure for a signature is:

~~~~ CDDL

COSE_signature =  (
    protected : bstr / nil,
    unprotected : header_map / nil,
    signature : bstr
)

~~~~

The fields in the structure have the following semantics:

protected
: contains additional information to be authenticated by the signature.
  The field holds data about the signature operation.
  The field MUST NOT hold attributes about the payload being signed.
  The content is a CBOR map of attributes which is encoded to a byte stream.
  At least one of protected and unprotected MUST be present.
  

unprotected
: contains attributes about the signature which are not protected by the signature.
  This field MUST NOT contain attributes about the payload being signed.
  At least one of protected and unprotected MUST be present.

signature
: contains the computed signature value.

The COSE structure used to create the byte stream to be signed uses the following CDDL grammar structure:

~~~~ CDDL

Sig_structure = [
    body_protected : bstr / nil,
    sign_protected : bstr / nil,
    payload : bstr
]

~~~~

How to compute a signature:

1. Create a Sig_structure object and populate it with the appropriate fields.

2. Create the value to be hashed by encoding the Sig_structure to a byte string.

1. Comput the hash value from the byte string.

3. Sign the hash

4. Place the signature value into the appropriate signature field.

# Encryption object

In this section we describe the structure and methods to be used when
doing an encryption in COSE.
In COSE, we use the same techniques and structures for encrypting both
the plain text and the keys used to protect the text.
This is different from the approach used by both {{RFC5652}} and
{{I-D.ietf-jose-json-web-encryption}} where different structures are
used for the plain text and for the different key management
techniques.

One of the byproducts of using the same technique for encrypting and
encoding both the content and the keys using the various key management
techniques, is a requirement that all of the key management techniques
use an Authenticated Encryption (AE) algorithm.  (For the purpose of this document we use a slightly loose definition of AE algorithms.)
When encrypting the plain text, it is normal to use an Authenticated
Encryption with Additional Data (AEAD) algorithm.  For key management,
either AE or AEAD algorithms can be used.
See {{AE-algo}} for more details about the different types of
algorithms.

The CDDL grammar structure for encryption is:

~~~~ CDDL

COSE_encrypt = (
  protected : bstr / nil,  ; Contains header_map
  unprotected : header_map / nil,
  iv : bstr / nil,
  aad : bstr / nil,
  ciphertext : bstr / nil,
  recipients : [+COSE_encrypt_a] / COSE_encrypt / nil
)

COSE_encrypt_a = [COSE_encrypt]

~~~~

Description of the fields:

protected
: contains the information about the plain text or encryption
  process that is to be integrity protected.
  The field is encoded in CBOR as a 'bstr' if present and the value
  'nil' if there is no data.
  The contents of the protected field is a CBOR map of the protected
  data names and values.
  The map is CBOR encoded before placing it into the bstr.
  Only values associated with the current cipher text are to be placed in this location even if the value would apply to multiple recipient structures.

unprotected
: contains information about the plain text that is not integrity protected.
  If there are no field, then the value 'nil' is used.
  Only values associated with the current cipher text are to be placed in this location even if the value would apply to multiple recipient structures.

iv
: contains the initialization vector (IV), or it's equivalent, if one
  is needed by the encryption algorithm.
  If there is no IV, then the value 'nil' is used.

aad
: contains additional authenticated data (aad) supplied by the application.
  This field contains information about the plain text data that is
  authenticated, but not encrypted.
  If the application does not provide this data, the value 'nil' is used.

cipherText
: contains the encrypted plain text.
  If the cipherText is to be transported independently of the control
  information about the encryption process (i.e. detached content)
  then the value 'nil' is encoded here.

recipients
:   contains the recipient information.
  The field can have one of three data types:

  *  An array of COSE_encrypt elements, one for each recipient.

  *  A single COSE_encrypt element, encoded as an extension to the containing COSE_encrypt element, for a single recipient.
     Single recipients can be encoded either this way or as a single array element.

  *  A 'nil' value if there are no recipients.

## Key Management Methods

There are a number of different key management methods that can be
used in the COSE encryption system.
In this section we will discuss each of the key management methods and
what fields need to be specified to deal with each of them.

The names of the key management methods used here are the same as are
defined in {{I-D.ietf-jose-json-web-key}}.
Other specifications use different terms for the key management
methods or do not support some of the key management methods.

At the moment we do not have any key management methods that allow for the use of protected headers.  This may be changed in the future if, for example, the AES-GCM Key wrap method defined in {{I-D.ietf-jose-json-web-algorithms}} were extended to allow for authenticated data.  In that event the use of the 'protected' field, which is current forbidden below, would be permitted.

### Direct Encryption

In direct encryption mode, a shared secret between the sender and the
recipient is used as the CEK.
When direct encryption mode is used, it MUST be the only mode used on the message.
It is a massive security leak to have both direct encryption and a
different key management mode on the same message.

For JOSE, direct encryption key management is the only key management
method allowed for doing MAC-ed messages.
In COSE, all of the key management methods can be used for MAC-ed messages.

The COSE_encrypt structure for the recipient is organized as follows:

* The 'protected', 'iv', 'aad', 'ciphertext' and 'recipients' fields
  MUST be nil.

* At a minimum, the 'unprotected' field SHOULD contain the 'alg'
  parameter as well as a parameter identifying the shared secret.

### Key Wrapping

In key wrapping mode, the CEK is randomly generated and that key is
then encrypted by a shared secret between the sender and the
recipient.
All of the currently defined key wrapping algorithms for JOSE (and
thus for COSE) are AE algorithms.
Key wrapping mode is considered to be superior to direct encryption if
the system has any capability for doing random key generation.
This is because the shared key is used to wrap random data rather than
data  has some degree of organization and may in fact be repeating the
same content.

The COSE_encrypt structure for the recipient is organized as follows:

* The 'protected', 'aad', and 'recipients' fields MUST be nil.

* The plain text to be encrypted is the key from next layer down
  (usually the content layer).

* At a minimum, the 'unprotected' field SHOULD contain the 'alg'
  parameter as well as a parameter identifying the shared secret.

* Use of the 'iv' field will depend on the key wrap algorithm.

### Key Encryption

Key Encryption mode is also called key transport mode in some
standards.
Key Encryption mode differs from Key Wrap mode in that it uses an
asymmetric encryption algorithm rather than a symmetric encryption
algorithm to protect the key.
The only current Key Encryption mode algorithm supported is RSAES-OAEP.

The COSE_encrypt structure for the recipient is organized as follows:

* The 'protected', 'aad', and 'iv' fields all use the 'nil' value.

* The plain text to be encrypted is the key from next layer down
  (usually the content layer).

* At a minimum, the 'unprotected' field SHOULD contain the 'alg'
  parameter as well as a parameter identifying the asymmetric key.

### Direct Key Agreement

Direct Key Agreement derives the CEK from the shared secret computed
by the key agreement operation.

When direct key agreement mode is used, it SHOULD be the only mode used
on the message.  This method creates the CEK directly and that makes it difficult to mix with additional recipients.

The COSE_encrypt structure for the recipient is organized as follows:

* The 'protected', 'aad', and 'iv' fields all use the 'nil' value.

* At a minimum, the 'unprotected' field SHOULD contain the 'alg'
  parameter as well as a parameter identifying the asymmetric key.

* The 'unprotected' field MUST contain the 'epk' parameter.

### Key Agreement with Key Wrapping

Key Agreement with Key Wrapping uses a randomly generated CEK.
The CEK is then encrypted using a Key Wrapping algorithm and a key
derived from the shared secret computed by the key agreement
algorithm.

The COSE_encrypt structure for the recipient is organized as follows:

* The 'protected', 'aad', and 'iv' fields all use the 'nil' value.

* The plain text to be encrypted is the key from next layer down
  (usually the content layer).

* At a minimum, the 'unprotected' field SHOULD contain the 'alg'
  parameter, a parameter identifying the recipient asymmetric key, and
  a parameter with the sender's asymmetric public key.

## Encryption Algorithm for AEAD algorithms

The encryption algorithm for AEAD algorithms is fairly simple.  
In order to get a consistent encoding of the data to be authenticated, the Enc_structure is used to have canonical form of the AAD.

~~~~ CDDL

Enc_structure = [
   protected : bstr / nil,
   aad : bstr / nil
]

~~~~

1.   If there is protected data, CBOR encode the map to a byte string and place in the protected field of the Enc_structure and the COSE_Encrypt structure.

1.   Copy the 'aad' field from the COSE_Encrypt structure to the Enc_Structure.

1.   Encode the Enc_structure using a CBOR Canonical encoding {{CBOR-Canonical}} to get the AAD value.

1.   Encrypt the plain text and place it in the 'ciphertext' field.  The
     AAD value is passed in as part of the encryption process.

1.   For recipient of the message, recursively perform the encryption
     algorithm for that recipient using the encryption key as the
     plain text.

## Encryption algorithm for AE algorithms


1.   Verify that the 'protected' field is empty.

1.   Verify that the 'aad' field is empty.

1.   Encrypt the plain text and place in the 'ciphertext' field.

# MAC objects

In this section we describe the structure and methods to be used when doing MAC authentication in COSE.  JOSE used a variant of the signature structure for doing MAC operations and it is restricted to using a single pre-shared secret to do the authentication.  This document allows for the use of all of the same methods of key management as are allowed for encryption.

When using MAC operations, there are two modes in which it can be used.  The first is just a check that the content has not been changed since the MAC was computed.  Any of the key management methods can be used for this purpose.  The second mode is to both check that the content has not been changed since the MAC was computed, and to use key management to verify who sent it.  The key management modes that support this are ones that either use a pre-shared secret, or do static-static key agreement.  In both of these cases the entity MAC-ing the message can be validated by a key binding.  (The binding of identity assumes that there are only two parties involved and you did not send the message yourself.)

~~~~ CDDL

COSE_mac = (
   protected : bstr / nil,
   unprotected : header_map / nil,
   payload : bstr,
   tag : bstr,
   recipients : [+COSE_encrypt_a] / COSE_encrypt / nil
)

~~~~

Field descriptions:

protected
: contains attributes about the payload which are to be protected by the MAC.
  An example of such an attribute would be the content type ('cty') attribute.
  The content is a CBOR map of attributes which is encoded to a byte stream.
  This field MUST NOT contain attributes about the recipient, even if
  those attributes are common across multiple recipients.
  At least one of protected and unprotected MUST be present.


unprotected
: contains attributes about the payload which are not protected by the MAC.
  An example of such an attribute would be the content type ('cty') attribute.
  This field MUST NOT contain attributes about a recipient, even if
  the attributes are common across multiple recipients.
  At least one of protected and unprotected MUST be present.

payload
: contains the serialized content to be MAC-ed.  
If the payload is not present in the message, the application is required to supply the payload separately.  
The payload is wrapped in a bstr to ensure that it is transported without changes, if the payload is transported separately it is the responsibility of the application to ensure that it will be transported without changes.

tag
: contains the MAC value.

recipients
:   contains the recipient information.  See the description under COSE_Encryption for more info.


~~~~ CDDL

MAC_structure = {
   protected : bstr / nil,
   payload : bstr
}

~~~~~

How to compute a MAC:

1.  Create a MAC_structure and copy the protected and payload elements from the COSE_mac structure.

2.  Encode the MAC_structure using a canonical CBOR encoder.  The resulting bytes is the value to compute the MAC on.

3.  Compute the MAC and place the result in the 'tag' field of the COSE_mac structure.

4.  Encrypt and encode the MAC key for each recipient of the message.

# Key Structure

There are only a few changes between JOSE and COSE for how keys are formatted.
As with JOSE, COSE uses a map to contain the elements of a key.
Those values, which in JOSE, are base64url encoded because they are binary values, are encoded as bstr values in COSE.

For COSE we use the same set of fields that were defined in
{{I-D.ietf-jose-json-web-key}}.

~~~~ CDDL

COSE_Key = {
    "kty" : tstr,
    ? "use" : tstr,
    ? "key_ops" : [+tstr],
    ? "alg" : tstr,
    ? "kid" : tstr,
    * keys => values
}

COSE_KeySet = [+COSE_Key]

~~~~

The element "kty" is a required element in a COSE_Key map.  
All other elements are optional and not all of the elements listed in {{I-D.ietf-jose-json-web-key}} or {{I-D.ietf-jose-json-web-algorithms}} have been listed here even though they can all appear in a COSE_Key map.

The "key_ops" element is prefered over the "use" element as the information provided that way is more finely detailed about the operations allowed.  It is strongly suggested that this element be present for all keys.

The same fields defined in {{I-D.ietf-jose-json-web-key}} are used
here with the following changes in rules:

* Any item which is base64 encoded in JWK, is bstr encoded for COSE.

* Any item which is integer encoded in JWK, is int encoded for COSE.

* Any item which is string (but not base64) encoded in JWK, is tstr encoded for COSE.
  Exceptions to this are the following fields:
  kid
: is always bstr encoded rather than tstr encoded.
   This change in encoded is due to the fact that frequently, values
   such as a hash of the public key is used for a kid value.
   Since the field is defined as not having a specific structure,
   making it binary rather than textual makes sense.

# CBOR Encoder Restrictions {#CBOR-Canonical}

There as been an attempt to resrict the number of places where the document 
needs to impose restrictions on how the CBOR Encoder needs to work.  We have
managed to narrow it down to the following restrictions:

* The restriction applies to the encoding the Sig_structure, the Enc_structure, and the MAC_structure.

* The rules for Canonical CBOR (Section 3.9 of RFC 7049) MUST be used in these
 locations.  The main rule that needs to be enforced is that all lengths
 in these structures MUST be encoded such that they are encoded using definite lengths 
 and the minimum length encoding is used.

* All parsers used SHOULD fail on both parsing and generation if the same key is used twice in a map.

# IANA Considerations

There are IANA considerations to be filled in.

# Security Considerations

There are security considerations:

1.  Protect private keys

2.  MAC messages with more than one recipient means one cannot figure out who sent the message

3.  Use of direct key with other recipient structures hands the key to other recipients.

4.  Use of direcct ECDH direct encryption is easy for people to leak information on if there are other recipients in the message.

5.  Considerations about protected vs unprotected header fields.

--- back

# AEAD and AE algorithms {#AE-algo}

The set of encryption algorithms that can be used with this
specification is restricted to authenticated encryption (AE) and
authenticated encryption with additional data (AEAD) algorithms.
This means that there is a strong check that the data decrypted by the
recipient is the same as what was encrypted by the sender.
Encryption modes such as counter have no check on this at all.
The CBC encryption mode had a weak check that the data is correct,
given a random key and random data, the CBC padding check will pass
one out of 256 times.
There have been several times that a normal encryption mode has been
combined with an integrity check to provide a content encryption mode
that does provide the necessary authentication.
AES-GCM {{AES-GCM}}, AES-CCM {{RFC3610}}, AES-CBC-HMAC
{{I-D.mcgrew-aead-aes-cbc-hmac-sha2}} are  examples of these composite
modes.

PKCS v1.5 RSA key transport does not qualify as an AE algorithm.
There are only three bytes in the encoding that can be checked as
having decrypted correctly, the rest of the content can only be
probabilistically checked as having decrypted correctly.
For this reason, PKCS v1.5 RSA key transport MUST NOT be used with
this specification.
RSA-OAEP was designed to have the necessary checks that that content
correctly decrypted and does qualify as an AE algorithm.

When dealing with authenticated encryption algorithms, there is always
some type of value that needs to be checked to see if the
authentication level has passed.
This authentication value may be:

* A separately generated tag computed by both the encrypter and
  decrypter and then compared by the decryptor.
  This tag value may be either placed at the end of the cipher text
  (the decision we made) or kept separately (the decision made by the
  JOSE working group).
  This is the approach followed by AES-GCM {{AES-GCM}} and AES-CCM {{RFC3610}}.

* A fixed value which is part of the encoded plain text.
  This is the approach followed by the AES key wrap algorithm {{RFC3394}}.

* A computed value is included as part of the encoded plain text.
  The computed value is then checked by the decryptor using the same computation path.
  This is the approach followed by RSAES-OAEP {{RFC3447}}.

# Three Levels of Recipient Information

All of the currently defined Key Management methods only use two levels of the COSE_Encrypt structure.
The first level is the message content and the second level is the content key encryption.
However, if one uses a key management technique such as RSA-KEM (see Appendix A of RSA-KEM {{RFC5990}}, then
it make sense to have three levels of the COSE_Encrypt structure.

These levels would be:

* Level 0: The content encryption level.  This level contains the payload of the message.

* Level 1: The encryption of the CEK by a KEK.

* Level 2: The encryption of a long random secret using an RSA key and a key derivation function to convert that secret into the KEK.

# Examples

## Direct MAC

This example has some features that are in questions but not yet incorporated in the document.

To make it easier to read, this uses CBOR's diagnostic notation rather than a binary dump.

Encoded in CBOR - 118 bytes, content is 14 bytes long

~~~~ CBORdiag

[
  3,
  nil,
  {
    "alg": "HS256"
  },
  h'436f6e74656e7420537472696e67',
  h'78956d858ee6c026ac630063627a4ce98d3003bc68e7c1e53b5b468331b69f93',
  nil,
  {
    "alg": "dir",
    "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
  },
  nil,
  nil,
  nil
]
~~~~


## Wrapped MAC

This example has some features that are in questions but not yet incorporated in the document.

To make it easier to read, this uses CBOR's diagnostic notation rather than a binary dump.

Encoded in CBOR - 162 bytes, content is 14 bytes long

~~~~ CBORdiag

[
  3,
  nil,
  {
    "alg": "HS256"
  },
  h'436f6e74656e7420537472696e67',
  h'2ee486376b8b2a61fe526589ceb456e20919a68ebc0458431ef3e13ffe7b
    f698',
  nil,
  {
    "alg": "A128KW",
    "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a"
  },
  nil,
  h'4f6e9e6a3e43b79561ef602a2a9e629a437e8df90a7ff361acbdb1076c95
    5d0f25c660a67aee1bdf',
  nil
]
~~~~


## Direct ECDH

This example has some features that are in questions but not yet incorporated in the document.

To make it easier to read, this uses CBOR's diagnostic notation rather than a binary dump.

Encoded in CBOR - 216 bytes, content is 14 bytes long

~~~~ CBORdiag

[
  2,
  nil,
  {"alg": "A128GCM"},
  h'656d6a73ccf1b35fb99044e1',
  h'd7b27b67a81b212ee513b148454fe2d571d51bb679239769f5d2299bb96b',
  nil,
  {
    "alg": "ECDH-ES",
    "epk": {
      "kty": "EC",
      "crv": "P-256",
      "x": h'00b81ff1de0eeba27613027526d83b5f4cbffaca433488e3805
             e7a75c43bd1b966',
      "y": h'00d142a334ac8790dc821abe9362434daeb00c1b8b076843e51
             a4a4717b30c54ce'},
    "kid": "meriadoc.brandybuck@buckland.example"
  },
  nil,
  nil,
  nil
]
~~~~

## Single Signature

This example has some features that are in questions but not yet cooperated in the document.

To make it easier to read, this uses CBOR's diagnostic notation rather than a binary dump.

~~~~ CBORdiag

[
  1,
  nil,
  nil,
  h'436f6e74656e7420537472696e67',
  nil,
  {
    "kid": "bilbo.baggins@hobbiton.example",
    "alg": "PS256"
  },
   h'5afe80ec9f208b4719a3bd688c803a3154b1ff25af86e054173ad6ddf71
     ba77a4a2b793beed077a4e1a8a69ac1277c457f636691cb4a7d3dc67b47
     ec84c067076b720236bae498bdb21deebbc0a0f525f9a24b336d51e2b3e
     ffd67df3e051405a3599aed83b8a8e94e4194dded2f661e5e6894825779
     b79b463bd4f477f33356cf8aecfa8a543344d2620145be8a72a712f9854
     57040140176164c77cdae7cc480ae4357683cce79b97ddb10f390862a24
     2aae1aa391cc730b1631f020874a8a6efc77b08f027323e2c4ae85eeb3e
     5dc715e0e2fa8aec63fb828d7a2c45e361e249117bd8b41e1e12388412d
     8ce3809c9a2172afda5ca7c5839896825da66a50'
]
~~~~

## Multiple Signers

This example has some features that are in questions but not yet cooperated in the document.

To make it easier to read, this uses CBOR's diagnostic notation rather than a binary dump.

Encoded in CBOR - 491 bytes, content is 14 bytes long

~~~~ CBORdiag

[
  1,
  nil,
  nil,
  h'436f6e74656e7420537472696e67',
  [
    [
      nil,
      {
        "kid": "bilbo.baggins@hobbiton.example",
        "alg": "PS256"
      },
       h'5afe80ec9f208b4719a3bd688c803a3154b1ff25af86e054173ad6d
         df71ba77a4a2b793beed077a4e1a8a69ac1277c457f636691cb4a7d
         3dc67b47ec84c067076b720236bae498bdb21deebbc0a0f525f9a24
         b336d51e2b3effd67df3e051405a3599aed83b8a8e94e4194dded2f
         661e5e6894825779b79b463bd4f477f33356cf8aecfa8a543344d26
         20145be8a72a712f985457040140176164c77cdae7cc480ae435768
         3cce79b97ddb10f390862a242aae1aa391cc730b1631f020874a8a6
         efc77b08f027323e2c4ae85eeb3e5dc715e0e2fa8aec63fb828d7a2
         c45e361e249117bd8b41e1e12388412d8ce3809c9a2172afda5ca7c
         5839896825da66a50'
    ],
    [
      nil,
      {
        "kid": "bilbo.baggins@hobbiton.example",
        "alg": "ES512"
      },
      h'00e9769c05afb2d93baf5a0c2cace1747b5091f50596831911c67ebf
        76f4220adb53698fe7831000d526887893d67de05ead1bbe378ce9e9
        731bda4cd37f53dcf8d40186c46d872795b566682c113cc9d5bf5a8c
        5321fd50a003237115decf0cb8b09e5c3cb50bc2203af45bebd51e6c
        4d0ec51170d5b9ac1b21a2017a50d7c15b6de8f9'
    ]
  ]
]
~~~~


# Processing Parameter Table

This table contains a list of all of the parameters for use in signature and encryption message types defined by the JOSE document set.  In the table is the data value type to be used for CBOR as well as the integer value that can be used as a replacement for the name in order to further decrease the size of the sent item.

| name | number | CBOR type | comments |
| alg | * | tstr | presence is required |
| apu | * | bstr |
| apv | * | bstr |
| crit | * | tstr* |
| cty | * | tstr |
| enc | * |  | use alg instead |
| epk | * | map | contains a COSE key not a JWK key |
| iv | * |  | use field in array instead |
| jku | * | tstr |
| jwk | * | map | contains a COSE key not a JWK key |
| kid | * | tstr |
| p2c | * | int |
| p2s | * | bstr |
| tag | * |  | tag is included in the cipher text |
| typ | * |  | use cty for the content type, no concept of a different wrapper type |
| x5c | * | bstr* |
| x5t | * | bstr |
| x5t#S256 | * | bstr |
| x5u | * | tstr |
| zip | * | tstr | only used at content level |

# Key Parameter Tables

This table contains a list of all of the parameters defined for keys that were defined by the JOSE document set.  In the table is the data value type to be used for CBOR as well as the integer value that can be used as a replacement for the name in order to further decrease the size of the sent item.

| name | number | CBOR type |
| kty |  * | tstr |
| use | * | tstr |
| key_ops | * | tstr* |
| alg | * | tstr |
| kid | * | tstr |
| x5u | * | tstr |
| x5c | * | bstr* |
| x5t | * | bstr |
| xt5#S256 | * | bstr |

This table contains a list of all of the parameters that were defined by the JOSE document set for a specific key type.  In the table is the data value type to be used for CBOR as well as the integer value that can be used as a replacement for the name in order to further decrease the size of the sent item.
Parameters dealing with keys

| key type | name | number | CBOR type |
| EC | d | * | bstr |
| EC | x | * | bstr |
| EC | y | * | bstr |
| RSA | e | * | bstr | 
| RSA | n | * | bstr |
| RSA | d | * | bstr |
| RSA | p | * | bstr |
| RSA | q | * | bstr |
| RSA | dp | * | bstr |
| RSA | dq | * | bstr |
| RSA | qi | * | bstr |
| RSA | oth | * | bstr |
| RSA | r | * | bstr |
| RSA | t | * | bstr |
| oct | k | * | bstr |
