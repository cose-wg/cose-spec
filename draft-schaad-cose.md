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
informative:
  I-D.ietf-jose-json-web-encryption:
  I-D.ietf-jose-json-web-algorithms:
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
  RFC7049:
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

> CBOR has capabilities that are not present in JSON and should be used.
> One example of this is the fact that CBOR has a method of encoding
> binary directly without first converting it into a base64 encoded
> sting. 

> The authors did not always agree with some of the decisions made by
> the JOSE working group.
> Many of these decisions have been re-examined, and where it seems to
> the authors to be superior or simpler, replaced.

## Design changes from JOSE

* Define a top level message structure so that encrypted, signed and MAC-ed messages can easily identified and still have a consistent view.

* Switch from using a map to using an array at the message level.
  While this change means that it is no longer possible to new named parameters to
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
In this document, we use a modified version of the CBOR data
definition language (CDDL) defined in
{{I-D.greevenbosch-appsawg-cbor-cddl}}.
The differences between the defined grammar and the one we used are
mostly self explanatory.
The biggest difference being the addition of the choice operator '|'.
Additionally, note the use of the null value which is used to occupy a location in an array but to mark that the element is not present.


# The COSE_MSG structure

The COSE_MSG structure is a top level CBOR object which corresponds to
the DataContent type in {{RFC5652}}.
This structure allows for a top level message to be sent which could
be any of the different security services, where the security service
is identified.
The presence of this structure does not preclude a protocol to use one
of the individual structures as a stand alone component.

~~~~

*COSE_MSG {
  msg_type : uint;
  ?sign_msg: COSE-Sign;         # present if msg_type = 1
  ?encrypt_msg: COSE-Encrypt;   # present if msg_type = 2
  ?mac_msg: COSE-MAC;           # present if msg_type = 3
}
~~~~

This structure is encoded as an array by CBOR.
Descriptions of the fields:

msg_type
: indicates which of the security structures is in this block.

# Signing Structure

The signature structure allows for one or more signatures to be applied to a message payload.
There are provisions for there to be attributes about the content and about the signature to be
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

The CDDL grammar structure for a signature is:
~~~~
COSE_Sign : {
    protected : bstr | null;
    unprotected : map(tstr) | null;
    payload : bstr | null;
    signatures: COSE_signature_a* | COSE_signature;
}
~~~~

The fields is the structure have the following semantics:

protected
: contains attributes about the payload which are to be protected by the signature.
  An example of such an attribute would be the content type ('cty') attribute.
  The content is a CBOR map of attributes which is encoded to a byte stream.
  This field MUST NOT contain attributes about the signature, even if
  those attributes are common across multiple signatures.
  At least one of protected and unprotected MUST be present.

unprotected
: contains attributes about the payload which are not protected by the signature.
  An example of such an attribute would be the content type ('cty') attribute.
  This field MUST NOT contain attributes about a signature, even if
  the attributes are common across multiple signatures.
  At least one of protected and unprotected MUST be present.


payload
: contains the serialized content to be signed.  
  If the payload is not present in the message, the application is required to 
  supply the payload separately.  
  The payload is wrapped in a bstr to ensure that it is transported without changes, 
  if the payload is transported separately it is the responsibility of the application
  to ensure that it will be transported without changes.


signatures
: is either a single signature or an array of signature values.  
  It is legal to use the array of signature values for a single signature.  
  Implementations MUST be able to parse both layouts.

~~~~

COSE_signature :  {
    protected : bstr | null;
    unprotected : map(tstr) | null;
    signature : bstr;
}
*COSE_signature_a : COSE_signature;
~~~~

The fields is the structure have the following semantics:

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

~~~~

*Sig_structure : {
    body_protected : bstr | null;
    sign_protected : bstr | null;
    payload : bstr;
}
~~~~

How to compute a signature:

1. Create a Sig_structure object and populate it with the appropriate fields.

2. Create the value to be hashed by encode the Sig_structure to a byte string.

3. Sign the hash

4. Place the signature value into the appropriate signature field.

# Encryption object

In this section we describe the structure and methods to be used when
doing an encryption in COSE.
In COSE, we use the same techniques and structures for encrypting both
the plain text and the keys used to protect the text.
This is different from the approach used by both {{RFC5652}} and
{{I-D.ietf-jose-json-web-encryption}} where different structures are
used both for the plain text and for the different key management
techniques.

One of the by products of using the same technique for encrypting and
encoding both the content and the keys using the various key management
techniques, is a requirement that all of the key management techniques
use an Authenticated Encryption (AE) algorithm.
When encrypting the plain text, it is normal to use an Authenticated
Encryption with Additional Data (AEAD) algorithm.  For key management,
either AE or AEAD algorithms can be used.
See {{AE-algo}} for more details about the different types of
algorithms.

The structure has two maps where data about the content can be placed.
The data placed here is also the data which is used to control how the
decryption is to be done for this object.
When data is placed in these two structures, it is extremely poor
practice to have data which is applicable to a different level.
For example, the unprotected field at the level of a key management
decryption should not contain information either about how to
interpret the plain text (i.e. content type) or how to convert the
cipher text back to plain text (i.e. the kid for the recipient).

~~~~

COSE_encrypt {
  protected : bstr | null;   # Contains map(tstr)
  unprotected : map(tstr) | null;
  iv : bstr | null;
  aad : bstr | null;
  ciphertext : bstr | null;
  recipients : COSE_encrypt_a* | COSE_encrypt | null;
}
* COSE_encrypt_a : COSE_encrypt
~~~~

Description of the fields:

protected
: contains the information about the plain text or encryption
  process that is to be integrity protected.
  The field is encoded in CBOR as a 'bstr' if present and the value
  'null' if there is no data.
  The contents of the protected field is a CBOR map of the protected
  data names and values.
  The map is CBOR encoded before placing it into the bstr.

unprotected
: contains information about the plain text that is not integrity protected.
  If there are no field, then the value 'null' is used.

iv
: contains the initialization vector (IV), or it's equivalent, if one
  is needed by the encryption algorithm.
  If there is no IV, then the value 'null' is used.

aad
: contains additional authenticated data (aad) supplied by the application.
  This field contains information about the plain text data that is
  authenticated, but not encrypted.
  If the application does not provide this data, the value 'null' is used.

cipherText
: contains the encrypted plain text.
  If the cipherText is to be transported independently of the control
  information about the encryption process (i.e. detached content)
  then the value 'null' is encoded here.

recipients
:   contains the recipient information.
  The field can have one of three values.
  *  An array of COSE_Encrypt elements, one for each recipient.
  *  A single COSE_Element, encoded as an extension to the containing COSE_element, for a single recipient.
     Single recipients can be encoded either this way or as a single array element.
  *  A 'null' value if there are no recipients.

## Header Parameters

The header parameters discussed here are taken from {{I-D.ietf-jose-json-web-encryption}}.
For the most part they are interpreted the same here as for JOSE.

alg
:   contains the algorithm identifier used to encrypt the plain text.

epk
:   contains an ephemeral key for key agreement management algorithms.  Note however, that it is a COSE encoded key and not a JOSE encoded key.

zip
:   contains a compression algorithm identifier if the plain text was compressed prior to being encrypted.

jku
:   contains a URL pointing to a JWK Set (defined in {{I-D.ietf-jose-json-web-key}}).[^CREF3]{: source="JLS"}

[^CREF3]: Do we defined a cku as well?

cwk
:   contains the public key fields for the key used to encrypt the object.

kid
:   contains a value which can be used to select a key from one or more keys the application has access to.

cty
:   contains a string which identifies the content of the plain text.

There are a number of header fields defined in
{{I-D.ietf-jose-json-web-encryption}} which are not used.
These include PUT THE LIST OF UNUSED ITEMS HERE.  Includes 'enc'?

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
For direct encryption mode, no recipient structure is built.
All of the information about the key is placed in either the protected
or unprotected fields at the content level.
When direct encryption mode is used, it MUST be the only mode used on the message.
It is a massive security leak to have both direct encryption and a
different key management mode on the same message.

For JOSE, direct encryption key management is the only key management
method allowed for doing MAC-ed messages.
In COSE, all of the key management methods can be used for MAC-ed messages.

The COSE_encrypt structure for the recipient is organized as follows:

* The 'protected', 'iv', 'aad', 'ciphertext' and 'recipients' fields
  MUST be null.

* The plain text to be encrypted is the key from next layer down
  (usually the content layer).

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

* The 'protected', 'aad', and 'recipients' fields MUST be null.

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

* The 'protected', 'aad', and 'iv' fields all use the 'null' value.

* The plain text to be encrypted is the key from next layer down
  (usually the content layer).

* At a minimum, the 'unprotected' field SHOULD contain the 'alg'
  parameter as well as a parameter identifying the asymmetric key.

### Direct Key Agreement

Direct Key Agreement derives the CEK from the shared secret computed
by the key agreement operation.
For Direct Key Agreement, no recipient structure is built.
All of the information about the key and key agreement process is
placed in either the 'protected' or 'unprotected' fields at the
content level.

When direct key agreement mode is used, it MUST be the only mode used
on the message.
It is a security leak to have both direct key agreement and a
different key management mode on the same message.

The COSE_encrypt structure for the recipient is organized as follows:

* The 'protected', 'aad', and 'iv' fields all use the 'null' value.

* At a minimum, the 'unprotected' field SHOULD contain the 'alg'
  parameter as well as a parameter identifying the asymmetric key.

* The 'unprotected' field MUST contain the 'epk' parameter.

### Key Agreement with Key Wrapping

Key Agreement with Key Wrapping uses a randomly generated CEK.
The CEK is then encrypted using a Key Wrapping algorithm and a key
derived from the shared secret computed by the key agreement
algorithm.

The COSE_encrypt structure for the recipient is organized as follows:

* The 'protected', 'aad', and 'iv' fields all use the 'null' value.

* The plain text to be encrypted is the key from next layer down
  (usually the content layer).

* At a minimum, the 'unprotected' field SHOULD contain the 'alg'
  parameter, a parameter identifying the recipient asymmetric key, and
  a parameter with the sender's asymmetric public key.

## Encryption Algorithm for AEAD algorithms

The encryption algorithm for AEAD algorithms is fairly simple.  
In order to get a consistent encoding of the data to be authenticated, the Enc_structure is used to have canonical form of the AAD.

~~~~
*Enc_structure : {
   protected : bstr | null;
   aad : bstr | null;
}
~~~~

1.   If there is protected data, CBOR encode the map to a byte string and place in the protected field of the Enc_structure and the COSE_Encrypt structure.

1.   Copy the add field from the COSE_Encrypt structure to the Enc_Structure.

1.   Encode the Enc_structure using a CBOR Canonical encoding {{CBOR-Canonical}} to get the AAD value.

1.   Encrypt the plain text and place it in the ciphertext field.  The
     AAD value is passed in as part of the encryption process.

1.   For recipient of the message, recursively perform the encryption
     algorithm for that recipient using the encryption key as the
     plain text.

## Encryption algorithm for AE algorithms


1.   Verify that the protected field is empty.

1.   Verify that the aad field is empty.

1.   Encrypt the plain text and place in the ciphertext field.

# MAC objects

add description

~~~~

COSE_mac :  {
   protected : bstr | null;
   unprotected" : map(tstr) | null;
   payload : bstr;
   tag : bstr;
   recipients : COSE_encrypt_a* | COSE_encrypt | null;
}
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


~~~~
*MAC_structure : {
   protected : bstr | null;
   payload : bstr;
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

~~~~

COSE_Key : map(tstr, *) {
    "kty" : tstr;
    ?"use" : tstr;
    ?"key_ops" : tstr*;
    ?"alg" : tstr;
    ?"kid" : tstr;
}

*COSE_KeySet : COSE_Key*;
~~~~

The element "kty" is a required element in a COSE_Key map.  
All other elements are optional and not all of the elements listed in {{I-D.ietf-jose-json-web-key}} or {{I-D.ietf-jose-json-web-algorithms}} have been listed here even though they can all appear in a COSE_Key map.

The "key_ops" element is prefered over the "use" element as the information provided that way is more finely detailed about the operations allowed.  It is strongly suggested that this element be present for all keys.

The same fields defined in {{I-D.ietf-jose-json-web-key}} are used
here with the following changes in rules:

> Any item which is base64 encoded in JWK, is bstr encoded for COSE.

> Any item which is integer encoded in JWK, is int encoded for COSE.

> Any item which is string (but not base64) encoded in JWK, is tstr encoded for COSE.

> Exceptions to this are the following fields:
> kid
> : is always bstr encoded rather than tstr encoded.
>   This change in encoded is due to the fact that frequently, values
>   such as a hash of the public key is used for a kid value.
>   Since the field is defined as not having a specific structure,
>   making it binary rather than textual makes sense.

# CBOR Encoder Restrictions {#CBOR-Canonical}

There as been an attempt to resrict the number of places where the document 
needs to impose restrictions on how the CBOR Encoder needs to work.  We have
managed to narrow it down to the following restrictions:

> The restriction applies only the encoding the Sig_structure.

> The rules for Canonical CBOR (Section 3.9 of RFC 7049) MUST be used in these
> locations.  The main rule that needs to be enforced is that all lengths
> in these structures MUST be encoded such that they are encoded using definite lengths 
> and the minimum length encoding is used.

# IANA Considerations

There are IANA considerations to be filled in.

# Security Considerations

There are security considertions:

1.  Protect private keys

2.  MAC messages with more than one recipient means one cannot figure out who sent the message

3.  Use of direct key with other recipient structures hands the key to other recipients.

4.  Use of direcct ECDH direct encryption is easy for people to leak information on if there are other recipients in the message.



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
However, if one uses a key management technique such as RSA-KEY (see Appendix A of RSA-KEM {{RFC5990}}, then
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

~~~~

[2, null, {"alg": "HS256"}, h'436f6e74656e7420537472696e67',
h'78956d858ee6c026ac630063627a4ce98d3003bc68e7c1e53b5b468331b69f93',
null, {"alg": "dir", "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"},
null, null, null]
~~~~


## Wrapped MAC

This example has some features that are in questions but not yet incorporated in the document.

To make it easier to read, this uses CBOR's diagnostic notation rather than a binary dump.

Encoded in CBOR - 162 bytes, content is 14 bytes long

~~~~

[2, null, {"alg": "HS256"}, h'436f6e74656e7420537472696e67',
h'2ee486376b8b2a61fe526589ceb456e20919a68ebc0458431ef3e13ffe7bf698',
null, {"alg": "A128KW", "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a"},
null,
h'4f6e9e6a3e43b79561ef602a2a9e629a437e8df90a7ff361acbdb1076c955d0f25c660a67aee1bdf',
null]
~~~~


## Direct ECDH

This example has some features that are in questions but not yet incorporated in the document.

To make it easier to read, this uses CBOR's diagnostic notation rather than a binary dump.

Encoded in CBOR - 216 bytes, content is 14 bytes long

~~~~

[1, null, {"alg": "A128GCM"}, h'656d6a73ccf1b35fb99044e1',
h'd7b27b67a81b212ee513b148454fe2d571d51bb679239769f5d2299bb96b',
null, {"alg": "ECDH-ES", "epk": {"kty": "EC", "crv": "P-256",
"x": h'00b81ff1de0eeba27613027526d83b5f4cbffaca433488e3805e7a75c43bd1b966',
"y": h'00d142a334ac8790dc821abe9362434daeb00c1b8b076843e51a4a4717b30c54ce'},
"kid": "meriadoc.brandybuck@buckland.example"}, null, null, null]
~~~~


## Multiple Signers

This example has some features that are in questions but not yet cooperated in the document.

To make it easier to read, this uses CBOR's diagnostic notation rather than a binary dump.

Encoded in CBOR - 491 bytes, content is 14 bytes long

~~~~

[0, null, null, h'436f6e74656e7420537472696e67', [
[null, {"kid": "bilbo.baggins@hobbiton.example", "alg": "PS256"},
h'5afe80ec9f208b4719a3bd688c803a3154b1ff25af86e054173ad6ddf71ba77a4a2b793beed077a4e1a8a69ac1277c457f636691cb4a7d3dc67b47ec84c067076b720236bae498bdb21deebbc0a0f525f9a24b336d51e2b3effd67df3e051405a3599aed83b8a8e94e4194dded2f661e5e6894825779b79b463bd4f477f33356cf8aecfa8a543344d2620145be8a72a712f985457040140176164c77cdae7cc480ae4357683cce79b97ddb10f390862a242aae1aa391cc730b1631f020874a8a6efc77b08f027323e2c4ae85eeb3e5dc715e0e2fa8aec63fb828d7a2c45e361e249117bd8b41e1e12388412d8ce3809c9a2172afda5ca7c5839896825da66a50'],
[null, {"kid": "bilbo.baggins@hobbiton.example", "alg": "ES512"},
h'00e9769c05afb2d93baf5a0c2cace1747b5091f50596831911c67ebf76f4220adb53698fe7831000d526887893d67de05ead1bbe378ce9e9731bda4cd37f53dcf8d40186c46d872795b566682c113cc9d5bf5a8c5321fd50a003237115decf0cb8b09e5c3cb50bc2203af45bebd51e6c4d0ec51170d5b9ac1b21a2017a50d7c15b6de8f9']]]
~~~~


