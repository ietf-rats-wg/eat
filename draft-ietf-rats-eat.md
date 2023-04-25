---
v: 3

title: The Entity Attestation Token (EAT)
abbrev: EAT
docname: draft-ietf-rats-eat-latest
cat: std

consensus: true
stream: IETF
ipr: trust200902
area: Security
wg: RATS
kw: signing attestation cbor

pi:
  toc: 'yes'
  tocdepth: '4'
  sortrefs: 'yes'
  symrefs: 'yes'
  compact: 'yes'
  subcompact: 'no'
  rfcedstyle: 'yes'



author:
- ins: L. Lundblade
  name: Laurence Lundblade
  org: Security Theory LLC
  email: lgl@securitytheory.com
- ins: G. Mandyam
  name: Giridhar Mandyam
  org: Qualcomm Technologies Inc.
  street: 5775 Morehouse Drive
  city: San Diego
  region: California
  country: USA
  phone: "+1 858 651 7200"
  email: mandyam@qti.qualcomm.com
- ins: J. O'Donoghue
  name: Jeremy O'Donoghue
  org: Qualcomm Technologies Inc.
  street: 279 Farnborough Road
  city: Farnborough
  code: GU14 7LS
  country: United Kingdom
  phone: +44 1252 363189
  email: jodonogh@qti.qualcomm.com
- ins: C. Wallace
  name: Carl Wallace
  org: Red Hound Software, Inc.
  email: carl@redhoundsoftware.com

contributor:
- name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
- name: Thomas Fossati
  org: Arm Limited
  email: thomas.fossati@arm.com
- name: Miguel Ballesteros
- name: Michael Richardson
  org: Sandelman Software Works
  email: mcr+ietf@sandelman.ca
- name: Patrick Uiterwijk
- name: Mathias Brossard
- name: Hannes Tschofenig
  org: Arm Limited
  email: hannes.tschofenig@arm.com
- name: Paul Crowley

normative:
  RFC7515:
  RFC8949: cbor
  RFC7252:
  RFC7519:
  RFC8126:
  RFC8259:
  RFC8392:
  RFC8610: cddl
  RFC8792:
  RFC3986:
  RFC9052:
  RFC9090:
  RFC9165: cddlplus
  RFC4648:
  RFC2252:

  WGS84:
    target: "https://earth-info.nga.mil/php/download.php?file=coord-wgs84"
    title: WORLD GEODETIC SYSTEM 1984, NGA.STND.0036_1.0.0_WGS84
    author:
    - org: National Geospatial-Intelligence Agency (NGA)
    date: 2014-07-08

  IANA.CWT.Claims: IANA.cwt

  IANA.JWT.Claims: IANA.jwt

  IANA.COSE.Algorithms: IANA.cose

  ThreeGPP.IMEI:
    target: https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=729
    title: 3rd Generation Partnership Project; Technical Specification Group Core Network and Terminals; Numbering, addressing and identification
    author:
    - org: 3GPP
    date: 2019

  CoSWID: I-D.ietf-sacm-coswid

  DLOA:
    target: https://globalplatform.org/wp-content/uploads/2015/12/GPC_DigitalLetterOfApproval_v1.0.pdf
    title: Digital Letter of Approval
    date: November 2015


  PEN:
    target: https://pen.iana.org/pen/PenApplication.page
    title: Private Enterprise Number (PEN) Request


  IANA.cbor-tags:

  SPDX:
    title: Software Package Data Exchange (SPDX)
    target: https://spdx.dev/wp-content/uploads/sites/41/2020/08/SPDX-specification-2-2.pdf
    date: 2020

  CycloneDX:
     title: CycloneDX
     target: https://cyclonedx.org/docs/1.4/json/
     date: false


  IANA.core-parameters:

  SUIT.Manifest: I-D.ietf-suit-manifest


informative:
  RFC4122:
  RFC4949:
  RFC7120:
  RFC9039:

  RATS.Architecture: I-D.ietf-rats-architecture

  BirthdayAttack:
    title: Birthday attack
    target: https://en.wikipedia.org/wiki/Birthday_attack.
    date: false

  IEEE.802.1AR: DOI.10.1109/IEEESTD.2018.8423794

  W3C.GeoLoc: W3C.REC-geolocation-API-20131024

  OUI.Guide:
    title: Guidelines for Use of Extended Unique Identifier (EUI), Organizationally Unique Identifier (OUI), and Company ID (CID)
    date: August 2017
    target: https://standards.ieee.org/content/dam/ieee-standards/standards/web/documents/tutorials/eui.pdf

  OUI.Lookup:
    title: IEEE Registration Authority Assignments
    target: https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries
    date: false

  IEEE-RA:
    title: IEEE Registration Authority
    target: https://standards.ieee.org/products-services/regauth/index.html
    date: false

  IEEE.802-2001: DOI.10.1109/IEEESTD.2014.6847097

  COSE.X509.Draft: I-D.ietf-cose-x509

  CBOR.Cert.Draft: I-D.ietf-cose-cbor-encoded-cert

  UCCS: I-D.ietf-rats-uccs

  JTAG:
    title: IEEE Standard for Reduced-Pin and Enhanced-Functionality Test Access Port and Boundary-Scan Architecture
    target: https://ieeexplore.ieee.org/document/5412866
    date: February 2010

  EAT.media-types: I-D.ietf-rats-eat-media-type

--- abstract

An Entity Attestation Token (EAT) provides an attested claims set
that describes state and characteristics of an entity,
a device like a smartphone, IoT device, network equipment or such.  This claims set is used by a
relying party, server or service to determine how much it wishes to trust the entity.

An EAT is either a CBOR Web Token (CWT) or JSON Web Token (JWT) with attestation-oriented
claims.

--- middle

# Introduction

An Entity Attestation Token (EAT) is a message or token made up of claims about an entity.
An entity may be a device, some hardware or some software.
The claims are ultimately used by a relying party who decides if and how it will interact with the entity.
The relying party may choose to trust, not trust or partially trust the entity.
For example, partial trust may be allowing a monetary transaction only up to a limit.

The security model and goal for attestation are unique and are not the same as for other security standards like those for server authentication, user authentication and secured messaging.
The reader is assumed to be familiar with the goals and security model for attestation as described in {{RATS.Architecture}}.

This document defines some common claims that are potentially of broad use.
EAT additionally allows proprietary claims and for further claims to be standardized.
Here are some examples:

* Make and model of manufactured consumer device
* Make and model of a chip or processor, particularly for a security-oriented chip
* Identification and measurement of the software running on a device
* Configuration and state of a device
* Environmental characteristics of a device like its GPS location
* Formal certifications received

EAT is constructed to support a wide range of use cases.

No single set of claims can accommodate all use cases so EAT is constructed as a framework for defining specific attestation tokens for specific use cases.
In particular, EAT provides a profile mechanism to be able to clearly specify the claims needed, the cryptographic algorithms that should be used, and other characteristics for a particular token and use case.
{{profiles}} describes profile contents and provides a profile that is suitable for constrained device use cases.

The entity's EAT implementation generates the claims and typically signs them with an attestation key.
It is responsible for protecting the attestation key.
Some EAT implementations will use components with very high resistance to attack like TPMs or secure elements.
Others may rely solely on simple software defenses.

Nesting of tokens and claims sets is accommodated for composite devices that have multiple subsystems.

An EAT may be encoded in either JSON {{RFC8259}} or CBOR {{RFC8949}} as needed for each use case.
EAT is built on CBOR Web Token (CWT) {{RFC8392}} and JSON Web Token (JWT) {{RFC7519}} and inherits all their characteristics and their security mechanisms.
Like CWT and JWT, EAT does not imply any message flow.

## Entity Overview

The document uses the term "entity" to refer to the target of an EAT. Many of the claims defined in this document are claims about an entity, which is equivalent to an attesting environment as defined in [RATS.architecture]. An entity may be the whole device, a subsystem, a subsystem of a subsystem, etc.
Correspondingly, EAT allows claims to be organized using mechanisms like submodules and nested EATs (see {{submods}}).
The entity to which a claim applies is the submodule in which it appears, or to the top-level entity if it doesn't appear in a submodule.

An entity also corresponds to a "system component", as defined in the Internet Security Glossary {{RFC4949}}, except that in the EAT context an "entity" never refers to a person or organization.

Some examples of entities:

* A Secure Element
* A TEE
* A network card in a router
* A router, perhaps with each network card in the router a submodule
* An IoT device
* An individual process
* An app on a smartphone
* A smartphone with many submodules for its many subsystems
* A subsystem in a smartphone like the modem or the camera

An entity may have strong security defenses against hardware invasive attacks.
It may also have low security, having no special security defenses.
There is no minimum security requirement to be an entity.


## EAT as a Framework

EAT is a framework for defining attestation tokens for specific use cases, not a specific token definition.
While EAT is based on and compatible with CWT and JWT, it can also be described as:

* An identification and type system for claims in claims-sets
* Definitions of common attestation-oriented claims
* Claims defined in CDDL and serialized using CBOR or JSON
* Security envelopes based on COSE and JOSE
* Nesting of claims sets and tokens to represent complex and compound devices
* A profile mechanism for specifying and identifying specific tokens for specific use cases

EAT uses the name/value pairs the same as CWT and JWT to identify individual claims.
{{theclaims}} defines common attestation-oriented claims that are added to the CWT and JWT IANA registries.
As with CWT and JWT, no claims are mandatory and claims not recognized should be ignored.

Unlike, but compatible with CWT and JWT, EAT defines claims using Concise Data Definition Language (CDDL) {{RFC8610}}.
In most cases the same CDDL definition is used for both the CBOR/CWT serialization and the JSON/JWT serialization.

Like CWT and JWT, EAT uses COSE and JOSE to provide authenticity, integrity and optionally confidentiality.
EAT places no new restrictions on cryptographic algorithms, retaining all the cryptographic flexibility of CWT, COSE, JWT and JOSE.

EAT defines a means for nesting tokens and claims sets to accommodate composite devices that have multiple subsystems and multiple attesters.
Full tokens with security envelopes may be embedded in an enclosing token.
The nested token and the enclosing token do not have to use the same encoding (e.g., a CWT may be enclosed in a JWT).

EAT adds the ability to detach claims sets and send them separately from a security enveloped EAT that contains a digest of the detached claims set.

This document registers no media or content types for the identification of the type of EAT, its serialization encoding or security envelope.
The definition and registration of EAT media types is addressed in {{EAT.media-types}}.

Finally, the notion of an EAT profile is introduced that facilitates the creation of narrowed definitions of EAT tokens for specific use cases in follow-on documents.


## Operating Model and RATS Architecture

EAT follows the operational model described in Figure 1 in {{RATS.Architecture}}. To summarize, an attester generates evidence in the form of a claims set describing various characteristics of an entity.
Evidence is usually signed by a key that proves the attester and the evidence it produces are authentic.
The claims set includes a nonce or some other means to assure freshness.

A verifier confirms an EAT is valid by verifying the signature and may vet some claims using reference values.
The verifier then produces attestation results, which may also be represented as an EAT.
The attestation results are provided to the relying party, which is the ultimate consumer of the Remote Attestation Procedure.
The relying party uses the attestation results as needed for its use case, perhaps allowing an entity to access a network, allowing a financial transaction or such.
In some cases, the verifier and relying party are not distinct entities.

### Relationship between Evidence and Attestation Results {#relationship}

Any claim defined in this document or in the IANA CWT or JWT registry may be used in evidence or attestation results. The relationship of claims in attestation results to evidence is fundamentally governed by the verifier and the verifier's policy.

A common use case is for the verifier and its policy to perform checks, calculations and processing with evidence as the input to produce a summary result in attestation results that indicates the overall health and status of the entity.
For example, measurements in evidence may be compared to reference values the results of which are represented as a simple pass/fail in attestation results.

It is also possible that some claims in the Evidence will be forwarded unmodified to the relying party in attestation results.
This forwarding is subject to the verifier's implementation and policy.
The relying party should be aware of the verifier's policy to know what checks it has performed on claims it forwards.

The verifier may modify claims it forwards, for example, to implement a privacy preservation functionality. It is also possible the verifier will put claims in the attestation results that give details about the entity that it has computed or looked up in a database.
For example, the verifier may be able to put an "oemid" claim in the attestation results by performing a look up based on a UEID (serial number) it received in evidence.

This specification does not establish any normative rules for the verifier to follow, as these are a matter of local policy.
It is up to each relying party to understand the processing rules of each verifier to know how to interpret claims in attestation results.


# Terminology

{::boilerplate bcp14-tagged}

In this document, the structure of data is specified in CDDL {{-cddl}} {{-cddlplus}}.

The examples in {{examples}} use CBOR diagnostic notation defined in {{Section 8 of -cbor}} and {{Appendix G of -cddl}}.

This document reuses terminology from JWT {{RFC7519}} and CWT {{RFC8392}}:

Base64url Encoding:
: Base64url encoding is as described in {{RFC7515}}, i.e., using URL- and filename-safe character set {{RFC4648}} with all trailing '=' characters omitted and without the inclusion of any line breaks, whitespace, or other additional characters.

Claim:
: A piece of information asserted about a subject. A claim is represented as pair with a value and either a name or key to identify it.

Claim Name:
: A unique text string that identifies the claim. It is used as the claim name for JSON encoding.

Claim Key:
: The CBOR map key used to identify a claim. (The term "Claim Key" comes from CWT. This document, like COSE, uses the term "label" to refer to CBOR map keys to avoid confusion with cryptographic keys.)

Claim Value:
: The value portion of the claim. A claim value can be any CBOR data item or JSON value.

Claims Set:
: The CBOR map or JSON object that contains the claims conveyed by the CWT or JWT.

This document reuses terminology from RATS Architecure {{RATS.Architecture}}:

Attester:
: A role performed by an entity (typically a device) whose evidence must be appraised in order to infer the extent to which the attester is considered trustworthy, such as when deciding whether it is authorized to perform some operation.

Verifier:
: A role that appraises the validity of evidence about an attester and produces attestation results to be used by a relying party.

Relying Party:
: A role that depends on the validity of information about an attester, for purposes of reliably applying application specific actions. Compare /relying party/ in [RFC4949].

Evidence:
: A set of claims generated by an attester to be appraised by a verifier. Evidence may include configuration data, measurements, telemetry, or inferences.

Attestation Results:
: The output generated by a verifier, typically including information about an attester, where the verifier vouches for the validity of the results

Reference Values:
: A set of values against which values of claims can be compared as part of applying an appraisal policy for evidence.  Reference Values are sometimes referred to in other documents as known-good values, golden measurements, or nominal values, although those terms typically assume comparison for equality, whereas here reference values might be more general and be used in any sort of comparison.

Endorsement:
: A secure statement that an Endorser vouches for the integrity of an attester's various capabilities such as claims collection and evidence signing.

This document reuses terminology from CDDL {{RFC8610}}:

Group Socket:
: refers to the mechanism by which a CDDL definition is extended, as described in [RFC8610] and [RFC9165]

# Top-Level Token Definition

An EAT is a "message", a "token", or such whose content is a Claims-Set about an entity or some number of entities. An EAT MUST always contains a Claims-Set.

Authenticity and integrity protection MUST be provided for EATs. This document relies on CWT or JWT for this purpose.
Extensions to this specification MAY use other methods of protection.

The identification of a protocol element as an EAT follows the general conventions used for CWTs and JWTs.
Identification depends on the protocol carrying the EAT.
In some cases it may be by media type (e.g., in a HTTP Content-Type field).
In other cases it may be through use of CBOR tags.
There is no fixed mechanism across all use cases.

This document also defines a new top-level message, the detached EAT bundle (see {{DEB}}), which holds a collection of detached claims sets and an EAT that provides integrity and authenticity protection for them.
Detached EAT bundles can be either CBOR or JSON encoded.

The following CDDL defines the top-level `$EAT-CBOR-Tagged-Token`, `$EAT-CBOR-Untagged-Token` and `$EAT-JSON-Token-Formats` sockets (see {{Section 3.9 of -cddl}}), enabling future token formats to be defined.
Any new format that plugs into one or more of these sockets MUST be defined by an IETF standards action.
Of particular use may be a token type that provides no direct authenticity or integrity protection for use with transports mechanisms that do provide the necessary security services {{UCCS}}.

Nesting of EATs is allowed and defined in {{Nested-Token}}.
This includes the nesting of an EAT that is a different format than the enclosing EAT, i.e., the nested EAT may be encoded using CBOR and the enclosing EAT encoded using JSON or vice versa.
The definition of Nested-Token references the CDDL defined in this section.
When new token formats are defined, the means for identification in a nested token MUST also be defined.

~~~~CDDL
{::include cddl/eat-cbor.cddl}
~~~~

~~~~CDDL
{::include cddl/eat-json.cddl}
~~~~


# The Claims {#theclaims}

This section describes new claims defined for attestation that are to be added to the CWT {{IANA.CWT.Claims}} and JWT {{IANA.JWT.Claims}} IANA registries.

All definitions, requirements, creation and validation procedures, security considerations, IANA registrations and so on from CWT and JWT carry over to EAT.

This section also describes how several extant CWT and JWT claims apply in EAT.

The set of claims that an EAT must contain to be considered valid is context dependent and is outside the scope of this specification.
Specific applications of EATs will require implementations to understand and process some claims in particular ways.
However, in the absence of such requirements, all claims that are not understood by implementations MUST be ignored.

CDDL, along with a text description, is used to define each claim
independent of encoding.  Each claim is defined as a CDDL group.
In {{encoding}} on encoding, the CDDL groups turn into CBOR map entries and JSON name/value pairs.

Each claim defined in this document is added to the `$$Claims-Set-Claims` group socket. Claims defined by other specifications MUST also be added to the `$$Claims-Set-Claims` group socket.

All claims in an EAT MUST use the same encoding except where otherwise explicitly stated (e.g., in a CBOR-encoded token, all claims must be CBOR-encoded).

This specification includes a CDDL definition of most of what is defined in {{RFC8392}}.
Similarly, this specification includes CDDL for most of what is defined in {{RFC7519}}.
These definitions are in {{CDDL_for_CWT}} and are not normative.

Each claim described has a unique text string and integer that identifies it.
CBOR-encoded tokens MUST use only the integer for claim keys.
JSON-encoded tokens MUST use only the text string for claim names.



## eat_nonce (EAT Nonce) Claim {#nonce}

An EAT nonce is either a byte or text string or an array of byte or text strings.
The array option supports multistage EAT verification and consumption.

A claim named "nonce" was defined and registered with IANA for JWT, but MUST NOT be used because it does not support multiple nonces.
No previous "nonce" claim was defined for CWT.
To distinguish from the previously defined JWT "nonce" claim, this claim is named "eat_nonce" in JSON-encoded EATs. The CWT nonce defined
here is intended for general purpose use and retains the "Nonce" claim name instead of an EAT-specific name.

An EAT nonce MUST have at least 64 bits of entropy.
A maximum EAT nonce size is set to limit the memory required for an implementation.
All receivers MUST be able to accommodate the maximum size.

In CBOR, an EAT nonce is a byte string.
The minimum size is 8 bytes.
The maximum size is 64 bytes.

In JSON, an EAT nonce is a text string.
It is assumed that only characters represented by the lower 7 bits of each byte will be used, so the text string must be one-seventh longer because the 8th bit doesn't contribute to entropy.
The minimum size for JSON-encoded EATs is 10 bytes and the maximum size is 74 bytes.


~~~~CDDL
{::include nc-cddl/nonce.cddl}
~~~~

## Claims Describing the Entity

The claims in this section describe the entity itself.
They describe the entity whether they occur in evidence or occur in attestation results.
See {{relationship}} for discussion on how attestation results relate to evidence.


### ueid (Universal Entity ID) Claim {#UEID}

The "ueid" claim conveys a UEID, which identifies an individual manufactured entity like a
mobile phone, a water meter, a Bluetooth speaker or a networked
security camera. It may identify the entire entity or a submodule.
It does not identify types, models or classes of
entities. It is akin to a serial number, though it does not have to be
sequential.

UEIDs MUST be universally and globally unique across manufacturers
and countries. UEIDs MUST also be unique across protocols and systems,
as tokens are intended to be embedded in many different protocols and
systems. No two products anywhere, even in completely different
industries made by two different manufacturers in two different
countries should have the same UEID (if they are not global and
universal in this way, then relying parties receiving them will have
to track other characteristics of the entity to keep entities distinct
between manufacturers).

UEIDs are not designed for direct use by humans (e.g., printing on
the case of a device), so no textual representation is defined.

There are privacy considerations for UEIDs. See {{ueidprivacyconsiderations}}.

A Device Identifier URN is registered for UEIDs. See {{registerueidurn}}.

~~~~CDDL
{::include nc-cddl/ueid.cddl}
~~~~

#### Rules for Creating UEIDs

These rules are solely for the creation of UEIDs.
The consumer need not have any awareness of them.

A UEID is constructed of a single type byte followed by the unique bytes for that type.
The type byte assures global uniqueness of a UEID even if the unique bytes for different types are accidentally the same.

UEIDS are variable length to accommodate the types defined here and future-defined types.

UEIDs SHOULD NOT be longer than 33 bytes.
If they are longer, there is no guarantee that a receiver will be able to accept them.
See {{UEID-Design}}.

A UEID is permanent. It MUST never change for a given entity.

The different types of UEIDs 1) accommodate different manufacturing processes, 2) accommodate small UEIDs, 3) provide an option that doesn't require registration fees and central administration.
Creation of new types requires a Standards Action {{RFC8126}}.

A manufacturer of entities MAY use different types for different products.
They MAY also change from one type to another for a given product or use one type for some items of a given produce and another type for other.

| Type Byte | Type Name | Specification |
| 0x01 | RAND | This is a 128, 192 or 256-bit random number generated once and stored in the entity. This may be constructed by concatenating enough identifiers to make up an equivalent number of random bits and then feeding the concatenation through a cryptographic hash function. It may also be a cryptographic quality random number generated once at the beginning of the life of the entity and stored. It MUST NOT be smaller than 128 bits. See the length analysis in {{UEID-Design}}. |
| 0x02 | IEEE EUI | This uses the IEEE company identification registry. An EUI is either an EUI-48, EUI-60 or EUI-64 and made up of an OUI, OUI-36 or a CID, different registered company identifiers, and some unique per-entity identifier. EUIs are often the same as or similar to MAC addresses. This type includes MAC-48, an obsolete name for EUI-48. (Note that while entities with multiple network interfaces may have multiple MAC addresses, there is only one UEID for an entity) {{IEEE.802-2001}}, {{OUI.Guide}}. |
| 0x03 | IMEI | This is a 14-digit identifier consisting of an 8-digit Type Allocation Code and a 6-digit serial number allocated by the manufacturer, which SHALL be encoded as byte string of length 14 with each byte as the digit's value (not the ASCII encoding of the digit; the digit 3 encodes as 0x03, not 0x33). The IMEI value encoded SHALL NOT include Luhn checksum or SVN information. See {{ThreeGPP.IMEI}}. |
{: #ueid-types-table title="UEID Composition Types"}

#### Rules for Consuming UEIDs

For the consumer, a UEID is solely a globally unique opaque identifier.
The consumer does not and should not have any awareness of the rules and structure used to achieve global uniqueness.

All implementations MUST be able to receive UEIDs up to 33 bytes long.
33 bytes is the longest defined in this document and gives necessary entropy for probabilistic uniqueness.

The consumer of a UEID MUST treat it as a completely opaque string of bytes and MUST NOT make any use of its internal structure.
The reasons for this are:

* UEIDs types vary freely from one manufacturer to the next.

* New types of UEIDs may be defined.

* The manufacturer of an entity is allowed to change from one type of UEID to another anytime they want.

For example, when the consumer receives a type 0x02 UEID, they should not use the OUI part to identify the manufacturer of the device because there is no guarantee all UEIDs will be type 0x02.
Different manufacturers may use different types.
A manufacturer may make some of their product with one type and others with a different type or even change to a different type for newer versions of their product.
Instead, the consumer should use the "oemid" claim.


### sueids (Semi-permanent UEIDs) Claim (SUEIDs)

The "sueids" claim conveys one or more semi-permanent UEIDs (SUEIDs). An SUEID has the same format, characteristics and requirements as a UEID, but MAY change to a different value on entity life-cycle events.
An entity MAY have both a UEID and SUEIDs, neither, one or the other.

Examples of life-cycle events are change of ownership, factory reset and on-boarding into an IoT device management system.
It is beyond the scope of this document to specify particular types of SUEIDs and the life-cycle events that trigger their change.
An EAT profile MAY provide this specification.

There MAY be multiple SUEIDs.
Each has a text string label the purpose of which is to distinguish it from others.
The label MAY name the purpose, application or type of the SUEID.
For example, the label for the SUEID used by XYZ Onboarding Protocol could thus be "XYZ".
It is beyond the scope of this document to specify any SUEID labeling schemes.
They are use case specific and MAY be specified in an EAT profile.

If there is only one SUEID, the claim remains a map and there still MUST be a label.

An SUEID provides functionality similar to an IEEE LDevID {{IEEE.802.1AR}}.

There are privacy considerations for SUEIDs. See {{ueidprivacyconsiderations}}.

A Device Identifier URN is registered for SUEIDs. See {{registerueidurn}}.

~~~~CDDL
{::include nc-cddl/sueids.cddl}
~~~~


### oemid (Hardware OEM Identification) Claim {#oemid}

The "oemid" claim identifies the Original Equipment Manufacturer (OEM) of the hardware.
Any of the three forms described below MAY be used at the convenience of the claim sender.
The receiver of this claim MUST be able to handle all three forms.

#### Random Number Based OEMID

The random number based OEMID MUST always be 16 bytes (128 bits) long.

The OEM MAY create their own ID by using a cryptographic-quality random number generator.
They would perform this only once in the life of the company to generate the single ID for said company.
They would use that same ID in every entity they make.
This uniquely identifies the OEM on a statistical basis and is large enough should there be ten billion companies.

In JSON-encoded tokens this MUST be base64url encoded {{RFC4648}}.

#### IEEE Based OEMID

The IEEE operates a global registry for MAC addresses and company IDs.
This claim uses that database to identify OEMs. The contents of the
claim may be either an IEEE MA-L, MA-M, MA-S or an IEEE CID
{{IEEE-RA}}.  An MA-L, formerly known as an OUI, is a 24-bit value
used as the first half of a MAC address. MA-M similarly is a 28-bit
value uses as the first part of a MAC address, and MA-S, formerly
known as OUI-36, a 36-bit value.  Many companies already have purchased
one of these. A CID is also a 24-bit value from the same space as an
MA-L, but not for use as a MAC address.  IEEE has published Guidelines
for Use of EUI, OUI, and CID {{OUI.Guide}} and provides a lookup
service {{OUI.Lookup}}.

Companies that have more than one of these IDs or MAC address blocks
SHOULD select one and prefer that for all their entities.

Commonly, these are expressed in Hexadecimal Representation as described in
{{IEEE.802-2001}}. It is also called the Canonical format. When this claim is
encoded the order of bytes in the bstr are the same as the order in the
Hexadecimal Representation. For example, an MA-L like "AC-DE-48" would
be encoded in 3 bytes with values 0xAC, 0xDE, 0x48.

This format is always 3 bytes in size in CBOR.

In JSON-encoded tokens, this MUST be base64url encoded and always 4 bytes.

#### IANA Private Enterprise Number Based OEMID

IANA maintains a registry for Private Enterprise Numbers (PEN) {{PEN}}. A PEN is an integer that identifies an enterprise and may be
used to construct an object identifier (OID) relative to the following OID arc that is managed by IANA:  iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1).

For EAT purposes, only the integer value assigned by IANA as the PEN is relevant, not the full OID value.

In CBOR this value MUST be encoded as a major type 0 integer and is typically 3 bytes.
In JSON, this value MUST be encoded as a number.

~~~~CDDL
{::include nc-cddl/oemid.cddl}
~~~~


### hwmodel (Hardware Model) Claim

The "hwmodel" claim differentiates hardware models, products and variants manufactured by a particular OEM, the one identified by OEM ID in {{oemid}}.
It MUST be unique within a given OEM ID.
The concatenation of the OEM ID and "hwmodel" give a global identifier of a particular product.

The granularity of the model identification is for each OEM to decide.
It may be very granular, perhaps including some version information.
It may be very general, perhaps only indicating top-level products.

The "hwmodel" claim is for use in protocols and not for human consumption.
The format and encoding of this claim should not be human-readable to discourage use other than in protocols.
If this claim is to be derived from an already-in-use human-readable identifier, it can be run through a hash function.

There is no minimum length so that an OEM with a very small number of models can use a one-byte encoding.
The maximum length is 32 bytes.
All receivers of this claim MUST be able to receive this maximum size.

The receiver of this claim MUST treat it as a completely opaque string of bytes, even if there is some apparent naming or structure.
The OEM is free to alter the internal structure of these bytes as long as the claim continues to uniquely identify its models.

~~~~CDDL
{::include cddl/hardware-model.cddl}
~~~~


### hwversion (Hardware Version) Claim

The "hwversion" claim is a text string the format of which is set by each manufacturer.
The structure and sorting order of this text string can be specified using the version-scheme item from CoSWID {{CoSWID}}.
It is useful to know how to sort versions so the newer can be distinguished from the older.

~~~~CDDL
{::include nc-cddl/hardware-version.cddl}
~~~~


### swname (Software Name) Claim

The "swname" claim contains a very simple free-form text value for naming the software used by the entity.
Intentionally, no general rules or structure are set.
This will make it unsuitable for use cases that wish precise naming.

If precise and rigourous naming of the software for the entity is needed, the "manifests" claim {{manifests}} may be used instead.

~~~~CDDL
{::include nc-cddl/software-name.cddl}
~~~~


### swversion (Software Version) Claim

The "swversion" claim makes use of the CoSWID version-scheme item to give a simple version for the software.
A full CoSWID manifest or other type of manifest can be instead if this is too simple.

~~~~CDDL
{::include nc-cddl/software-version.cddl}
~~~~


### oemboot (OEM Authorized Boot) Claim

An "oemboot" claim with value of true indicates the entity booted with software authorized by the manufacturer of the entity as indicated by the "oemid" claim described in {{oemid}}.
It indicates the firmware and operating system are fully under control of the OEM and may not be replaced by the end user or even the enterprise that owns the device.
The means of control may be by cryptographic authentication of the software, by the software being in ROM, a combination of the two or other.
If this claim is present the "oemid" claim SHOULD always also be present.

~~~~CDDL
{::include nc-cddl/oem-boot.cddl}
~~~~


### dbgstat (Debug Status) Claim

The "dbgstat" claim applies to entity-wide or submodule-wide debug facilities of the
entity like {{JTAG}} and diagnostic hardware built into
chips. It applies to any software debug facilities related to root,
operating system or privileged software that allow system-wide memory
inspection, tracing or modification of non-system software like user
mode applications.

This characterization assumes that debug facilities can be enabled and
disabled in a dynamic way or be disabled in some permanent way, such
that no enabling is possible. An example of dynamic enabling is one
where some authentication is required to enable debugging. An example
of permanent disabling is blowing a hardware fuse in a chip. The specific
type of the mechanism is not taken into account. For example, it does
not matter if authentication is by a global password or by per-entity
public keys.

As with all claims, the absence of the "dbgstat" claim means it is not reported.

This claim is not extensible so as to provide a common interoperable description of debug status.
If a particular implementation considers this claim to be inadequate, it can define its own proprietary claim.
It may consider including both this claim as a coarse indication of debug status and its own proprietary claim as a refined indication.

The higher levels of debug disabling requires that all debug disabling
of the levels below it be in effect. Since the lowest level requires
that all of the target's debug be currently disabled, all other levels
require that too.

There is no inheritance of claims from a submodule to a superior
module or vice versa. There is no assumption, requirement or guarantee
that the target of a superior module encompasses the targets of
submodules. Thus, every submodule must explicitly describe its own
debug state. The receiver of an EAT MUST NOT
assume that debug is turned off in a submodule because there is a claim
indicating it is turned off in a superior module.

An entity may have multiple debug
facilities. The use of plural in the description of the states
refers to that, not to any aggregation or inheritance.

The architecture of some chips or devices may be such that a debug
facility operates for the whole chip or device. If the EAT for such
a chip includes submodules, then each submodule should independently
report the status of the whole-chip or whole-device debug facility.
This is the only way the receiver can know the debug status
of the submodules since there is no inheritance.

#### Enabled

If any debug facility, even manufacturer hardware diagnostics, is
currently enabled, then this level must be indicated.

#### Disabled

This level indicates all debug facilities are currently disabled. It
may be possible to enable them in the future. It may also be
that they were enabled in the past, but they are currently disabled.

#### Disabled Since Boot

This level indicates all debug facilities are currently disabled and
have been so since the entity booted/started.

#### Disabled Permanently

This level indicates all non-manufacturer facilities are permanently
disabled such that no end user or developer can enable them. Only
the manufacturer indicated in the "oemid" claim can enable them. This
also indicates that all debug facilities are currently disabled and
have been so since boot/start.

#### Disabled Fully and Permanently

This level indicates that all debug facilities for the entity are permanently disabled.

~~~~CDDL
{::include nc-cddl/debug-status.cddl}
~~~~


### location (Location) Claim {#location}

The "location" claim gives the geographic position of the entity from which the attestation originates.
Latitude, longitude, altitude, accuracy, altitude-accuracy, heading and speed MUST be as defined in the W3C Geolocation API {{W3C.GeoLoc}}
(which, in turn, is based on {{WGS84}}).
If the entity is stationary, the heading is NaN (floating-point not-a-number).
Latitude and longitude MUST always be provided.
If any other of these values are unknown, they are omitted.

The location may have been cached for a period of time before token
creation. For example, it might have been minutes or hours or more
since the last contact with a GPS satellite. Either the timestamp or
age data item can be used to quantify the cached period.  The timestamp
data item is preferred as it a non-relative time.
If the entity has no clock or the clock is unset but has a means to measure the time interval between the acquisition of the location and the token creation the age may be reported instead.
The age is in seconds.

See location-related privacy considerations in {{locationprivacyconsiderations}}.

~~~~CDDL
{::include nc-cddl/location.cddl}
~~~~

### uptime (Uptime) Claim

The "uptime" claim MUST contain a value that represents the number of
seconds that have elapsed since the entity or submodule was last booted.

~~~~CDDL
{::include nc-cddl/uptime.cddl}
~~~~

### bootcount (Boot Count) Claim

The "bootcount" claim contains a count of the number
times the entity or submodule has been booted. Support for this claim
requires a persistent storage on the device.

~~~~CDDL
{::include nc-cddl/boot-count.cddl}
~~~~

### bootseed (Boot Seed) Claim

The "bootseed" claim contains a value created at system boot time that allows differentiation of attestation reports from different boot sessions of a particular entity (e.g., a certain UEID).

This value is usually public.
It is not a secret and MUST NOT be used for any purpose that a secret seed is needed, such as seeding a random number generator.

There are privacy considerations for this claim. See {{bootseedprivacyconsiderations}}.

~~~~CDDL
{::include nc-cddl/boot-seed.cddl}
~~~~


### dloas (Digital Letters of Approval) Claim {#dloas}

The "dloas" claim conveys one or more Digital Letters of Approval (DLOAs)). A DLOA {{DLOA}} is a document that describes a certification that an entity has received.
Examples of certifications represented by a DLOA include those issued by Global Platform and those based on Common Criteria.
The DLOA is unspecific to any particular certification type or those issued by any particular organization.

This claim is typically issued by a verifier, not an attester.
Verifiers MUST NOT issue this claim unless the entity has received the certification indicated by the DLOA.

This claim MAY contain more than one DLOA.
If multiple DLOAs are present, verifiers MUST NOT issue this claim unless the entity has received all of the certifications.

DLOA documents are always fetched from a registrar that stores them.
This claim contains several data items used to construct a URL for fetching the DLOA from the particular registrar.

This claim MUST be encoded as an array with either two or three elements.
The first element MUST be the URI for the registrar.
The second element MUST be a platform label indicating which platform was certified.
If the DLOA applies to an application, then the third element is added which MUST be an application label.
The method of constructing the registrar URI, platform label and possibly application label is specified in {{DLOA}}.

~~~~CDDL
{::include nc-cddl/dloas.cddl}
~~~~


### manifests (Software Manifests) Claim {#manifests}

The "manifests" claim contains descriptions of software present on the entity.
These manifests are installed on the entity when the software is installed or are created as part of the installation process.
Installation is anything that adds software to the entity, possibly factory installation, the user installing elective applications and so on.
The defining characteristic is they are created by the software manufacturer.
The purpose of these claims in an EAT is to relay them without modification to the verifier and possibly to the relying party.

Some manifests may be signed by their software manufacturer before they are put into this EAT claim.
When such manifests are put into this claim, the manufacturer's signature SHOULD be included.
For example, the manifest might be a CoSWID signed by the software manufacturer, in which case the full signed CoSWID should be put in this claim.

This claim allows multiple formats for the manifest.
For example, the manifest may be a CBOR-encoded CoSWID, an XML-encoded SWID or other.
Identification of the type of manifest is always by a CoAP Content-Format integer {{RFC7252}}.
If there is no CoAP identifier registered for the manifest encoding, one should be registered, perhaps in the experimental or first-come-first-served range.

This claim MUST be an array of one or more manifests.
Each manifest in the claim MUST be an array of two.
The first item in the array of two MUST be an integer CoAP Content-Format identifier.
The second item is MUST be the actual manifest.

In JSON-encoded tokens the manifest, whatever encoding it is, MUST be placed in a text string.
When a non-text encoded manifest like a CBOR-encoded CoSWID is put in a JSON-encoded token, the manifest MUST be base-64 encoded.

This claim allows for multiple manifests in one token since multiple software packages are likely to be present.
The multiple manifests MAY be of different encodings.
In some cases EAT submodules may be used instead of the array structure in this claim for multiple manifests.

When the {{CoSWID}} format is used, it MUST be a payload CoSWID, not an evidence CoSWID.

A {{SUIT.Manifest}} may be used as a manifest.

This document registers CoAP Content Formats for CycloneDX {{CycloneDX}} and SPDX {{SPDX}} so they can be used as a manifest.

This claim is extensible for use of manifest formats beyond those mentioned in this document.
No particular manifest format is preferred.
For manifest interoperability, an EAT profile, {{profiles}}, should be used that specifies what manifest format(s) are allowed.

~~~~CDDL
{::include nc-cddl/manifests.cddl}
~~~~


### measurements (Measurements) Claim {#measurements}

The "measurements" claim contains descriptions, lists, evidence or measurements of the software that exists on the entity or any other measurable
subsystem of the entity (e.g. hash of sections of a file system or non-volatile memory).
The defining characteristic of this claim is that its contents are created by processes on the entity that inventory, measure or otherwise characterize the software on the entity.
The contents of this claim do not originate from the manufacturer of the measurable subsystem (e.g. developer of a software library).

This claim can be a {{CoSWID}}.
When the CoSWID format is used, it MUST be an evidence CoSWID, not a payload CoSWID.

Formats other than CoSWID MAY be used.
The identification of format is by CoAP Content Format, the same as the "manifests" claim in {{manifests}}.

~~~~CDDL
{::include nc-cddl/measurements.cddl}
~~~~

### measres (Software Measurement Results) Claim {#measurementresults}

The "measres" claim is a general-purpose structure for reporting comparison of measurements to expected reference values.
This claim provides a simple standard way to report the result of a comparison as success, failure, fail to run, ...

It is the nature of measurement systems that they are specific to the operating system, software and hardware of the entity that is being measured.
It is not possible to standardize what is measured and how it is measured across platforms, OS's, software and hardware.
The recipient must obtain the information about what was measured and what it indicates for the characterization of the security of the entity from the provider of the measurement system.
What this claim provides is a standard way to report basic success or failure of the measurement.
In some use cases it is valuable to know if measurements succeeded or failed in a general way even if the details of what was measured is not characterized.

This claim MAY be generated by the verifier and sent to the relying party.
For example, it could be the results of the verifier comparing the contents of the "measurements" claim, {{measurements}}, to reference values.


This claim MAY also be generated on the entity if the entity has the ability for one subsystem to measure and evaluate another subsystem.
For example, a TEE might have the ability to measure the software of the rich OS and may have the reference values for the rich OS.

Within an entity, attestation target or submodule, multiple results can be reported.
For example, it may be desirable to report the results for measurements of the file system, chip configuration, installed software, running software and so on.

Note that this claim is not for reporting the overall result of a verifier.
It is solely for reporting the result of comparison to reference values.

An individual measurement result is an array of two, an identifier of the measurement and an enumerated type that is the result.
The range and values of the measurement identifier varies from one measurement scheme to another.

Each individual measurement result is part of a group that may contain many individual results.
Each group has a text string that names it, typically the name of the measurement scheme or system.

The claim itself consists of one or more groups.

The values for the results enumerated type are as follows:

1 -- comparison successful:
: Indicates successful comparison to reference values.

2 -- comparison fail:
: The comparison was completed and did not compare correctly to the reference values.

3 -- comparison not run:
: The comparison was not run. This includes error conditions such as running out of memory.

4 -- measurement absent:
: The particular measurement was not available for comparison.


~~~~CDDL
{::include nc-cddl/measurement-results.cddl}
~~~~


### submods (Submodules) {#submods}

Some devices are complex and have many subsystems.  A mobile phone is a good example. It may have subsystems for communications (e.g., Wi-Fi and cellular), low-power audio and video playback, multiple
security-oriented subsystems like a TEE and a Secure Element, and etc. The claims for a subsystem can be grouped together in a submodule.

Submodules may be used in either evidence or attestation results.

Because system architecture will vary greatly from use case to use case, there are no set requirements for what a submodule represents either in evidence or in attestation results.
Profiles, {{profiles}}, may wish to impose requirements.
An attester that outputs evidence with submodules should document the semantics it associates with particular submodules for the verifier.
Likewise, a verifier that outputs attestation results with submodules should document the semantics it associates with the submodules for the relying party.

A submodule claim is a map that holds some number of submodules.
Each submodule is named by its label in the submodule claim map.
The value of each entry in a submodule may be a Claims-Set, nested token or Detached-Submodule-Digest.
This allows for the submodule to serve as its own attester or not and allows for claims
for each submodule to be represented directly or indirectly, i.e., detached.

A submodule may include a submodule, allowing for arbitrary levels of nesting.
However, submodules do not inherit anything from the containing token and must explicitly include all claims.
Submodules may contain claims that are present in any surrounding token or submodule.
For example, the top-level of the token may have a UEID, a submodule may have a different UEID and a further subordinate submodule may also have a UEID.

The following sub-sections define the three types for representing submodules:

* A submodule Claims-Set
* The digest of a detached Claims-Set
* A nested token, which can be any EAT

The Submodule type definition and Nested-Token type definition vary with the type of encoding. The definitions for CBOR-encoded EATs are as follows:

~~~~CDDL
{::include nc-cddl/submods-cbor.cddl}
~~~~

The Submodule and Nested-Token definitions for JSON-encoded EATs is as below. This difference in definitions vs. CBOR is necessary because JSON has no tag mechanism and no byte string type to help indicate the nested token is CBOR.

~~~~CDDL
{::include nc-cddl/submods-json.cddl}
~~~~

The Detached-Submodule-Digest type is defined as follows:

~~~~CDDL
{::include nc-cddl/detached-digest.cddl}
~~~~

Nested tokens can be one of three types as defined in this document or types standardized in follow-on documents (e.g., {{UCCS}}).
Nested tokens are the only mechanism by which JSON can be embedded in CBOR and vice versa.

The addition of further types is accomplished by augmenting the $EAT-CBOR-Tagged-Token socket or the $JSON-Selector-Type and $JSON-Selector-Value sockets.

When decoding a JSON-encoded EAT, the type of submodule is determined as follows.
A JSON object indicates the submodule is a Claims-Set.
In all other cases, it is a JSON-Selector, which is an array of two elements that indicates whether the submodule is a nested token or a Detached-Submodule-Digest.The first element in the array indicates the type present in the second element.
If the value is “JWT”, “CBOR”, “BUNDLE” or a future-standardized token types, e.g., {{UCCS}}, the submodule is a nested token of the indicated type, i.e., JWT-Message, CBOR-Token-Inside-JSON-Token, Detached-EAT-Bundle, or a future type.
If the value is "DIGEST", the submodule is a Detached-Submodule-Digest.
Any other value indicates a standardized extension to this specification.

When decoding a CBOR-encoded EAT, the CBOR item type indicates the type of the submodule as follows.
A map indicates a CBOR-encoded submodule Claims-Set.
An array indicates a CBOR-encoded Detached-Submodule-Digest.
A byte string indicates a CBOR-encoded CBOR-Nested-Token.
A text string indicates a JSON-encoded JSON-Selector. Where JSON-Selector is used in a CBOR-encoded EAT, the "DIGEST" type and corresponding Detached-Submodule-Digest type MUST NOT be used.

The type of a CBOR-encoded nested token is always determined by the CBOR tag encountered after the byte string wrapping is removed in a CBOR-encoded enclosing token or after the base64 wrapping is removed in JSON-encoded enclosing token.

The type of a JSON-encoded nested token is always determined by the string name in JSON-Selector and is always “JWT”, “BUNDLE” or a new name standardized outside this document for a further type (e.g., “UCCS”).
This string name may also be “CBOR” to indicate the nested token is CBOR-encoded.

"JWT":
: The second array item MUST be a JWT formatted according to {{RFC7519}}

"CBOR":
: The second array item MUST be some base64url-encoded CBOR that is a tag, typically a CWT or CBOR-encoded detached EAT bundle

"BUNDLE":
: The second array item MUST be a JSON-encoded Detached EAT Bundle as defined in this document.

"DIGEST":
: The second array item MUST be a JSON-encoded Detached-Submodule-Digest as defined in this document.

As noted elsewhere, additional EAT types may be defined by a standards action. New type specifications MUST address the integration of the new type into the Submodule claim type for submodules.


#### Submodule Claims-Set

The Claims-Set type provides a means of representing claims from a submodule that does not have its own attesting environment,
i.e., it has no keys distinct from the attester producing the surrounding token. Claims are represented as a Claims-Set. Submodule claims represented in this way are secured by the same
mechanism as the enclosing token (e.g., it is signed by the same attestation key).

The encoding of a submodule Claims-Set MUST be the same as the encoding as the surrounding EAT, e.g., all submodule Claims-Sets in a CBOR-encoded token must be CBOR-encoded.

#### Detached Submodule Digest

The Detached-Submodule-Digest type is similar to a submodule Claims-Set, except a digest of the Claims-Set is included in the claim with the Claims-Set contents conveyed separately.
The separately-conveyed Claims-Set is called a detached claims set.
The input to the digest algorithm is directly the CBOR or JSON-encoded Claims-Set for the submodule.
There is no byte-string wrapping or base 64 encoding.

The data type for this type of submodule is an array consisting of two data items: an algorithm identifier and a byte string containing the digest. The hash algorithm identifier is always from the COSE Algorithm registry, {{IANA.COSE.Algorithms}}. Either the integer or string identifier may be used. The hash algorithm identifier is never from the JOSE Algorithm registry.

A detached EAT bundle, described in {{DEB}}, may be used to convey detached claims sets and the EAT containing the corresponding detached digests.
EAT, however, doesn't require use of a detached EAT bundle.
Any other protocols may be used to convey detached claims sets and the EAT containing the corresponding detached digests.
Detached Claims-Sets must not be modified in transit, else validation will fail.

#### Nested Tokens {#Nested-Token}

The CBOR-Nested-Token and JSON-Selector types provide a means of representing claims from a submodule that has its own attesting environment,
i.e., it has keys distinct from the attester producing the surrounding token. Claims are represented in a signed EAT token.

Inclusion of a signed EAT as a claim cryptographically binds the EAT to the surrounding token.
If it was conveyed in parallel with the surrounding token, there would be no such binding and attackers could substitute a good attestation from another device for the attestation of an errant subsystem.

A nested token need not use the same encoding as the enclosing token.
This enables composite devices to be built without regards to the encoding used by components.
Thus, a CBOR-encoded EAT can have a JSON-encoded EAT as a nested token and vice versa.

## Claims Describing the Token

The claims in this section provide meta data about the token they occur in.
They do not describe the entity. They may appear in evidence or attestation results.


### iat (Timestamp) Claim {#iat-claim}

The "iat" claim defined in CWT and JWT is used to indicate the
date-of-creation of the token, the time at which the claims are
collected and the token is composed and signed.

The data for some claims may be held or cached for some period of
time before the token is created. This period may be long, even
days. Examples are measurements taken at boot or a geographic
position fix taken the last time a satellite signal was received.
There are individual timestamps associated with these claims to
indicate their age is older than the "iat" timestamp.

CWT allows the use floating-point for this claim. EAT disallows
the use of floating-point. An EAT token MUST NOT contain an "iat" claim in
floating-point format. Any recipient of a token with a floating-point
format "iat" claim MUST consider it an error.

A 64-bit integer representation of the CBOR epoch-based time
{{RFC8949}} used by this claim can represent a range of +/- 500
billion years, so the only point of a floating-point timestamp is to
have precession greater than one second. This is not needed for EAT.


### eat_profile (EAT Profile) Claim {#profile-claim}

See {{profiles}} for the detailed description of an EAT profile.

The "eat_profile" claim identifies an EAT profile by either a URL or an OID.
Typically, the URI will reference a document describing the profile.
An OID is just a unique identifier for the profile.
It may exist anywhere in the OID tree.
There is no requirement that the named document be publicly accessible.
The primary purpose of the "eat_profile" claim is to uniquely identify the profile even if it is a private profile.

The OID is always absolute and never relative.

See {{common-types}} for OID and URI encoding.

~~~~CDDL
{::include nc-cddl/profile.cddl}
~~~~


### intuse (Intended Use) Claim

EAT's may be used in the context of several different applications.  The "intuse"
claim provides an indication to an EAT consumer about  the intended usage
of the token. This claim can be used as a way for an application using EAT to internally distinguish between different ways it uses EAT.

1 -- Generic:
: Generic attestation describes an application where the EAT consumer
requires the most up-to-date security assessment of the attesting entity. It
is expected that this is the most commonly-used application of EAT.

2-- Registration:
: Entities that are registering for a new service may be expected to
provide an attestation as part of the registration process.  This "intuse"
setting indicates that the attestation is not intended for any use but registration.

3 -- Provisioning:
: Entities may be provisioned with different values or settings by an EAT
consumer.  Examples include key material or device management trees.  The consumer
may require an EAT to assess entity security state of the entity prior to provisioning.

4 -- Certificate Issuance:
: Certification Authorities (CAs) may require attestation results (which in a background check model might require receiving evidence to be passed to a verifier) to make decisions about the issuance of certificates.
An EAT may be used as part of the certificate signing request (CSR).

5 -- Proof-of-Possession:
: An EAT consumer may require an attestation as part of an accompanying
proof-of-possession (PoP) application. More precisely, a PoP transaction is intended
to provide to the recipient cryptographically-verifiable proof that the sender has possession
of a key.  This kind of attestation may be necessary to verify the
security state of the entity storing the private key used in a PoP application.

~~~~CDDL
{::include nc-cddl/intended-use.cddl}
~~~~


# Detached EAT Bundles {#DEB}

A detached EAT bundle is a structure to convey a fully-formed and signed token plus detached claims set that relate to that token.
It is a top-level EAT message like a CWT or JWT.
It can be occur any place that CWT or JWT messages occur.
It may also be sent as a submodule.

A detached EAT bundle consists of two parts.

The first part is a full top-level token.
This top-level token MUST have at least one submodule that is a detached digest.
This top-level token may be either CBOR or JSON-encoded.
It MAY be a CWT, or JWT but MUST NOT be a detached EAT bundle.
It MAY also be some future-defined token type.
The same mechanism for distinguishing the type for nested token submodules is employed here.

The second part is a map/object containing the detached Claims-Sets corresponding to the detached digests in the full token.
When the detached EAT bundle is CBOR-encoded, each detached Claims-Set MUST be CBOR-encoded and wrapped in a byte string.
When the detached EAT bundle is JSON-encoded, each detached Claims-Set MUST be JSON-encoded and base64url encoded.
All the detached Claims-Sets MUST be encoded in the same encoding as the detached EAT bundle.
No mixing of encodings is allowed for the Claims-Sets in a detached EAT bundle.

For CBOR-encoded detached EAT bundles, tag TBD602 can be used to identify it.
The normal rules apply for use or non-use of a tag.
When it is sent as a submodule, it is always sent as a tag to distinguish it from the other types of nested tokens.

The digests of the detached claims sets are associated with detached Claims-Sets by label/name.
It is up to the constructor of the detached EAT bundle to ensure the names uniquely identify the detached claims sets.
Since the names are used only in the detached EAT bundle, they can be very short, perhaps one byte.

~~~~CDDL
{::include nc-cddl/deb.cddl}
~~~~




# Profiles {#profiles}

EAT makes normative use of CBOR, JSON, COSE, JOSE, CWT and JWT.
Most of these have implementation options to accommodate a range of use cases.

For example, COSE doesn't require a particular set of cryptographic algorithms so as to accommodate different usage scenarios and evolution of algorithms over time.
Section 10 of {{RFC9052}} describes the profiling considerations for COSE.

The use of encryption is optional for both CWT and JWT.
Section 8 of {{RFC7519}} describes implementation requirement and recommendations for JWT.

Similarly, CBOR provides indefinite length encoding, which is not commonly used, but valuable for very constrained devices.
For EAT itself, in a particular use case some claims will be used and others will not.
Section 4 of {{RFC8949}} describes serialization considerations for CBOR.

For example a mobile phone use case may require the device make and model, and prohibit UEID and location for privacy reasons.
The general EAT standard retains all this flexibility because it too is aimed to accommodate a broad range of use cases.

It is necessary to explicitly narrow these implementation options to guarantee interoperability.
EAT chooses one general and explicit mechanism, the profile, to indicate the choices made for these implementation options for all aspects of the token.

Below is a list of the various issues that should be addressed by a profile.

The "eat_profile" claim in {{profile-claim}} provides a unique identifier for the profile a particular token uses.

A profile can apply to evidence or to attestation results or both.

## Format of a Profile Document

A profile document doesn't have to be in any particular format. It may be simple text, something more formal or a combination.

A profile may define, and possibly register, one or more new claims if needed. A profile may also reuse one or more already defined claims, either as-is or with values constrained to a subset or subrange.

## List of Profile Issues

The following is a list of EAT, CWT, JWT, COSE, JOSE and CBOR options that a profile should address.


### Use of JSON, CBOR or both

A profile should specify whether CBOR, JSON or both may be sent.
A profile should specify that the receiver can accept all encodings that the sender is allowed to send.

This should be specified for the top-level and all nested tokens.
For example, a profile might require all nested tokens to be of the same encoding of the top level token.


### CBOR Map and Array Encoding

A profile should specify whether definite-length arrays/maps, indefinite-length arrays/maps or both may be sent.
A profile should specify that the receiver be able to accept all length encodings that the sender is allowed to send.

This applies to individual EAT claims, CWT and COSE parts of the implementation.

For most use cases, specifying that only definite-length arrays/maps may be sent is suitable.


### CBOR String Encoding

A profile should specify whether definite-length strings, indefinite-length strings or both may be sent.
A profile should specify that the receiver be able to accept all types of string encodings that the sender is allowed to send.

For most use cases, specifying that only definite-length strings may be sent is suitable.


### CBOR Preferred Serialization

A profile should specify whether or not CBOR preferred serialization must be sent or not.
A profile should specify the receiver be able to accept preferred and/or non-preferred serialization so it will be able to accept anything sent by the sender.


### CBOR Tags

The profile should specify whether the token should be a CWT Tag or not.

When COSE protection is used, the profile should specify whether COSE tags are used or not.
Note that RFC 8392 requires COSE tags be used in a CWT tag.

Often a tag is unnecessary because the surrounding or carrying protocol identifies the object as an EAT.


### COSE/JOSE Protection {#message-type}

COSE and JOSE have several options for signed, MACed and encrypted messages.
JWT may use the JOSE NULL protection option.
It is possible to implement no protection, sign only, MAC only, sign then encrypt and so on.
All combinations allowed by COSE, JOSE, JWT, and CWT are allowed by EAT.

A profile should specify all signing, encryption and MAC message formats that may be sent.
For example, a profile might allow only COSE_Sign1 to be sent.
For another example, a profile might allow COSE_Sign and COSE_Encrypt to be sent to carry multiple signatures for post quantum cryptography and to use encryption to provide confidentiality.

A profile should specify the receiver accepts all message formats that are allowed to be sent.

When both signing and encryption are allowed, a profile should specify which is applied first.


### COSE/JOSE Algorithms

See the section on "Application Profiling Considerations" in {{RFC9052}} for a discussion on selection of cryptographic algorithms and related issues.

The profile MAY require the protocol or system using EAT provide an algorithm negotiation mechanism.

If not, The profile document should list a set of algorithms for each COSE and JOSE message type allowed by the profile per {{message-type}}.
The verifier should implement all of them.
The attester may implement any of them it wishes, possibly just one for each message type.

If detached submodule digests are used the profile should address the determination of the hash algorithm(s) for the digests.


### Detached EAT Bundle Support

A profile should specify whether or not a detached EAT bundle ({{DEB}}) can be sent.
A profile should specify that a receiver be able to accept a detached EAT bundle if the sender is allowed to send it.


### Key Identification

A profile should specify what must be sent to identify the verification, decryption or MAC key or keys.
If multiple methods of key identification may be sent, a profile should require the receiver support them all.

{{keyid}} describes a number of methods for identifying verification keys.
When encryption is used, there are further considerations.
In some cases key identification may be very simple and in others involve multiple components.
For example, it may be simple through use of COSE key ID or it may be complex through use of an X.509 certificate hierarchy.

While not always possible, a profile should specify or make reference to, a full end-end specification for key identification.
For example, a profile should specify in full detail how COSE key IDs are to be created, their lifecycle and such rather than just specifying that a COSE key ID be used.
For example, a profile should specify the full details of an X.509 hierarchy including extension processing, algorithms allowed and so on rather than just saying X.509 certificates are used.


### Endorsement Identification

Similar to, or perhaps the same as verification key identification, the profile may wish to specify how endorsements are to be identified.
However note that endorsement identification is optional, whereas key identification is not.

### Freshness

Security considerations, see {{sec-con-freshness}}, require a mechanism to provide freshness.
This may be the EAT nonce claim in {{nonce}}, or some claim or mechanism defined outside this document.
The section on freshness in {{RATS.Architecture}} describes several options.
A profile should specify which freshness mechanism or mechanisms can be used.

If the EAT nonce claim is used, a profile should specify whether multiple nonces may be sent.
If a profile allows multiple nonces to be sent, it should require the receiver to process multiple nonces.

### Claims Requirements

A profile may define new claims that are not defined in this document.

This document requires an EAT receiver must accept all claims it does not understand.
A profile for a specific use case may reverse this and allow a receiver to reject tokens with claims it does not understand.
A profile for a specific use case may specify that specific claims are prohibited.

A profile for a specific use case may modify this and specify that some claims are required.

A profile may constrain the definition of claims that are defined in this document or elsewhere.
For example, a profile may require the EAT nonce be a certain length or the "location" claim always include the altitude.

Some claims are "pluggable" in that they allow different formats for their content.
The "manifests" claim ({{manifests}}) along with the measurement and "measurements" ({{measurements}})) claims are examples of this, allowing the use of CoSWID, TEEP Manifests and other formats.
A profile should specify which formats are allowed to be sent, with the assumption that the corresponding COAP content types have been registered.
A profile should require the receiver to accept all formats that are allowed to be sent.

Further, if there is variation within a format that is allowed, the profile should specify which variations can be sent.
For example, there are variations in the CoSWID format.
A profile that require the receiver to accept all variations that are allowed to be sent.


## The Constrained Device Standard Profile

It is anticipated that there will be many profiles defined for EAT for many different use cases.
This section standardizes one profile that is good for many constrained device use cases.

The identifier for this profile is "https://www.rfc-editor.org/rfc/rfcTBD".


| Issue | Profile Definition |
| CBOR/JSON | CBOR only |
| CBOR Encoding | Only definite length maps and arrays are allowed |
| CBOR Encoding | Only definite length strings are allowed |
| CBOR Serialization | Only preferred serialization is allowed |
| COSE Protection | Only COSE_Sign1 is used |
| Algorithms | Receiver MUST accept ES256, ES384 and ES512; sender MUST send one of these |
| Detached EAT Bundle Usage | Detached EAT bundles may not be sent with this profile |
| Verification Key Identification | Either the COSE kid or the UEID MUST be used to identify the verification key. If both are present, the kid takes precedence |
| Endorsements | This profile contains no endorsement identifier |
| Nonce | A new single unique nonce MUST be used for every token request |
| Claims | No requirement is made on the presence or absence of claims other than requiring an EAT nonce. As per general EAT rules, the receiver MUST NOT error out on claims it doesn't understand. |

Strictly speaking, even slight modifications, such as the use of a different means of key identification, are a divergence from this profile and require allocation of a different profile identifier.

A profile that is similar to this can be defined and/or standardized by making normative reference to this section and adding requirements.
Such a profile MUST have a different profile identifier.


# Encoding and Collected CDDL {#encoding}

An EAT is fundamentally defined using CDDL.
This document specifies how to encode the CDDL in CBOR or JSON.
Since CBOR can express some things that JSON can't (e.g., tags) or that are expressed differently (e.g., labels) there is some CDDL that is specific to the encoding.

## Claims-Set and CDDL for CWT and JWT

CDDL was not used to define CWT or JWT.
It was not available at the time.

This document defines CDDL for both CWT and JWT.
This document does not change the encoding or semantics of anything in a CWT or JWT.

A Claims-Set is the central data structure for EAT, CWT and JWT.
It holds all the claims and is the structure that is secured by signing or other means.
It is not possible to define EAT, CWT, or JWT in CDDL without it.
The CDDL definition of Claims-Set here is applicable to EAT, CWT and JWT.

This document specifies how to encode a Claims-Set in CBOR or JSON.

With the exception of nested tokens and some other externally defined structures (e.g., SWIDs) an entire Claims-Set must be in encoded in either CBOR or JSON, never a mixture.

CDDL for the seven claims defined by {{RFC8392}} and {{RFC7519}} is included here.


## Encoding Data Types

This makes use of the types defined in {{RFC8610}} Appendix D, Standard Prelude.

### Common Data Types {#common-types}

time-int is identical to the epoch-based time, but disallows
floating-point representation.

The OID encoding from {{RFC9090}} is used without the tag number in CBOR-encoded tokens.
In JSON tokens OIDs are a text string in the common form of "nn.nn.nn...".

Unless expliclity indicated, URIs are not the URI tag defined in {{RFC8949}}.
They are just text strings that contain a URI conforming to the format defined in {{RFC3986}}.

~~~~CDDL
{::include nc-cddl/common-types.cddl}
~~~~

### JSON Interoperability {#jsoninterop}

JSON should be encoded per {{RFC8610}}, Appendix E. In addition, the
following CDDL types are encoded in JSON as follows:

* bstr -- MUST be base64url encoded
* time -- MUST be encoded as NumericDate as described in Section 2 of {{RFC7519}}.
* string-or-uri -- MUST be encoded as StringOrURI as described in Section 2 of {{RFC7519}}.
* uri -- MUST be a URI {{RFC3986}}.
* oid -- MUST be encoded as a string using the well established dotted-decimal notation (e.g., the text "1.2.250.1") {{RFC2252}}.

The CDDL generic "JC< >" is used in most places where there is a variance between CBOR and JSON.
The first argument is the CDDL for JSON and the second is CDDL for CBOR.

### Labels

Most map labels, Claims-Keys, Claim-Names and enumerated-type values are integers for CBOR-encoded tokens and strings for JSON-encoded tokens.
When this is the case the "JC < >" CDDL construct is used to give both the integer and string values.

### CBOR Interoperability

CBOR allows data items to be serialized in more than one form to accommodate a variety of use cases.
This is addressed in {{profiles}}.

## Collected CDDL

### Payload CDDL

This CDDL defines all the EAT Claims that are added to the main definition of a Claim-Set in {{CDDL_for_CWT}}.
Claims-Set is the payload for CWT, JWT and potentially other token types.
This is for both CBOR and JSON.
When there is variation between CBOR and JSON, the JC<> CDDL generic defined in {{CDDL_for_CWT}}.

This CDDL uses, but doesn't define Submodule or nested tokens because the definition for these types varies between CBOR and JSON and the JC<> generic can't be used to define it.
The submodule claim is the one place that that a CBOR token can be nested inside a JSON token and vice versa.
Encoding-specific definitions are provided in the following sections.

~~~~CDDL
{::include nc-cddl/common.cddl}
~~~~

### CBOR-Specific CDDL

~~~~CDDL
{::include nc-cddl/cbor.cddl}
~~~~

### JSON-Specific CDDL

~~~~CDDL
{::include nc-cddl/json.cddl}
~~~~

# Privacy Considerations {#privacyconsiderations}

Certain EAT claims can be used to track the owner of an entity and
therefore, implementations should consider providing privacy-preserving
options dependent on the intended usage of the EAT.  Examples would
include suppression of location claims for EAT's provided to
unauthenticated consumers.

## UEID and SUEID Privacy Considerations {#ueidprivacyconsiderations}

A UEID is usually not privacy-preserving. Relying parties
receiving tokens that happen to be from a particular entity will be
able to know the tokens are  from the same entity and be able to
identify the entity issuing those tokens.

Thus the use of the claim may violate privacy policies. In other usage situations a UEID will
not be allowed for certain products like browsers that give privacy
for the end user. It will often be the case that tokens will not have
a UEID for these reasons.

An SUEID is also usually not privacy-preserving.  In some cases it may
have fewer privacy issues than a UEID depending on when and how and
when it is generated.

There are several strategies that can be used to still be able to put
UEIDs and SUEIDs in tokens:

* The entity obtains explicit permission from the user of the entity
to use the UEID/SUEID. This may be through a prompt. It may also be through
a license agreement.  For example, agreements for some online banking
and brokerage services might already cover use of a UEID/SUEID.

* The UEID/SUEID is used only in a particular context or particular use
case. It is used only by one relying party.

* The entity authenticates the relying party and generates a derived
UEID/SUEID just for that particular relying party.  For example, the relying
party could prove their identity cryptographically to the entity, then
the entity generates a UEID just for that relying party by hashing a
proofed relying party ID with the main entity UEID/SUEID.

Note that some of these privacy preservation strategies result in
multiple UEIDs and SUEIDs per entity. Each UEID/SUEID is used in a
different context, use case or system on the entity. However, from the
view of the relying party, there is just one UEID and it is still
globally universal across manufacturers.

## Location Privacy Considerations {#locationprivacyconsiderations}

Geographic location is most always considered personally identifiable information.
Implementers should consider laws and regulations governing the transmission of location data from end user devices to servers and services.
Implementers should consider using location management facilities offered by the operating system on the entity generating the attestation.
For example, many mobile phones prompt the user for permission before sending location data.

## Boot Seed Privacy Considerations {#bootseedprivacyconsiderations}

The "bootseed" claim is effectively a stable entity identifier within a given boot epoch.  Therefore, it is not suitable for use in attestation schemes that are privacy-preserving.

## Replay Protection and Privacy {#replayprivacyconsiderations}

EAT defines the EAT nonce claim for replay protection and token freshness.
The nonce claim is based on a value usually derived remotely (outside of the entity).
This claim might be used to extract and convey personally identifying information either inadvertently or by intention.
For instance, an implementor may choose a nonce equivalent to a username associated with the device (e.g., account login).
If the token is inspected by a 3rd-party then this information could be used to identify the source of the token or an account associated with the token.
To avoid the conveyance of privacy-related information in the nonce claim, it should be derived using a salt that originates from a true and reliable random number generator or any other source of randomness that would still meet the target system requirements for replay protection and token freshness.

# Security Considerations {#securitycons}

The security considerations provided in Section 8 of {{RFC8392}} and Section 11
of {{RFC7519}} apply to EAT in its CWT and JWT form, respectively.  Moreover, Chapter 12
of {{RATS.Architecture}} is also applicable to implementations of EAT.  In addition,
implementors should consider the following.

## Claim Trustworthiness

This specification defines semantics for each claim.
It does not require any particular level of security in the implementation of the claims or even the attester itself.
Such specification is far beyond the scope of this document which is about a message format not the security level of an implementation.

The receiver of an EAT comes to know the trustworthiness of the claims in it by understanding the implementation made by the attester vendor and/or understanding the checks and processing performed by the verifier.

For example, this document says that a UEID is permanent and that it must not change, but it doesn't say what degree of attack to change it must be defended.

The degree of security will vary from use case to use case.
In some cases the receiver may only need to know something of the implementation such as that it was implemented in a TEE.
In other cases the receiver may require the attester be certified by a particular certification program.
Or perhaps the receiver is content with very little security.


## Key Provisioning

Private key material can be used to sign and/or encrypt the EAT, or
can be used to derive the keys used for signing and/or encryption.  In
some instances, the manufacturer of the entity may create the key
material separately and provision the key material in the entity
itself.  The manufacturer of any entity that is capable of producing
an EAT should take care to ensure that any private key material be
suitably protected prior to provisioning the key material in the
entity itself.  This can require creation of key material in an
enclave (see {{RFC4949}} for definition of "enclave"), secure
transmission of the key material from the enclave to the entity using
an appropriate protocol, and persistence of the private key material
in some form of secure storage to which (preferably) only the entity
has access.

### Transmission of Key Material

Regarding transmission of key material from the enclave to the entity,
the key material may pass through one or more intermediaries.
Therefore some form of protection ("key wrapping") may be necessary.
The transmission itself may be performed electronically, but can also
be done by human courier.  In the latter case, there should be minimal
to no exposure of the key material to the human (e.g. encrypted
portable memory).  Moreover, the human should transport the key
material directly from the secure enclave where it was created to a
destination secure enclave where it can be provisioned.

## Freshness {#sec-con-freshness}

All EAT use must provide a freshness mechanism to prevent replay and related attacks.
The extensive discussions on freshness in {{RATS.Architecture}} including security considerations apply here.
The EAT nonce claim, in {{nonce}}, is one option to provide freshness.


## Multiple EAT Consumers

In many cases, more than one EAT consumer may be required to fully
verify the entity attestation.  Examples include individual consumers
for nested EATs, or consumers for individual claims with an EAT.  When
multiple consumers are required for verification of an EAT, it is
important to minimize information exposure to each consumer.  In
addition, the communication between multiple consumers should be
secure.

For instance, consider the example of an encrypted and signed EAT with
multiple claims.  A consumer may receive the EAT (denoted as the
"receiving consumer"), decrypt its payload, verify its signature, but
then pass specific subsets of claims to other consumers for evaluation
("downstream consumers").  Since any COSE encryption will be removed
by the receiving consumer, the communication of claim subsets to any
downstream consumer should leverage a communication security protocol
(e.g. Transport Layer Security).

However, assume the EAT of the previous example is hierarchical and
each claim subset for a downstream consumer is created in the form of
a nested EAT.  Then, Transport Layer Security between the receiving and
downstream consumers is not strictly required.  Nevertheless,
downstream consumers of a nested EAT should provide a nonce unique to
the EAT they are consuming.

## Detached EAT Bundle Digest Security Considerations

A detached EAT bundle is composed of a nested full token appended to
an unsigned claims set as per {{DEB}} .  Although the attached claims set is vulnerable to
modification in transit, any modification can be detected by the receiver through the associated
digest, which is a claim fully contained within an EAT.  Moreover, the digest itself can only be derived using
an appropriate COSE hash algorithm, implying that an attacker cannot induce false detection
of a modified detached claims because the algorithms in the COSE registry are assumed to be
of sufficient cryptographic strength.

# IANA Considerations

## Reuse of CBOR and JSON Web Token (CWT and JWT) Claims Registries

Claims defined for EAT are compatible with those of CWT and JWT
so the CWT and JWT Claims Registries, {{IANA.CWT.Claims}} and {{IANA.JWT.Claims}}, are re-used. No new IANA registry
is created.

All EAT claims defined in this document are placed in both registries.
All new EAT claims defined subsequently should be placed in both registries.

{{Claim_Characteristics}} describes some considerations when defining new claims.


## CWT and JWT Claims Registered by This Document

This specification adds the following values to the "JSON Web Token
Claims" registry established by {{RFC7519}} and the "CBOR Web Token Claims Registry"
established by {{RFC8392}}.
Each entry below is an addition to both registries.

The "Claim Description", "Change Controller" and "Specification Documents" are common and equivalent for the JWT and CWT registries.
The "Claim Key" and "Claim Value Types(s)" are for the CWT registry only.
The "Claim Name" is as defined for the CWT registry, not the JWT registry.
The "JWT Claim Name" is equivalent to the "Claim Name" in the JWT registry.

IANA is requested to register the following claims.

RFC Editor: Please make the following adjustments and remove this paragraph.
Replace "__this document__" with this RFC number.
In the following, the claims with "Claim Key: TBD" need to be assigned a value in the Specification Required Range, preferably starting around 267.
Those below already with a Claim Key number were given early assignment.
No change is requested for them except for Claim Key 262.
Claim 262 should be renamed from "secboot" to "oemboot" in the JWT registry and it's description changed in both the CWT and JWT registries.

* Claim Name: Nonce
* Claim Description: Nonce
* JWT Claim Name: "eat_nonce"
* Claim Key: 10
* Claim Value Type(s): byte string
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: UEID
* Claim Description: The Universal Entity ID
* JWT Claim Name: "ueid"
* CWT Claim Key: 256
* Claim Value Type(s): byte string
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: SUEIDs
* Claim Description: Semi-permanent UEIDs
* JWT Claim Name: "sueids"
* CWT Claim Key: 257
* Claim Value Type(s): map
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Hardware OEMID
* Claim Description: Hardware OEM ID
* JWT Claim Name: "oemid"
* Claim Key: 258
* Claim Value Type(s): byte string or integer
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Hardware Model
* Claim Description: Model identifier for hardware
* JWT Claim Name: "hwmodel"
* Claim Key: 259
* Claim Value Type(s): byte string
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Hardware Version
* Claim Description: Hardware Version Identifier
* JWT Claim Name: "hwversion"
* Claim Key: TBD 260
* Claim Value Type(s): array
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: OEM Authortised Boot
* Claim Description: Indicate whether the software booted was OEM authorized
* JWT Claim Name: "oemboot"
* Claim Key: 262
* Claim Value Type(s): Boolean
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Debug Status
* Claim Description: Indicate status of debug facilities
* JWT Claim Name: "dbgstat"
* Claim Key: 263
* Claim Value Type(s): integer or string
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Location
* Claim Description: The geographic location
* JWT Claim Name: "location"
* Claim Key: 264
* Claim Value Type(s): map
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: EAT Profile
* Claim Description: Indicates the EAT profile followed
* JWT Claim Name: "eat_profile"
* Claim Key: 265
* Claim Value Type(s): URI or OID
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Submodules Section
* Claim Description: The section containing submodules
* JWT Claim Name: "submods"
* Claim Key: 266
* Claim Value Type(s): map
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Uptime
* Claim Description: Uptime
* JWT Claim Name: "uptime"
* Claim Key: TBD
* Claim Value Type(s): unsigned integer
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Boot Count
* Claim Description: The number times the entity or submodule has been booted
* JWT Claim Name: "bootcount"
* Claim Key: TBD
* Claim Value Type(s): uint
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Boot Seed
* Claim Description: Identifies a boot cycle
* JWT Claim Name: "bootseed"
* Claim Key: TBD
* Claim Value Type(s): bytes
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: DLOAs
* Claim Description: Certifications received as Digital Letters of Approval
* JWT Claim Name: "dloas"
* Claim Key: TBD
* Claim Value Type(s): array
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Software Name
* Claim Description: The name of the software running in the entity
* JWT Claim Name: "swname"
* Claim Key: TBD
* Claim Value Type(s): map
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Software Version
* Claim Description: The version of software running in the entity
* JWT Claim Name: "swversion"
* Claim Key: TBD
* Claim Value Type(s): map
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Software Manifests
* Claim Description: Manifests describing the software installed on the entity
* JWT Claim Name: "manifests"
* Claim Key: TBD
* Claim Value Type(s): array
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Measurements
* Claim Description: Measurements of the software, memory configuration and such on the entity
* JWT Claim Name: "measurements"
* Claim Key: TBD
* Claim Value Type(s): array
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Software Measurement Results
* Claim Description: The results of comparing software measurements to reference values
* JWT Claim Name: "measres"
* Claim Key: TBD
* Claim Value Type(s): array
* Change Controller: IESG
* Specification Document(s): __this document__

&nbsp;

* Claim Name: Intended Use
* Claim Description: Indicates intended use of the EAT
* JWT Claim Name: "intuse"
* Claim Key: TBD
* Claim Value Type(s): integer or string
* Change Controller: IESG
* Specification Document(s): __this document__



## UEID URN Registered by this Document {#registerueidurn}

IANA is requested to register the following new subtypes in the "DEV URN Subtypes" registry under "Device Identification". See {{RFC9039}}.

| Subtype | Description                                | Reference     |
| ueid    | Universal Entity Identifier                | This document |
| sueid   | Semi-permanent Universal Entity Identifier | This document |


## CBOR Tag for Detached EAT Bundle Registered by this Document

In the registry {{IANA.cbor-tags}}, IANA is requested to allocate the
following tag from the  FCFS space, with the present document as the
specification reference.

| Tag    | Data Items     | Semantics                   |
| TBD602 | array          | Detached EAT Bundle {{DEB}} |


## Media Types Registered by this Document

It is requested that the CoAP Content-Format for SPDX and CycloneDX be been registered in the "CoAP Content-Formats" subregistry within the "Constrained RESTful Environments (CoRE) Parameters" registry [IANA.core-parameters]:

* Media Type: application/spdx+json
* Encoding: binary
* ID: TBD
* Reference: {{SPDX}}

&nbsp;

* Media Type: vendor/vnd.cyclonedx+xml
* Encoding: binary
* ID: TBD
* Reference: {{CycloneDX}}

&nbsp;

* Media Type: vendor/vnd.cyclonedx+json
* Encoding: binary
* ID: TBD
* Reference: {{CycloneDX}}

--- back

# Examples {#examples}

Most examples are shown as just a Claims-Set that would be a payload for a CWT, JWT, detached EAT bundle or future token types.
It is shown this way because the payload is all the claims, the most interesting part and showing full tokens makes it harder to show the claims.

Some examples of full tokens are also given.

WARNING: These examples use tag and label numbers not yet assigned by IANA.


## Payload Examples

### Simple TEE Attestation

This is a simple attestation of a TEE that includes a manifest that is a payload CoSWID to describe the TEE's software.

~~~~
{::include cddl/Example-Payloads/valid_tee.diag}
~~~~

~~~~
{::include cddl/Example-Payloads/coswid/tee-coswid.diag}
~~~~

### Submodules for Board and Device

~~~~
{::include cddl/Example-Payloads/valid_submods.diag}
~~~~


### EAT Produced by Attestation Hardware Block

~~~~
{::include cddl/Example-Payloads/valid_hw_block.diag}
~~~~

### Key / Key Store Attestation

~~~~
{::include cddl/Example-Payloads/valid_key_store.diag}
~~~~


### Software Measurements of an IoT Device

This is a simple token that might be for and IoT device.
It includes CoSWID format measurments of the SW.
The CoSWID is in byte-string wrapped in the token and also shown in diagnostic form.

~~~~
{::include cddl/Example-Payloads/valid_iot.diag}
~~~~

~~~~
{::include cddl/Example-Payloads/coswid/iot-sw.diag}
~~~~


### Attestation Results in JSON

This is a JSON-encoded payload that might be the output of a verifier that evaluated the IoT Attestation example immediately above.

This particular verifier knows enough about the TEE attester to be able to pass claims like debug status directly through to the relying party.
The verifier also knows the reference values for the measured software components and is able to check them.
It informs the relying party that they were correct in the "measres" claim.
"Trustus Verifications" is the name of the services that verifies the software component measurements.

~~~~
{::include cddl/Example-Payloads/valid_results.json}
~~~~


### JSON-encoded Token with Sumodules

This example has its lines wrapped per {{RFC8792}}.

~~~~
{::include cddl/Example-Payloads/submods.json_f}
~~~~


## Full Token Examples

### Basic CWT Example

This is a simple ECDSA signed CWT-format token.

~~~~
{::include cddl/Example-Tokens/valid_cwt.diag}
~~~~

### Detached EAT Bundle

In this detached EAT bundle, the main token is produced by a HW attestation block.
The detached Claims-Set is produced by a TEE and is largely identical to the Simple TEE examples above.
The TEE digests its Claims-Set and feeds that digest to the HW block.

In a better example the attestation produced by the HW block would be a CWT and thus signed and secured by the HW block.
Since the signature covers the digest from the TEE that Claims-Set is also secured.

The detached EAT bundle itself can be assembled by untrusted software.

~~~~
{::include cddl/Example-Tokens/valid_deb.diag}
~~~~

~~~~
{::include cddl/Example-Payloads/valid_hw_block2.diag}
~~~~


### JSON-encoded Detached EAT Bundle

In this bundle there are two detached Claims-Sets, "CS1" and "CS2".
The JWT at the start of the bundle has detached signature submodules with hashes of "CS1" and "CS2".
TODO: make the JWT actually be correct verifiable JWT.

This example has its lines wrapped per {{RFC8792}}.

~~~~
{::include cddl/Example-Tokens/deb.json_f}
~~~~


# UEID Design Rationale {#UEID-Design}

## Collision Probability

This calculation is to determine the probability of a collision of
UEIDs given the total possible entity population and the number of
entities in a particular entity management database.

Three different sized databases are considered. The number of devices
per person roughly models non-personal devices such as traffic lights,
devices in stores they shop in, facilities they work in and so on,
even considering individual light bulbs. A device may have
individually attested subsystems, for example parts of a car or a
mobile phone. It is assumed that the largest database will have at
most 10% of the world's population of devices. Note that databases
that handle more than a trillion records exist today.

The trillion-record database size models an easy-to-imagine reality
over the next decades. The quadrillion-record database is roughly at
the limit of what is imaginable and should probably be accommodated.
The 100 quadrillion database is highly speculative perhaps involving
nanorobots for every person, livestock animal and domesticated
bird. It is included to round out the analysis.

Note that the items counted here certainly do not have IP address and
are not individually connected to the network. They may be connected
to internal buses, via serial links, Bluetooth and so on.  This is
not the same problem as sizing IP addresses.

| People     | Devices / Person | Subsystems / Device | Database Portion | Database Size           |
|------------+------------------+------------------- -+------------------+-------------------------+
| 10 billion | 100              | 10                  | 10%              | trillion (10^12)        |
| 10 billion | 100,000          | 10                  | 10%              | quadrillion (10^15)     |
|100 billion | 1,000,000        | 10                  | 10%              | 100 quadrillion (10^17) |


This is conceptually similar to the Birthday Problem where m is the
number of possible birthdays, always 365, and k is the number of
people. It is also conceptually similar to the Birthday Attack where
collisions of the output of hash functions are considered.

The proper formula for the collision calculation is

       p = 1 - e^{-k^2/(2n)}

       p   Collision Probability
       n   Total possible population
       k   Actual population

However, for the very large values involved here, this formula requires floating
point precision higher than commonly available in calculators and software so this
simple approximation is used. See {{BirthdayAttack}}.

       p = k^2 / 2n

For this calculation:

       p  Collision Probability
       n  Total population based on number of bits in UEID
       k  Population in a database

| Database Size           | 128-bit UEID | 192-bit UEID | 256-bit UEID |
|-------------------------+--------------+--------------+--------------+
| trillion (10^12)        | 2 * 10^-15   | 8 * 10^-35   | 5 * 10^-55   |
| quadrillion (10^15)     | 2 * 10^-09   | 8 * 10^-29   | 5 * 10^-49   |
| 100 quadrillion (10^17) | 2 * 10^-05   | 8 * 10^-25   | 5 * 10^-45   |

Next, to calculate the probability of a collision occurring in one year's
operation of a database, it is assumed that the database size is in
a steady state and that 10% of the database changes per year. For example,
a trillion record database would have 100 billion states per year. Each
of those states has the above calculated probability of a collision.

This assumption is a worst-case since it assumes that each
state of the database is completely independent from the previous state.
In reality this is unlikely as state changes will be the addition or
deletion of a few records.

The following tables gives the time interval until there is a probability of
a collision based on there being one tenth the number of states per year
as the number of records in the database.

      t = 1 / ((k / 10) * p)

      t  Time until a collision
      p  Collision probability for UEID size
      k  Database size

| Database Size           | 128-bit UEID   | 192-bit UEID | 256-bit UEID |
|-------------------------+----------------+--------------+--------------+
| trillion (10^12)        | 60,000 years   | 10^24 years  | 10^44 years  |
| quadrillion (10^15)     | 8 seconds      | 10^14 years  | 10^34 years  |
| 100 quadrillion (10^17) | 8 microseconds | 10^11 years  | 10^31 years  |

Clearly, 128 bits is enough for the near future thus the requirement that UEIDs
be a minimum of 128 bits.

There is no requirement for 256 bits today as quadrillion-record databases
are not expected in the near future and because this time-to-collision
calculation is a very worst case.  A future update of the standard may
increase the requirement to 256 bits, so there is a requirement that
implementations be able to receive 256-bit UEIDs.

## No Use of UUID

A UEID is not a UUID {{RFC4122}} by conscious choice for the following
reasons.

UUIDs are limited to 128 bits which may not be enough for some future
use cases.

Today, cryptographic-quality random numbers are available from common
CPUs and hardware. This hardware was introduced between 2010 and 2015.
Operating systems and cryptographic libraries give access to this
hardware. Consequently, there is little need for implementations
to construct such random values from multiple sources on their own.

Version 4 UUIDs do allow for use of such cryptographic-quality
random numbers, but do so by mapping into the overall UUID
structure of time and clock values. This structure is of no
value here yet adds complexity. It also slightly reduces the
number of actual bits with entropy.

The design of UUID accommodates the construction of a unique identifier by combination of several identifiers that separately do not provide sufficient uniqueness.
UEID takes the view that this construction is no longer needed, in particular because cryptographic-quality random number generators are readily available.
It takes the view that hardware, software and/or manufacturing process implement UEID in a simple and direct way.


# EAT Relation to IEEE.802.1AR Secure Device Identity (DevID)

This section describes several distinct ways in which an IEEE IDevID {{IEEE.802.1AR}} relates to EAT, particularly to UEID and SUEID.

{{IEEE.802.1AR}} orients around the definition of an implementation called a "DevID Module."
It describes how IDevIDs and LDevIDs are stored, protected and accessed using a DevID Module.
A particular level of defense against attack that should be achieved to be a DevID is defined.
The intent is that IDevIDs and LDevIDs can be used with any network protocol or message format.
In these protocols and message formats the DevID secret is used to sign a nonce or similar to prove the association of the DevID certificates with the device.

By contrast, EAT standardize a message format that is sent to a relying party, the very thing that is not defined in {{IEEE.802.1AR}}.
Nor does EAT give details on how keys, data and such are stored protected and accessed.
EAT is intended to work with a variety of different on-device implementations ranging from minimal protection of assets to the highest levels of asset protection.
It does not define any particular level of defense against attack, instead providing a set of security considerations.

EAT and DevID can be viewed as complimentary when used together or as competing to provide a device identity service.

## DevID Used With EAT

As just described, EAT standardizes a message format and {{IEEE.802.1AR}} doesn't.
Vice versa, EAT doesn't define a an device implementation and DevID does.

Hence, EAT can be the message format that a DevID is used with.
The DevID secret becomes the attestation key used to sign EATs.
The DevID and its certificate chain become the endorsement sent to the verifier.

In this case, the EAT and the DevID are likely to both provide a device identifier (e.g. a serial number).
In the EAT it is the UEID (or SUEID).
In the DevID (used as an endorsement), it is a device serial number included in the subject field of the DevID certificate.
It is probably a good idea in this use for them to be the same serial number or for the UEID to be a hash of the DevID serial number.

## How EAT Provides an Equivalent Secure Device Identity

The UEID, SUEID and other claims like OEM ID are equivalent to the secure device identity put into the subject field of a DevID certificate.
These EAT claims can represent all the same fields and values that can be put in a DevID certificate subject.
EAT explicitly and carefully defines a variety of useful claims.

EAT secures the conveyance of these claims by having them signed on the device by the attestation key when the EAT is generated.
EAT also signs the nonce that gives freshness at this time.
Since these claims are signed for every EAT generated, they can include things that vary over time like GPS location.

DevID secures the device identity fields by having them signed by the manufacturer of the device sign them into a certificate.
That certificate is created once during the manufacturing of the device and never changes so the fields cannot change.

So in one case the signing of the identity happens on the device and the other in a manufacturing facility,
but in both cases the signing of the nonce that proves the binding to the actual device happens on the device.

While EAT does not specify how the signing keys, signature process and storage of the identity values should be secured against attack,
an EAT implementation may have equal defenses against attack.
One reason EAT uses CBOR is because it is simple enough that a basic EAT implementation can be constructed entirely in hardware.
This allows EAT to be implemented with the strongest defenses possible.

## An X.509 Format EAT

It is possible to define a way to encode EAT claims in an X.509 certificate.
For example, the EAT claims might be mapped to X.509 v3 extensions.
It is even possible to stuff a whole CBOR-encoded unsigned EAT token into a X.509 certificate.

If that X.509 certificate is an IDevID or LDevID, this becomes another way to use EAT and DevID together.

Note that the DevID must still be used with an authentication protocol that has a nonce or equivalent.
The EAT here is not being used as the protocol to interact with the rely party.

## Device Identifier Permanence

In terms of permanence, an IDevID is similar to a UEID in that they do not change over the life of the device.
They cease to exist only when the device is destroyed.

An SUEID is similar to an LDevID.
They change on device life-cycle events.

{{IEEE.802.1AR}} describes much of this permanence as resistant to attacks that seek to change the ID.
IDevID permanence can be described this way because {{IEEE.802.1AR}} is oriented around the definition of an implementation with a particular level of defense against attack.

EAT is not defined around a particular implementation and must work on a range of devices that have a range of defenses against attack.
EAT thus can't be defined permanence in terms of defense against attack.
EAT's definition of permanence is in terms of operations and device lifecycle.


# CDDL for CWT and JWT {#CDDL_for_CWT}

{{RFC8392}} was published before CDDL was available and thus is specified in prose, not CDDL.
Following is CDDL specifying CWT as it is needed to complete this specification.
This CDDL also covers the Claims-Set for JWT.

Note that {{iat-claim}} requires that the iat claim be the type ~time-int ({{common-types}}), not the type ~time when it is used in an EAT as floating-point values are not allowed for the "iat" claim in EAT.

The COSE-related types in this CDDL are defined in {{RFC9052}}.

This however is NOT a normative or standard definition of CWT or JWT in CDDL.
The prose in CWT and JWT remain the normative definition.

~~~~CDDL
{::include cddl/external/claims-set.cddl}
~~~~

~~~~CDDL
{::include cddl/external/jwt.cddl}
~~~~

~~~~CDDL
{::include cddl/external/cwt.cddl}
~~~~


# Claim Characteristics {#Claim_Characteristics}

The following is design guidance for creating new EAT claims, particularly those to be registered with IANA.

Much of this guidance is generic and could also be considered when designing new CWT or JWT claims.

## Interoperability and Relying Party Orientation

It is a broad goal that EATs can be processed by relying parties in a general way regardless of the type, manufacturer or technology of the device from which they originate.
It is a goal that there be general-purpose verification implementations that can verify tokens for large numbers of use cases with special cases and configurations for different device types.
This is a goal of interoperability of the semantics of claims themselves, not just of the signing, encoding and serialization formats.

This is a lofty goal and difficult to achieve broadly requiring careful definition of claims in a technology neutral way.
Sometimes it will be difficult to design a claim that can represent the semantics of data from very different device types.
However, the goal remains even when difficult.

## Operating System and Technology Neutral

Claims should be defined such that they are not specific to an operating system.
They should be applicable to multiple large high-level operating systems from different vendors.
They should also be applicable to multiple small embedded operating systems from multiple vendors and everything in between.

Claims should not be defined such that they are specific to a software environment or programming language.

Claims should not be defined such that they are specific to a chip or particular hardware.
For example, they should not just be the contents of some HW status register as it is unlikely that the same HW status register with the same bits exists on a chip of a different manufacturer.

The boot and debug state claims in this document are an example of a claim that has been defined in this neutral way.

## Security Level Neutral

Many use cases will have EATs generated by some of the most secure hardware and software that exists.
Secure Elements and smart cards are examples of this.
However, EAT is intended for use in low-security use cases the same as high-security use case.
For example, an app on a mobile device may generate EATs on its own.

Claims should be defined and registered on the basis of whether they are useful and interoperable, not based on security level.
In particular, there should be no exclusion of claims because they are just used only in low-security environments.

## Reuse of Extant Data Formats

Where possible, claims should use already standardized data items, identifiers and formats.
This takes advantage of the expertise put into creating those formats and improves interoperability.

Often extant claims will not be defined in an encoding or serialization format used by EAT.
It is preferred to define a CBOR and JSON encoding for them so that EAT implementations do not require a plethora of encoders and decoders for serialization formats.

In some cases, it may be better to use the encoding and serialization as is.
For example, signed X.509 certificates and CRLs can be carried as-is in a byte string.
This retains interoperability with the extensive infrastructure for creating and processing X.509 certificates and CRLs.


## Proprietary Claims

EAT allows the definition and use of proprietary claims.

For example, a device manufacturer may generate a token with proprietary claims intended only for verification by a service offered by that device manufacturer.
This is a supported use case.

In many cases proprietary claims will be the easiest and most obvious way to proceed, however for better interoperability, use of general standardized claims is preferred.


# Endorsements and Verification Keys {#keyid}

The verifier must possess the correct key when it performs the cryptographic part of an EAT verification (e.g., verifying the COSE/JOSE signature).
This section describes several ways to identify the verification key.
There is not one standard method.

The verification key itself may be a public key, a symmetric key or something complicated in the case of a scheme like Direct Anonymous Attestation (DAA).

RATS Architecture {{RATS.Architecture}} describes what is called an endorsement.
This is an input to the verifier that is usually the basis of the trust placed in an EAT and the attester that generated it.
It may contain the public key for verification of the signature on the EAT.
It may contain implied claims, those that are passed on to the relying party in attestation results.

There is not yet any standard format(s) for an endorsement.
One format that may be used for an endorsement is an X.509 certificate.
Endorsement data like reference values and implied claims can be carried in X.509 v3 extensions.
In this use, the public key in the X.509 certificate becomes the verification key, so identification of the endorsement is also identification of the verification key.

The verification key identification and establishment of trust in the EAT and the attester may also be by some other means than an endorsement.

For the components (attester, verifier, relying party,...) of a particular end-end attestation system to reliably interoperate, its definition should specify how the verification key is identified.
Usually, this will be in the profile document for a particular attestation system.

## Identification Methods

Following is a list of possible methods of key identification. A specific attestation system may employ any one of these or one not listed here.

The following assumes endorsements are X.509 certificates or equivalent and thus does not mention or define any identifier for endorsements in other formats. If such an endorsement format is created, new identifiers for them will also need to be created.

### COSE/JWS Key ID

The COSE standard header parameter for Key ID (kid) may be used. See {{RFC9052}} and {{RFC7515}}

COSE leaves the semantics of the key ID open-ended.
It could be a record locator in a database, a hash of a public key, an input to a KDF, an authority key identifier (AKI) for an X.509 certificate or other.
The profile document should specify what the key ID's semantics are.

### JWS and COSE X.509 Header Parameters

COSE X.509 {{COSE.X509.Draft}} and JSON Web Signature {{RFC7515}} define several header parameters (x5t, x5u,...) for referencing or carrying X.509 certificates any of which may be used.

The X.509 certificate may be an endorsement and thus carrying additional input to the verifier. It may be just an X.509 certificate, not an endorsement. The same header parameters are used in both cases. It is up to the attestation system design and the verifier to determine which.

### CBOR Certificate COSE Header Parameters

Compressed X.509 and CBOR Native certificates are defined by CBOR Certificates {{CBOR.Cert.Draft}}. These are semantically compatible with X.509 and therefore can be used as an equivalent to X.509 as described above.

These are identified by their own header parameters (c5t, c5u,...).

### Claim-Based Key Identification

For some attestation systems, a claim may be re-used as a key identifier. For example, the UEID uniquely identifies the entity and therefore can work well as a key identifier or endorsement identifier.

This has the advantage that key identification requires no additional bytes in the EAT and makes the EAT smaller.

This has the disadvantage that the unverified EAT must be substantially decoded to obtain the identifier since the identifier is in the COSE/JOSE payload, not in the headers.

## Other Considerations

In all cases there must be some way that the verification key is itself verified or determined to be trustworthy.
The key identification itself is never enough.
This will always be by some out-of-band mechanism that is not described here.
For example, the verifier may be configured with a root certificate or a master key by the verifier system administrator.

Often an X.509 certificate or an endorsement carries more than just the verification key.
For example, an X.509 certificate might have key usage constraints and an endorsement might have reference values.
When this is the case, the key identifier must be either a protected header or in the payload such that it is cryptographically bound to the EAT.
This is in line with the requirements in section 6 on Key Identification in JSON Web Signature {{RFC7515}}.


# Changes from Previous Drafts

The following is a list of known changes since the immediately previous drafts.  This list is
non-authoritative.  It is meant to help reviewers see the significant
differences. A comprehensive history is available via the IETF Datatracker's record for this document.

## From draft-ietf-rats-eat-19
- Prefer the term "encoding" over "format" when referring to CBOR and JSON.
- Separate sections for creating and consuming UEIDs
- Base location on W3C reference directly and WGS84 indirectly
- The option for a hash-based OEMID is removed


--- contributor

Many thanks to the following contributors to draft versions of this
document:
