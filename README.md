# eat
Entity Attestation Token IETF Draft Standard

Entity Attestation Token (EAT) is proposed as a general purpose signed 
attestation token to prove provenance and characteristics about an end 
client device, node or entity to a server or service. The proposal uses 
CBOR to represent claims to be small, compact and general purpose, 
particularly for very small IoT devices. COSE is used so the 
cryptography and signing is up to date. 

EAT is not tied to any particular use case. It is intended as a 
general mechanism for any use case where a server or service requires 
proof of device provenance, configuration and characteristics. These use 
cases might include IoT device claiming and on boarding, online banking 
and payments, biometric authentication, DRM/content protection and 
authentication risk engine inputs. 

EAT is intended to be flexible with regard to the devices signing key 
material so as to accommodate many device manufacturing scenarios. For 
example, the proposal can use IEEE Device ID, ECDAA or even symmetric 
key material.

Info and subscription for IETF mailing list: https://www.ietf.org/mailman/listinfo/EAT

Archives of IETF mailing list: https://mailarchive.ietf.org/arch/browse/eat/

