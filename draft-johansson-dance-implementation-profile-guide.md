---
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is draft-<yourname>-<workgroup>-<name>.md
#
# Set the "title" field below at the same time.  The "abbrev" field should be
# updated too.  "abbrev" can be deleted if your title is short.
#
# You can edit the contents of the document as the same time.
# Initial setup only needs the filename and title.
# If you change title or name later, you can run the "Rewrite README" action.
#
# Do not include "-latest" in the file name.
# The tools use "draft-<name>-latest" to find the draft name *inside* the draft,
# such as the "docname" field below, and replace it with a draft number.
# The "docname" field below can be left alone: it will be updated for you.
#
# This template uses kramdown-rfc2629: https://github.com/cabo/kramdown-rfc2629
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
# Delete this comment when you are done.
#
title: "Recommendations on writing DANCE implementation profiles"
abbrev: "DANCE-guide-implementation-profiles"
docname: draft-johansson-dance-implementation-profile-guide-latest
category: info

ipr: trust200902
area: Internet
workgroup: DANCE
keyword: Internet-Draft

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    name: Ash Wilson
    organization: Valimail
    email: ash.d.wilson@gmail.com
 -
    name: Shumon Huque
    organization: Salesforce
    email: shuque@gmail.com
 -
    name: Olle Johansson
    organization: Edvina.net
    email: oej@edvina.net
 -
    name: Michael Richardson
    organization: Sandelman Software Works Inc
    email: mcr+ietf@sandelman.ca

normative:

informative:

--- abstract

This informational document provide guidance for authors and implementors of protocol-specific
DANCE implementations.

--- middle

# Introduction

DANCE provides a way for TLS clients to authenticate to services using certificates
that are anchored in DNSsec using DANE DNS records. The TLS client provides a DNS name
either in the TLS setup or in the TLS client certificate that the server.

The way to apply this to various protocols and implementations and how to convert
identifiers to DNS names vary. This document outlines a few general principles
and things to think of when writing documents specifying how to apply the DANCE
client authentication to a specific situation.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

**Identity provisioning:** This refers to the set of tasks required to securely provision an asymmetric key pair for the device, sign the certificate (if the public credential is not simply a raw public key), and publish the public key or certificate in DNS. Under some circumstances, these steps are not all performed by the same party or organization. A manufacturer may instantiate the key pair, and a systems integrator may be responsible for issuing (and publishing) the device certificate in DNS. In some circumstances, a manufacturer may also publish device identity records in DNS. In this case, the system integrator needs to perform network and application access configuration, since the identity already exists in DNS.

**Security Domain:** DNS-bound client identity allows the device to establish secure communications with any server with a DNS-bound identity, as long as a network path exists, the entity is configured to trust its communicating peer by name, and agreement on protocols can be achieved. The act of joining a security domain, in the past, may have involved certificate provisioning. Now, it can be as simple as using a manufacturer-provisioned identity to join the device to the network and application.

**Client:** This architecture document adopts the definition of "Client" from RFC 8446: "The endpoint initiating the TLS connection"

**Server:** This architecture document adopts the definition of "Server" from RFC 8446: "The endpoint that did not initiate the TLS connection"

**Sending agent:** Software which encodes and transmits messages. A sending agent may perform tasks related to generating cryptographic signatures and/or encrypting messages before transmission.

**Receiving agent:** Software which interprets and processes messages. A receiving agent may perform tasks related to the decryption of messages, and verification of message signatures.

**Store-and-forward system:** A message handling system in-path between the sending agent and the receiving agent.

**Hardware supplier role:** The entity which manufactures or assembles the physical device. In many situations, multiple hardware suppliers are involved in producing a given device. In some cases, the hardware supplier may provision an asymmetric key pair for the device and establish the device identity in DNS. In some cases, the hardware supplier may ship a device with software pre-installed.

**Systems integrator:** The party responsible for configuration and deployment of application components. In some cases, the systems integrator also installs the software onto the device, and may provision the device identity in DNS.

**Consumer:** The entity or organization which pays for the value provided by the application, and defines the success criteria for the output of the application.

## Availability

## Privacy

If the name of the identity proven by a certificate is directly or indirectly relatable to a person, privacy needs to be considered when forming the name of the DNS resource record for the certificate.
When creating the name of the RR, effects of DNS zone walking and possible harvesting of identities in the DNS zone will have to be considered. The name of the RR may note have to have a direct relation to the name of the subject of the certificate.

### DNS Scalability

In the use case for IoT an implementation must be scalable to a large amount of devices. In many cases, identities may also be very short lived as revocation is performed by simply removing a DNS record. A zone will have to manage a large amount of changes as devices are constantly added and de-activated.

In these cases it is important to consider the architecture of the DNS zone and when possible use a tree-like structure with many subdomain parts, much like reverse DNS records or how telephone numbers are represented in the [https://datatracker.ietf.org/doc/html/rfc6116](ENUM) standard RFC 6116.

If an authoritative resolver were configured to respond quite slowly (think slow loris), is it possible to cause a DoS on the TLS server via complete exhaustion of TCP connections?

The availability of a client identity zone is essential to permitting clients to authenticate. If the DNS infrastructure hosting client identities becomes unavailable, then the clients represented by that zone cannot be authenticated.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
