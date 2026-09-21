# deathletter

A small implementation of the DLP/1 packet format

> a message is only dead when nobody knows where to look.

## Overview
`deathletter` is a small command-line utility and packet format designed for secure message exchange.

It provides a self-contained way to encrypt, authenticate, sign and transport messages without requiring both parties to use the same application or communication channel.

DLP packets are designed to be treated as portable encrypted messages:

> message -> encrypt -> sign -> DLP packet -> transport -> verify -> decrypt -> message

The protocol is intentionally small and dependency-light.

## Design goals
DLP/1 is built around a few simple goals:
* **Confidentiality** - message contents should not be readable without the required secret. 
* **Integrity* - modified packets should be detected.
* **Authenticity** - signed packets can be verified against a known public key.
* **Portability** - packets can be stored or transported independently of the application that created them.
* **Inspectability** - packet metadata can be examined without decrypting the payload.
* **Versioning** - protocol revisions can be distinguished without ambiguity.

DLP does not define a transport layer. A packet can be sent through practically any medium capable of carrying binary data.

For example:
- file
- email
- messenger
- HTTP
- TCP
- object storage
- USB
- *in your ass*

The transport is deliberately separated from the message format.

## DLP/1
A DLP packet consists of a fixed header followed by metadata and encrypted payload data.

- magic
- version
- flags
- rotation parameters
- key id
- key checksum
- salt
- nonce
- ciphertext
- authentication tag
- optional signature

The format is versioned so future revisions can introduce incompatible changes without making existing packets ambiguous.

## Cryptography
DLP/1 currently uses:

* AES-256-GCM for authenticated encryption
* scrypt for password-based key derivation
* Ed25519 for optional packet signatures

Default scrypt parameters:
```
N = 32768
r = 8
p = 1
```
The derived encryption key is bound to the packet context and key identifier.

## Usage
#### Generate a key
`deathletter keygen`

#### Encrypt a message
`deathletter encrypt message.txt --output message.dlp`
#### Decrypt a packet
`deathletter decrypt message.dlp --output message.txt`
#### Sign a packet
`deathletter sign message.dlp`
#### Verify a signature
`deathletter verify message.dlp`
#### Inspect a packet
`deathletter inspect message.dlp`

inspect reads packet metadata without decrypting the payload.

## Secure communication

DLP is intended for situations where the communication channel itself should not need to be trusted.

A sender can create an encrypted packet, optionally sign it, and then transport the resulting packet through an untrusted channel.

The recipient only needs the appropriate secret and, when signatures are used, the corresponding public key.

## Security model

DLP provides cryptographic protection for the packet contents and can provide sender authentication through signatures.

**It does not hide all metadata.**

Depending on how a packet is transported, an observer may still be able to determine:

* that a DLP packet exists
* its approximate size
* when it was transmitted
* unencrypted packet metadata
* information exposed by the transport layer

DLP should therefore be considered a message protection format, not an anonymity protocol.

## Project status

DLP/1 is currently experimental.

The format and implementation may change before a stable release.

Expect sharp edges.