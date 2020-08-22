#
#                         DNS stamps implementation
#            Copyright (c) 2020 Leorize <leorize+oss@disroot.org>
#
#  This Source Code Form is subject to the terms of the Mozilla Public License,
#  v. 2.0. If a copy of the MPL was not distributed with this file, You can
#  obtain one at https://mozilla.org/MPL/2.0/.

import std / with, base64, endians

## An implementation of DNS stamps as described at:
## https://dnscrypt.info/stamps-specifications

type
  Protocol* = enum
    ## Protocol of the DNS server.
    ##
    ## See also:
    ##
    ## * `toInt <#toInt,Protocol>`_ for getting the integer identifier of the
    ##   protocol.
    ## * `intToProtocol <#intToProtocol,int>`_ for converting an integer to
    ##   `Protocol`.
    protoDns = "DNS"
    protoDnsCrypt = "DNSCrypt"
    protoDnsOverHttps = "DNS-over-HTTPS"
    protoDnsOverTls = "DNS-over-TLS"
    protoDnsCryptRelay = "Anonymized DNSCrypt relay"

  Properties* = enum
    ## Informal properties of the DNS server.
    propDnssec = "DNSSEC"
    propNoLog = "No logs"
    propNoFilter = "No filter"

  Stamp* = object
    ## The structured representation of a DNS server stamp.
    address*: string ## The IP address (and/or port) to the server.
    props*: set[Properties] ## The set of informal properties of the server

    case proto*: Protocol ## The protocol of the stamp.
    of protoDnsCrypt:
      providerName*: string ## The name of the DNSCrypt provider
      publicKey*: array[32, byte] ## The Ed25519 public key of the provider
    of protoDnsOverHttps, protoDnsOverTls:
      hashes*: seq[array[32, byte]]
        ## The list of SHA256 digests of the TBS certificates in the
        ## certification chain. Should not be empty.
      hostname*, path*: string
        ## Hostname and path to the resolver.
        ## Hostname must not be empty.
        ## Path is ignored for DNS-over-TLS stamps.
      bootstrapIps*: seq[string]
        ## The list of regular DNS resolvers recommended for resolving the
        ## hostname if no IP address is provided. Can be empty.
    else:
      discard

const
  RelayDistance = protoDnsCryptRelay.ord - protoDnsCrypt.ord
    ## The distance between a relay type and the "normal" type.
  RelayMask = 0x80
  MoreItemMask = 0x80
  StampPrefix = "sdns://"

func toInt*(protocol: Protocol): int {.inline.} =
  ## Returns the integer identifier of the given `protocol`.
  case protocol
  of protoDns..protoDnsOverTls: protocol.ord
  of protoDnsCryptRelay: RelayMask or protocol.pred(RelayDistance).toInt()

func intToProtocol*(i: int): Protocol {.inline.} =
  ## Returns the `Protocol` corresponding to the given integer `i`.
  ##
  ## Raises `ValueError` if `i` is not a valid protocol identifier.
  var proto = i and not RelayMask
  if (i and RelayMask) != 0:
    proto.inc RelayDistance
  if proto notin Protocol.low.ord..Protocol.high.ord:
    raise newException(ValueError, $i & " is not a valid protocol identifier")
  result = proto.Protocol

func isRelay*(protocol: Protocol): bool {.inline.} =
  ## Returns whether the given `protocol` is a relay type.
  protocol >= protoDnsCryptRelay

func initDnsStamp*(address: string,
                   props: set[Properties] = {}): Stamp {.inline.} =
  ## Create a DNS server stamp.
  ##
  ## :address: The IP address of the resolver, must not be empty.
  ## :props: The set of informal `Properties <#Properties>`_ of the resolver.
  assert address != "", "Address must not be empty for a DNS server"
  result = Stamp(address: address, props: props, proto: protoDns)

func initDnsCryptStamp*(address: string, publicKey: openArray[byte],
                        providerName: string,
                        props: set[Properties] = {}): Stamp {.inline.} =
  ## Create a DNSCrypt server stamp.
  ##
  ## :address:
  ##   The IP address of the resolver with an optional port number if not
  ##   reachable via the standard port (443), must not be empty.
  ## :publicKey:
  ##   The provider's Ed25519 public key in bytes. The array must be exactly 32
  ##   bytes in size.
  ## :providerName: The name of the provider, must not be empty.
  ## :props: The set of informal `Properties <#Properties>`_ of the resolver.
  assert address != "", "Address must not be empty for a DNSCrypt server"
  assert publicKey.len == 32,
    "The length of the provider's Ed25519 public key must be exactly 32 bytes"
  assert providerName != "", "The provider name must not be empty"

  result = Stamp(
    address: address, props: props, proto: protoDnsCrypt,
    providerName: providerName
  )

  copyMem(addr result.publicKey[0], unsafeAddr publicKey[0],
          result.publicKey.len)

func initDoHStamp*(address: string = "", hashes: openArray[array[32, byte]],
                   hostname: string, path = "/dns-query",
                   bootstrapIps: openArray[string] = [],
                   props: set[Properties] = {}): Stamp {.inline.} =
  ## Create a DNS-over-HTTPS server stamp.
  ##
  ## :address:
  ##   The IP address of the resolver. Can be empty or just a port number
  ##   represented with a preceding colon (eg. `:443`).
  ## :hashes:
  ##   List of SHA256 digests of the TBS certificates found in the verification
  ##   chain, typically the certificates used to sign the resolver's
  ##   certificate. At least one hash must be present.
  ## :hostname: The server host name, must not be empty.
  ## :path: The absolute URI path to the resolver (eg. ``/dns-query``).
  ## :bootstrapIps:
  ##   The list of IP addresses of recommended resolvers accessible over
  ##   standard DNS in order to resolve ``hostname``.
  ## :props: The set of informal `Properties <#Properties>`_ of the resolver.
  assert hostname != "", "The hostname of the DoH server must not be empty"
  assert hashes != []

  result = Stamp(
    address: address, props: props, proto: protoDnsOverHttps,
    hashes: @hashes, hostname: hostname, path: path,
    bootstrapIps: @bootstrapIps
  )

func initDoTStamp*(address: string, hashes: openArray[array[32, byte]],
                   hostname: string, bootstrapIps: openArray[string] = [],
                   props: set[Properties] = {}): Stamp {.inline.} =
  ## Create a DNS-over-TLS server stamp.
  ##
  ## :address:
  ##   The IP address of the resolver. Can be empty or just a port number
  ##   represented with a preceding colon (eg. `:853`).
  ## :hashes:
  ##   List of SHA256 digests of the TBS certificates found in the verification
  ##   chain, typically the certificates used to sign the resolver's
  ##   certificate. At least one hash must be present.
  ## :hostname: The server host name, must not be empty.
  ## :bootstrapIps:
  ##   The list of IP addresses of recommended resolvers accessible over
  ##   standard DNS in order to resolve ``hostname``.
  ## :props: The set of informal `Properties <#Properties>`_ of the resolver.
  assert hostname.len > 0
  assert hashes.len > 0

  result = Stamp(
    address: address, props: props, proto: protoDnsOverTls,
    hashes: @hashes, hostname: hostname, bootstrapIps: @bootstrapIps
  )

func initDnsCryptRelayStamp*(address: string): Stamp {.inline.} =
  ## Create an Anonymized DNSCrypt relay stamp.
  ##
  ## :address: The IP address of the relay, must not be empty.
  result = Stamp(address: address, proto: protoDnsCryptRelay)

func addProps(r: var seq[byte], props: set[Properties]) =
  var p: uint64
  p = p or cast[byte](props)
  r.setLen r.len + sizeof(p)
  littleEndian64(addr r[^sizeof(p)], addr p)

func addEncodedBytes(r: var seq[byte], b: openArray[byte], mask: byte = 0) =
  assert b.len <= 0x80

  r.add b.len.byte or mask
  r.add b

func addEncodedBytes(r: var seq[byte], b: openArray[char], mask: byte = 0) =
  r.addEncodedBytes b.toOpenArrayByte(b.low, b.high), mask

func addEncodedSet[T](r: var seq[byte], set: T, encodeEmpty = false) =
  if encodeEmpty and set.len == 0:
    r.addEncodedBytes default(seq[byte])
  else:
    for idx, item in set:
      r.addEncodedBytes item, if idx < set.high: MoreItemMask else: 0

proc addStamp*(s: var string, stamp: Stamp) =
  ## Append the string representaton of `stamp` to `s`.
  s.add StampPrefix
  var rawStamp: seq[byte]
  rawStamp.add byte stamp.proto.toInt()
  if stamp.proto < protoDnsCryptRelay:
    rawStamp.addProps stamp.props
  rawStamp.addEncodedBytes stamp.address

  case stamp.proto
  of protoDnsCrypt:
    if not stamp.proto.isRelay:
      with rawStamp:
        addEncodedBytes stamp.publicKey
        addEncodedBytes stamp.providerName
  of protoDnsOverHttps, protoDnsOverTls:
    with rawStamp:
      addEncodedSet stamp.hashes
      addEncodedBytes stamp.hostname
    if stamp.proto == protoDnsOverHttps:
      rawStamp.addEncodedBytes stamp.path
    rawStamp.addEncodedSet stamp.bootstrapIps
  else:
    discard

  s.add encode(rawStamp, safe = true)

  # Chomp base64 padding.
  if s[^1] == '=':
    s.setLen s.len - 1
  if s[^1] == '=':
    s.setLen s.len - 1

proc `$`*(stamp: Stamp): string {.inline.} =
  ## Convert `stamp` into its string representation.
  result.addStamp stamp
