#           Copyright (c) 2020, Leorize <leorize+oss@disroot.org>
#
# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at http://mozilla.org/MPL/2.0/.

import strutils, unittest

import dnsstamps

# test cases shamelessly copied from
# https://github.com/ameshkov/dnsstamps/blob/master/dnsstamps_test.go
#
# The reference online stamp calculator at https://dnscrypt.info/stamps
# was used to generate many of the "expected" stamps here.
#
# generated with:
# openssl x509 -noout -fingerprint -sha256 -inform pem -in /etc/ssl/certs/Go_Daddy_Class_2_CA.pem
const
  PubKeyStr = "C3:84:6B:F2:4B:9E:93:CA:64:27:4C:0E:C6:7C:1E:CC:5E:02:4F:FC:AC:D2:D7:40:19:35:0E:81:FE:54:6A:E4"
  PubKey = PubKeyStr.replace(":").parseHexStr()
  PubKey32 = block:
    var result: array[32, byte]
    for idx, i in PubKey:
      result[idx] = i.byte
    result

suite "DNS":
  test "Stamp creation":
    let stamp = initDnsStamp("127.0.0.1", {propNoLog})
    check $stamp == "sdns://AAIAAAAAAAAACTEyNy4wLjAuMQ"

suite "DNSCrypt":
  test "Stamp creation":
    let stamp = initDnsCryptStamp("127.0.0.1", cast[seq[byte]](PubKey),
                                  "2.dnscrypt-cert.localhost",
                                  {propDnssec, propNoLog, propNoFilter})
    check $stamp == "sdns://AQcAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5BkyLmRuc2NyeXB0LWNlcnQubG9jYWxob3N0"

suite "DNS-over-HTTPS":
  test "Stamp creation (with IP)":
    let stamp = initDoHStamp("127.0.0.1", [PubKey32], "localhost",
                             props = {propDnssec})
    check $stamp == "sdns://AgEAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5Alsb2NhbGhvc3QKL2Rucy1xdWVyeQ"

  test "Stamp creation (no IP)":
    let stamp = initDoHStamp("", [PubKey32], "localhost", "/experimental")
    check $stamp == "sdns://AgAAAAAAAAAAACDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5Alsb2NhbGhvc3QNL2V4cGVyaW1lbnRhbA"

  ## TODO: Test with bootstrap DNS

suite "DNS-over-TLS":
  test "Stamp creation (with IP)":
    let stamp = initDoTStamp("127.0.0.1", [PubKey32], "localhost",
                             props = {propDnssec})
    check $stamp == "sdns://AwEAAAAAAAAACTEyNy4wLjAuMSDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5Alsb2NhbGhvc3Q"

  test "Stamp creation (no IP)":
    let stamp = initDoTStamp("", [PubKey32], "localhost")
    check $stamp == "sdns://AwAAAAAAAAAAACDDhGvyS56TymQnTA7GfB7MXgJP_KzS10AZNQ6B_lRq5Alsb2NhbGhvc3Q"

  ## TODO: Test with bootstrap DNS

suite "Anonymized DNSCrypt relay":
  test "Stamp creation":
    let stamp = initDnsCryptRelayStamp("127.0.0.1")
    check $stamp == "sdns://gQkxMjcuMC4wLjE"
