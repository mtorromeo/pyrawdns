#!/usr/bin/env python

import pprint
import socket
import struct

from enum import Enum
from array import array
from ipaddress import IPv4Address


class MType(Enum):
  Question = 0
  Response = 1


class OpCode(Enum):
  Query  = 0
  IQuery = 1
  Status = 2
  Notify = 4
  Update = 5


# http://tools.ietf.org/html/rfc1035 3.2.4/3.2.5
class RRClass(Enum):
  IN   = 1 # Internet
  CS   = 2 # CSNET
  CH   = 3 # Chaos
  HS   = 4 # Hesiod
  NONE = 254
  ANY  = 255


# http://tools.ietf.org/html/rfc1035 3.2.2/3.2.3/4.1.2/4.1.3
class RRType(Enum):
  A     = 1
  NS    = 2
  MD    = 3
  MF    = 4
  CNAME = 5
  SOA   = 6
  MB    = 7
  MG    = 8
  MR    = 9
  NULL  = 10
  WKS   = 11
  PTR   = 12
  HINFO = 13
  MINFO = 14
  MX    = 15
  TXT   = 16
  AFXR  = 252
  MAILB = 253
  MAILA = 254
  ALL   = 255


class ResponseCode(Enum):
  NoError  = 0
  FormErr  = 1
  ServFail = 2
  NXDomain = 3
  NotImp   = 4
  Refused  = 5
  YXDomain = 6
  YXRRSet  = 7
  NXRRSet  = 8
  NotAuth  = 9
  NotZone  = 10
  BADVERS  = 16
  BADKEY   = 17
  BADTIME  = 18
  BADMODE  = 19
  BADNAME  = 20
  BADALG   = 21


class Message:
  # http://tools.ietf.org/html/rfc1035 4.1.1
  headerfmt = struct.Struct("!6H")
  # http://tools.ietf.org/html/rfc1035 4.1.2
  queryfmt = struct.Struct("!2H")

  def __init__(self, data=None):
    self.answers = []

    if data is not None:
      self.id, misc, qdcount, self.answer_count, self.authority_count, self.additional_count = self.headerfmt.unpack_from(data)

      self.type                =       MType((misc & 0b1000000000000000) != 0)
      self.opcode              =      OpCode((misc & 0b0111100000000000) >> 11)
      self.is_authoritative    =             (misc & 0b0000010000000000) != 0
      self.is_truncated        =             (misc & 0b0000001000000000) != 0
      self.recursion_desired   =             (misc & 0b0000000100000000) != 0
      self.recursion_available =             (misc & 0b0000000010000000) != 0
      self.reserved            =             (misc & 0b0000000001110000) >> 4
      self.response_code       = ResponseCode(misc & 0b0000000000001111)

      offset = self.headerfmt.size
      self.questions, offset = self._decode_questions(qdcount, data, offset)
    else:
      self.questions = []

  def _decode_questions(self, qdcount, data, offset):
    questions = []

    for _ in range(qdcount):
      qname, offset = self._decode_labels(data, offset)
      qname = ".".join([label.decode("ASCII") for label in qname])

      qtype, qclass = self.queryfmt.unpack_from(data, offset)
      offset += self.queryfmt.size

      question = {
        "name": qname,
        "type": RRType(qtype),
        "class": RRClass(qclass),
      }

      questions.append(question)

    return questions, offset

  def _decode_labels(self, data, offset):
    labels = []

    while True:
      length, = struct.unpack_from("!B", data, offset)

      if (length & 0xC0) == 0xC0:
        pointer, = struct.unpack_from("!H", data, offset)
        offset += 2

        return labels + self._decode_labels(data, pointer & 0x3FFF), offset

      if (length & 0xC0) != 0x00:
        raise StandardError("unknown label encoding")

      offset += 1

      if length == 0:
        return labels, offset

      labels.append(*struct.unpack_from("!%ds" % length, data, offset))
      offset += length

  def __repr__(self):
    return "<{} {}>".format(self.__class__.__name__, pprint.pformat(self.__dict__, indent=2))

  def encode(self):
    misc = (self.opcode.value << 11) | self.response_code.value
    if self.type == MType.Response:
      misc |= 0b1000000000000000
    if self.is_authoritative:
      misc |= 0b0000010000000000
    if self.is_truncated:
      misc |= 0b0000001000000000
    if self.recursion_desired:
      misc |= 0b0000000100000000
    if self.recursion_available:
      misc |= 0b0000000010000000

    data = self.headerfmt.pack(self.id, misc, len(self.questions), len(self.answers), 0, 0)

    for answer in self.answers:
      data += answer.encode()

    return data

  def response(self):
    response = Message()
    response.id                  = self.id
    response.type                = MType.Response
    response.opcode              = self.opcode
    response.is_authoritative    = self.is_authoritative
    response.is_truncated        = 0
    response.recursion_desired   = self.recursion_desired
    response.recursion_available = self.recursion_available
    response.reserved            = 0
    response.response_code       = ResponseCode.NoError
    return response


class ResourceRecord:
  def __init__(self, name, type, rrclass, ttl):
    self.name = name
    self.type = type
    self.rrclass = rrclass
    self.ttl = ttl

  def encode(self):
    data = self.encode_dn(self.name)
    rdata = self.encode_rdata()
    data += struct.pack("!2HLH", self.type.value, self.rrclass.value, self.ttl, len(rdata)) + rdata
    return data

  def encode_dn(self, dn):
    dn = [part.encode("ASCII") for part in dn.split(".")]

    data = b""
    for label in dn:
      data += struct.pack("!B%ds" % len(label), len(label), label)
    data += struct.pack("!B", 0)

    return data

  def encode_rdata(self):
    return b""


class RR_A(ResourceRecord):
  def __init__(self, name, ttl, addr):
    ResourceRecord.__init__(self, name, RRType.A, RRClass.IN, ttl)
    self.addr = IPv4Address(addr)

  def encode_rdata(self):
    return self.addr.packed


class RR_MX(ResourceRecord):
  def __init__(self, name, ttl, preference, exchange):
    ResourceRecord.__init__(self, name, RRType.MX, RRClass.IN, ttl)
    self.preference = preference
    self.exchange = exchange

  def encode_rdata(self):
    return struct.pack("!H", self.preference) + self.encode_dn(self.exchange)


if __name__ == '__main__':
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  host = ''
  port = 53
  size = 512
  s.bind((host, port))
  while True:
    data, addr = s.recvfrom(size)
    message = Message(data)
    print(message)

    if message.opcode != OpCode.Notify:
        response = message.response()
        response.response_code = ResponseCode.NXDomain
        s.sendto(response.encode(), addr)

    #response = message.response()
    #for question in message.questions:
        #response.answers.append(RR_MX(question['name'], 14400, 0, 'mail.artera.it'))

    #s.sendto(response.encode(), addr)
