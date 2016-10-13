#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from pyasn1.codec.ber import encoder, decoder

from metadataverificationmodule import *

from datetime import datetime
import calendar
import hashlib
import json


def ber_to_json_metadata(get_json_signed, ber_metadata):
  asn_metadata = decoder.decode(ber_metadata, asn1Spec=Metadata())[0]

  asn_signed = asn_metadata['signed']
  ber_signed = get_ber_signed(asn_signed)
  ber_signed_digest = hashlib.sha256(ber_signed).hexdigest()

  json_signatures = []
  asn_signatures = asn_metadata['signatures']

  for i in xrange(asn_metadata['numberOfSignatures']):
    asn_signature = asn_signatures[i]
    asn_digest = asn_signature['hash']['digest']['hexString']
    assert asn_digest == ber_signed_digest

    # Cheap hack.
    method = int(asn_signature['method'])
    assert method == 1
    method = 'ed25519'

    json_signature = {
      'keyid': str(asn_signature['keyid']),
      'method': method,
      'sig': str(asn_signature['value'])
    }
    json_signatures.append(json_signature)

  return {
    'signatures': json_signatures,
    # NOTE: Check that signatures are for signed_hash instead of signed.
    'signed_hash': ber_signed_digest,
    'signed': get_json_signed(asn_metadata)
  }


def epoch_to_iso8601(timestamp):
  return datetime.utcfromtimestamp(timestamp).isoformat()+'Z'


def get_asn_and_ber_signed(get_asn_signed, json_signed):
  asn_signed = get_asn_signed(json_signed)
  ber_signed = get_ber_signed(asn_signed)
  return asn_signed, ber_signed


def get_ber_signed(asn_signed):
  return encoder.encode(asn_signed)


def iso8601_to_epoch(datestring):
  return calendar.timegm(datetime.strptime(datestring,
                                           "%Y-%m-%dT%H:%M:%SZ").timetuple())


def json_to_ber_metadata(asn_signed, ber_signed, json_signatures):
  metadata = Metadata()
  metadata['signed'] = asn_signed
  signedDigest = hashlib.sha256(ber_signed).hexdigest()

  asn_signatures = Signatures()\
                   .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 2))
  counter = 0

  for json_signature in json_signatures:
    asn_signature = Signature()
    asn_signature['keyid'] = json_signature['keyid']
    asn_signature['method'] = \
                  int(SignatureMethod(json_signature['method'].encode('ascii')))
    asn_hash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatConstructed, 2))
    asn_hash['function'] = int(HashFunction('sha256'))
    asn_digest = BinaryData()\
                 .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                              tag.tagFormatConstructed, 1))
    asn_digest['hexString'] = signedDigest
    asn_hash['digest'] = asn_digest
    asn_signature['hash'] = asn_hash
    asn_signature['value'] = json_signature['sig']
    asn_signatures[counter] = asn_signature
    counter += 1

  metadata['numberOfSignatures'] = counter
  metadata['signatures'] = asn_signatures
  return encoder.encode(metadata)


def pretty_print(json_metadata):
  print(json.dumps(json_metadata, sort_keys=True, indent=2,
                   separators=(',', ': ')))
