#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from metadataverificationmodule import *

import metadata

import json

def get_asn_signed(json_signed):
  timestampMetadata = TimestampMetadata()\
                      .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                   tag.tagFormatConstructed, 3))
  filename = 'snapshot.json'
  meta = json_signed['meta'][filename]
  timestampMetadata['filename'] = filename
  timestampMetadata['version'] = meta['version']
  timestampMetadata['length'] = meta['length']
  timestampMetadata['numberOfHashes'] = 1
  hashes = Hashes().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 4))
  hash = Hash()
  hash['function'] = int(HashFunction('sha256'))
  digest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                                    tag.tagFormatConstructed,
                                                    1))
  digest['hexString'] = meta['hashes']['sha256']
  hash['digest'] = digest
  hashes[0] = hash
  timestampMetadata['hashes'] = hashes

  signedBody = SignedBody()\
               .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                            tag.tagFormatConstructed, 3))
  signedBody['timestampMetadata'] = timestampMetadata

  signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatConstructed, 0))
  signed['type'] = int(RoleType('timestamp'))
  signed['expires'] = metadata.iso8601_to_epoch(json_signed['expires'])
  signed['version'] = json_signed['version']
  signed['body'] = signedBody

  return signed


def get_json_signed(asn_metadata):
  json_signed = {
    '_type': 'Timestamp'
  }

  asn_signed = asn_metadata['signed']
  json_signed['expires'] = metadata.epoch_to_iso8601(asn_signed['expires'])
  json_signed['version'] = int(asn_signed['version'])

  timestampMetadata = asn_signed['body']['timestampMetadata']
  json_signed['meta'] = {
    'snapshot.json' : {
      'hashes': {
        'sha256': str(timestampMetadata['hashes'][0]['digest']['hexString'])
      },
      'length': int(timestampMetadata['length']),
      'version': int(timestampMetadata['version'])
    }
  }

  return json_signed


if __name__ == '__main__':
  # 1. Read from JSON.
  with open('timestamp.json', 'rb') as jsonFile:
    before_json = json.load(jsonFile)
  json_signed = before_json['signed']
  json_signatures = before_json['signatures']

  # 2. Write the signed encoding.
  asn_signed, ber_signed = metadata.get_asn_and_ber_signed(get_asn_signed,
                                                           json_signed)
  # TODO: Use the hash(ber_signed) to MODIFY json_signatures.
  with open ('timestamp.ber', 'wb') as berFile:
    ber_metadata = metadata.json_to_ber_metadata(asn_signed, ber_signed,
                                                 json_signatures)
    berFile.write(ber_metadata)

  # 3. Read it back to check the signed hash.
  with open('timestamp.ber', 'rb') as berFile:
    ber_metadata = berFile.read()
  # TODO: In after_json, check that signatures match signed_hash.
  after_json = metadata.ber_to_json_metadata(get_json_signed, ber_metadata)
  metadata.pretty_print(after_json)
