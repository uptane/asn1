#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from metadataverificationmodule import *

import metadata


def get_asn_signed(json_signed):
  targetsMetadata = TargetsMetadata()\
                    .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                 tag.tagFormatConstructed, 1))
  targets = Targets().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatSimple, 1))
  numberOfTargets = 0

  for filename, filemeta in json_signed['targets'].items():
    targetAndCustom = TargetAndCustom()

    target = Target().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatConstructed, 0))
    target['filename'] = filename
    target['length'] = filemeta['length']

    hashes = Hashes().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatSimple, 3))
    numberOfHashes = 0

    for hash_function, hash_value in filemeta['hashes'].items():
      hash = Hash()
      hash['function'] = int(HashFunction(hash_function.encode('ascii')))
      digest = BinaryData()\
               .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                            tag.tagFormatConstructed, 1))
      digest['hexString'] = hash_value
      hash['digest'] = digest
      hashes[numberOfHashes] = hash
      numberOfHashes += 1

    target['numberOfHashes'] = numberOfHashes
    target['hashes'] = hashes
    targetAndCustom['target'] = target

    # Optional bit.
    if 'custom' in filemeta:
      custom = Custom().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                    tag.tagFormatConstructed,
                                                    1))
      custom['ecuIdentifier'] = filemeta['custom']['ecu-serial-number']
      targetAndCustom['custom'] = custom

    targets[numberOfTargets] = targetAndCustom
    numberOfTargets += 1

  targetsMetadata['numberOfTargets'] = numberOfTargets
  targetsMetadata['targets'] = targets

  signedBody = SignedBody()\
               .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                            tag.tagFormatConstructed, 3))
  signedBody['targetsMetadata'] = targetsMetadata

  signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatConstructed, 0))
  signed['type'] = int(RoleType('snapshot'))
  signed['expires'] = metadata.iso8601_to_epoch(json_signed['expires'])
  signed['version'] = json_signed['version']
  signed['body'] = signedBody

  return signed


def get_json_signed(asn_metadata):
  json_signed = {
    '_type': 'Targets',
    'delegations': {
     'keys': {},
     'roles': []
    },
  }

  asn_signed = asn_metadata['signed']
  json_signed['expires'] = metadata.epoch_to_iso8601(asn_signed['expires'])
  json_signed['version'] = int(asn_signed['version'])

  targetsMetadata = asn_signed['body']['targetsMetadata']
  numberOfTargets = int(targetsMetadata['numberOfTargets'])
  targets = targetsMetadata['targets']
  json_targets = {}

  for i in range(numberOfTargets):
    targetAndCustom = targets[i]

    target = targetAndCustom['target']
    filename = str(target['filename'])
    filemeta = {'length': int(target['length'])}

    numberOfHashes = int(target['numberOfHashes'])
    # Quick workaround for now.
    hashenum_to_hashfunction = {
      1: 'sha256',
      3: 'sha512'
    }
    hashes = target['hashes']
    json_hashes = {}
    for j in range(numberOfHashes):
      hash = hashes[j]
      hash_function = hashenum_to_hashfunction[int(hash['function'])]
      hash_value = str(hash['digest']['hexString'])
      json_hashes[hash_function] = hash_value
    filemeta['hashes'] = json_hashes

    # Optional bit.
    custom = targetAndCustom['custom']
    if custom:
      json_custom = {
        'ecu-serial-number': str(custom['ecuIdentifier']),
        # FIXME: Hard-coded for now!
        'type': 'application'
      }
      filemeta['custom'] = json_custom

    json_targets[filename] = filemeta

  json_signed['targets'] = json_targets

  return json_signed


if __name__ == '__main__':
  metadata.test('director.json', 'targets.ber', get_asn_signed,
                get_json_signed, metadata.identity_update_json_signature)
