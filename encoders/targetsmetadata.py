#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from metadataverificationmodule import *

import metadata


def get_asn_signed(json_signed):
  targetsMetadata = TargetsMetadata()\
                    .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                 tag.tagFormatConstructed, 1))

  set_targets(json_signed, targetsMetadata)
  set_delegations(json_signed, targetsMetadata)

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
  set_json_targets(json_signed, targetsMetadata)

  return json_signed


def set_delegations(json_signed, targetsMetadata):
  # Optional bit.
  if len(json_signed['delegations']['keys']) > 0 or \
     len(json_signed['delegations']['roles']) > 0:
    delegations = TargetsDelegations()\
                  .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                               tag.tagFormatSimple, 2))
    set_keys(json_signed, delegations)
    set_roles(json_signed, delegations)
    set_prioritizedPathsToRoles(json_signed, delegations)
    targetsMetadata['delegations'] = delegations


def set_json_targets(json_signed, targetsMetadata):
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


def set_keys(json_signed, delegations):
  keys = PublicKeys().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatSimple, 1))
  numberOfKeys = 0

  for keyid, keymeta in json_signed['delegations']['keys'].items():
    key = PublicKey()
    key['publicKeyid'] = keyid
    key['publicKeyType'] = \
                          int(PublicKeyType(keymeta['keytype'].encode('ascii')))
    value = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                                     tag.tagFormatConstructed,
                                                     2))
    value['hexString'] = keymeta['keyval']['public']
    key['publicKeyValue'] = value
    keys[numberOfKeys] = key
    numberOfKeys += 1

  delegations['numberOfKeys'] = numberOfKeys
  delegations['keys'] = keys


def set_prioritizedPathsToRoles(json_signed, delegations):
  prioritizedPathsToRoles = PrioritizedPathsToRoles()\
                            .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                         tag.tagFormatSimple,
                                                         5))
  numberOfPrioritizedPathsToRoles = 0

  for json_role in json_signed['delegations']['roles']:
    pathsToRoles = PathsToRoles()

    paths = Paths().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 1))
    numberOfPaths = 0

    for json_path in json_role['paths']:
      path = Path(json_path)
      # Some damned bug in pyasn1 I could not care less to fix right now.
      paths.setComponentByPosition(numberOfPaths, path, False)
      numberOfPaths += 1

    pathsToRoles['numberOfPaths'] = 1
    pathsToRoles['paths'] = paths

    roles = RoleNames().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                    tag.tagFormatSimple, 3))
    numberOfRoles = 0

    # NOTE: There are no multi-role delegations (TAP 3) yet in TUF.
    role = RoleName(json_role['name'])
    # Some damned bug in pyasn1 I could not care less to fix right now.
    roles.setComponentByPosition(0, role, False)
    pathsToRoles['numberOfRoles'] = 1
    pathsToRoles['roles'] = roles

    pathsToRoles['terminating'] = True

    prioritizedPathsToRoles[numberOfPrioritizedPathsToRoles] = pathsToRoles
    numberOfPrioritizedPathsToRoles += 1

  delegations['numberOfPrioritizedPathsToRoles'] = \
                                                numberOfPrioritizedPathsToRoles
  delegations['prioritizedPathsToRoles'] = prioritizedPathsToRoles


def set_roles(json_signed, delegations):
  roles = DelegatedTargetsRoles()\
          .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                       tag.tagFormatSimple, 3))
  numberOfRoles = 0

  for json_role in json_signed['delegations']['roles']:
    role = DelegatedTargetsRole()
    role['rolename'] = json_role['name']

    keyids = Keyids().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatSimple, 3))
    numberOfKeyids = 0

    for json_keyid in json_role['keyids']:
      keyid = Keyid(json_keyid)
      # Some damned bug in pyasn1 I could not care less to fix right now.
      keyids.setComponentByPosition(numberOfKeyids, keyid, False)
      numberOfKeyids += 1

    role['numberOfKeyids'] = numberOfKeyids
    role['keyids'] = keyids

    role['threshold'] = json_role['threshold']
    roles[numberOfRoles] = role
    numberOfRoles += 1

  delegations['numberOfRoles'] = numberOfRoles
  delegations['roles'] = roles


def set_targets(json_signed, targetsMetadata):
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


if __name__ == '__main__':
  metadata.test('director.json', 'targets.ber', get_asn_signed,
                get_json_signed, metadata.identity_update_json_signature)
