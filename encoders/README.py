#!/usr/bin/env python

import hashlib
import json

import tuf.repository_tool
import tuf.keys

import metadata
import rootmetadata
import snapshotmetadata
import targetsmetadata
import timestampmetadata


def seamless_transport_of_json_over_ber(json_in_filename, ber_filename,
                                        json_out_filename, get_asn_signed,
                                        get_json_signed):
  '''This function demonstrates how to seamlessly transport JSON over BER
  without modifying JSON signatures.
  This is useful for TUF metadata (root, timestamp, snapshot, targets) that need
  to be exchanged between repositories and primaries, or primaries and
  secondaries, and that are signed and verified using the TUF Python reference
  implementation.

  The first three parameters are: (1) the input JSON filename, (2) the
  intermediary BER filename, and (3) the output JSON filename.
  The fourth and fifth parameters are the get_asn_signed and get_json_signed
  functions from either the timestampmetadata, snapshotmetadata, rootmetadata,
  or targetsmetadata module, depending on which type of JSON metadata is being
  converted.'''

  # 1. Read from JSON.
  with open(json_in_filename, 'rb') as json_in_file:
    before_json = json.load(json_in_file)
  print('Read {}'.format(json_in_filename))
  json_signed = before_json['signed']
  json_signatures = before_json['signatures']

  # 2. Write the BER encoding of the JSON.
  asn_signed, ber_signed = metadata.get_asn_and_ber_signed(get_asn_signed,
                                                           json_signed)
  with open (ber_filename, 'wb') as ber_file:
    ber_metadata = metadata.json_to_ber_metadata(asn_signed, ber_signed,
                                                 json_signatures)
    ber_file.write(ber_metadata)
  print('Wrote {}'.format(ber_filename))

  # 3. Read it back to check the signed hash.
  with open(ber_filename, 'rb') as ber_file:
    ber_metadata = ber_file.read()
  print('Read {}'.format(ber_filename))

  after_json = metadata.ber_to_json_metadata(get_json_signed, ber_metadata)
  with open(json_out_filename, 'wb') as json_out_file:
    json.dump(after_json, json_out_file, sort_keys=True, indent=1,
              separators=(',', ': '))
  print('Wrote {}'.format(json_out_filename))


def sign_the_ber_not_the_json(json_in_filename, ber_filename, json_out_filename,
                              get_asn_signed, get_json_signed):
  '''This function demonstrates how to encode JSON in BER, but *replacing* the
  signatures with the hash of the BER signed message, rather than of the entire
  JSON signed message.
  This is useful for exchanging time server messages, ECU version manifests,
  or vehicle version manifests between repositories and primaries, or primaries
  and secondaries.

  The first three parameters are: (1) the input JSON filename, (2) the
  intermediary BER filename, and (3) the output JSON filename.
  The fourth and fifth parameters are the get_asn_signed and get_json_signed
  functions from either the timestampmetadata, snapshotmetadata, rootmetadata,
  or targetsmetadata module, depending on which type of JSON metadata is being
  converted.'''

  timestamp_keyid = \
              'da9c65c96c5c4072f6984f7aa81216d776aca6664d49cb4dfafbc7119320d9cc'
  timestamp_keyval = \
              'f4ac8d95cfdf65a4ccaee072ba5a48e8ad6a0c30be6ffd525aec6bc078211033'
  keyid_to_keyfilename = {
    timestamp_keyid: 'timestamp.pri'
  }
  keyid_to_keypasswd = {
    timestamp_keyid: 'pw'
  }
  keyid_to_keyval = {
    timestamp_keyid: timestamp_keyval
  }

  def update_json_signature(ber_signed_digest, json_signature):
    keyid = json_signature['keyid']
    keyfilename = keyid_to_keyfilename[keyid]
    keypasswd = keyid_to_keypasswd[keyid]
    private_key = tuf.repository_tool\
                     .import_ed25519_privatekey_from_file(keyfilename,
                                                          password=keypasswd)
    signature = tuf.keys.create_signature(private_key, ber_signed_digest)
    # NOTE: Update the original JSON signature object!
    json_signature['sig'] = signature['sig']

  def check_json_signature(json_signature):
    keyid = json_signature['keyid']
    keyval = keyid_to_keyval[keyid]
    method = json_signature['method']
    sig = json_signature['sig']
    hash = json_signature['hash']

    keydict = {
      'keytype': method,
      'keyid': keyid,
      'keyval': {
        'public': keyval
      }
    }

    sigdict = {
      'keyid': keyid,
      'method': method,
      'sig': sig
    }

    assert tuf.keys.verify_signature(keydict, sigdict, hash)

  # 1. Read from JSON.
  with open(json_in_filename, 'rb') as json_in_file:
    before_json = json.load(json_in_file)
  print('Read {}'.format(json_in_filename))
  json_signed = before_json['signed']
  json_signatures = before_json['signatures']

  # 2. Write the signed BER.
  asn_signed, ber_signed = metadata.get_asn_and_ber_signed(get_asn_signed,
                                                           json_signed)
  ber_signed_digest = hashlib.sha256(ber_signed).hexdigest()

  # NOTE: Use ber_signed_digest to *MODIFY* json_signatures.
  for json_signature in json_signatures:
    update_json_signature(ber_signed_digest, json_signature)

  with open (ber_filename, 'wb') as ber_file:
    ber_metadata = metadata.json_to_ber_metadata(asn_signed, ber_signed,
                                                 json_signatures)
    ber_file.write(ber_metadata)
  print('Wrote {}'.format(ber_filename))

  # 3. Read it back to check the signed hash.
  with open(ber_filename, 'rb') as ber_file:
    ber_metadata = ber_file.read()
  print('Read {}'.format(ber_filename))

  # This function checks that, indeed,
  # Metadata.signatures[i].hash==hash(BER(Metadata.signed)).
  after_json = metadata.ber_to_json_metadata(get_json_signed, ber_metadata)

  # NOTE: In after_json, check that each signature is of that hash.
  for json_signature in after_json['signatures']:
    check_json_signature(json_signature)

  with open(json_out_filename, 'wb') as json_out_file:
    json.dump(after_json, json_out_file, sort_keys=True, indent=1,
              separators=(',', ': '))
  print('Wrote {}'.format(json_out_filename))


if __name__ == '__main__':
  # These two functions are almost identical, except for a subtle difference.
  seamless_transport_of_json_over_ber('timestamp.json',
                                      'timestamp2.ber',
                                      'timestamp2.json',
                                      timestampmetadata.get_asn_signed,
                                      timestampmetadata.get_json_signed)

  sign_the_ber_not_the_json('timestamp.json',
                            'timestamp3.ber',
                            'timestamp3.json',
                            timestampmetadata.get_asn_signed,
                            timestampmetadata.get_json_signed)
