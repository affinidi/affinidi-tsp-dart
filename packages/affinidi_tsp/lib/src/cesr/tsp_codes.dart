import 'dart:convert';
import 'dart:typed_data';

import 'cesr.dart';

/// CESR code points TSP Rev 3 uses (master table for genus `-_AAACAA`).
abstract final class TspCodes {
  /// `-E`: the envelope group; its count covers all signable content.
  static final int envelope = Cesr.codeInt('E');

  /// `-Z`: the payload group.
  static final int payload = Cesr.codeInt('Z');

  /// `-A`: the generic CESR stream carrying an XSCS/XCTL payload.
  static final int genericStream = Cesr.codeInt('A');

  /// `-J`: a VID list (hop list, reply path, referral field).
  static final int vidList = Cesr.codeInt('J');

  /// `-C`: the attachment group carrying signatures.
  static final int attachmentGroup = Cesr.codeInt('C');

  /// `-K`: the indexed-signature group.
  static final int indexedSignatureGroup = Cesr.codeInt('K');

  /// `B`: variable-size bytes — VIDs, padding and the XSCS body primitive.
  static final int bytes = Cesr.codeInt('B');

  /// `F`: variable-size HPKE-Base ciphertext (`4F##`…`9AAF####`).
  static final int hpkeBaseCiphertext = Cesr.codeInt('F');

  /// `C`: variable-size libsodium sealed-box ciphertext.
  static final int sealedBoxCiphertext = Cesr.codeInt('C');

  /// `I`: SHA2-256 digest.
  static final int sha256Digest = Cesr.codeInt('I');

  /// `F`: Blake2b-256 digest.
  static final int blake2b256Digest = Cesr.codeInt('F');

  /// `0A`: the 128-bit nonce.
  static final int nonce = Cesr.codeInt('A');

  /// `B#`: indexed Ed25519 signature (the `B` part).
  static final int ed25519IndexedSignature = Cesr.codeInt('B');

  /// `1AAQ`: ML-DSA-65 signature (provisional code point).
  static final int mlDsa65Signature = Cesr.codeInt('AAQ');

  /// `YTSP`: the protocol genus marker preceding the version count code.
  static final Uint8List ytsp = Cesr.code3('YTSP');

  /// `XSCS`: upper-layer (application) payload.
  static final Uint8List xscs = Cesr.code3('XSCS');

  /// `XCTL`: generic upper-layer control payload.
  static final Uint8List xctl = Cesr.code3('XCTL');

  /// `XPAD`: padding-only message.
  static final Uint8List xpad = Cesr.code3('XPAD');

  /// `XHOP`: nested or routed message.
  static final Uint8List xhop = Cesr.code3('XHOP');

  /// `XRFI`: relationship forming invite.
  static final Uint8List xrfi = Cesr.code3('XRFI');

  /// `XRFA`: relationship forming accept.
  static final Uint8List xrfa = Cesr.code3('XRFA');

  /// `XRFD`: relationship forming decline / cancel.
  static final Uint8List xrfd = Cesr.code3('XRFD');

  /// The HPKE `info` string: the protocol code `YTSP-` as five ASCII bytes.
  static final Uint8List hpkeInfo = Uint8List.fromList(ascii.encode('YTSP-'));

  /// The byte the SAID derivation fills the digest slot with.
  static const int saidDummy = 0x23;

  /// Length of an encoded 256-bit digest (`I`/`F` code byte plus 32 bytes).
  static const int encodedDigestLength = 33;
}
