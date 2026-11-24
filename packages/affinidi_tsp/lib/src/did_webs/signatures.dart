// Signature verification for KERI key events: Ed25519, ECDSA secp256k1 and
// ECDSA P-256, with the acceptance rules of the JS port this follows
// (vti-didcomm-js `src/did-webs-kel.js`, which uses @noble/curves 2.4):
//
// - Ed25519 is verified strictly (RFC 8032 / noble `zip215: false`): the key
//   and R must be canonical encodings of curve points (y < p, and not x = 0
//   with the sign bit set), S must be below the group order, a small-order
//   key verifies nothing, and the equation is the cofactored one,
//   [8][S]B = [8]R + [8][k]A.
// - ECDSA is over the SHA-256 of the message, with r and s in [1, n), and a
//   secp256k1 signature must be low-S; a P-256 one need not be.
//
// The common case — a valid Ed25519 signature — is checked with TweetNaCl
// (pinenacl), which is fast on every platform. A signature TweetNaCl refuses
// is re-checked here with the cofactored equation, which accepts the same
// signatures plus those whose disagreement is a small-order component.

// ignore_for_file: public_member_api_docs

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:pinenacl/ed25519.dart' as nacl;
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';

BigInt _le(List<int> bytes) {
  var n = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8) | BigInt.from(bytes[i]);
  }
  return n;
}

BigInt _be(List<int> bytes) {
  var n = BigInt.zero;
  for (final b in bytes) {
    n = (n << 8) | BigInt.from(b);
  }
  return n;
}

// ─── Ed25519 ────────────────────────────────────────────────────────────

final BigInt _p = (BigInt.one << 255) - BigInt.from(19);
// noble's `MASK`: 2^256, so with `zip215` every y the 255 bits hold passes.
final BigInt _mask = BigInt.one << 256;
final BigInt _l =
    (BigInt.one << 252) +
    BigInt.parse('27742317777372353535851937790883648493');
final BigInt _d =
    (-BigInt.from(121665) * BigInt.from(121666).modInverse(_p)) % _p;
final BigInt _d2 = (_d * BigInt.two) % _p;
final BigInt _sqrtM1 = BigInt.two.modPow((_p - BigInt.one) >> 2, _p);

/// A point in extended coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z.
class _Ext {
  const _Ext(this.x, this.y, this.z, this.t);
  final BigInt x;
  final BigInt y;
  final BigInt z;
  final BigInt t;

  static final _Ext zero = _Ext(
    BigInt.zero,
    BigInt.one,
    BigInt.one,
    BigInt.zero,
  );

  bool get isZero => x % _p == BigInt.zero && (y - z) % _p == BigInt.zero;

  // add-2008-hwcd-3, complete for a = -1.
  _Ext operator +(_Ext o) {
    final a = ((y - x) * (o.y - o.x)) % _p;
    final b = ((y + x) * (o.y + o.x)) % _p;
    final c = (t * _d2 % _p) * o.t % _p;
    final d = (z * BigInt.two * o.z) % _p;
    final e = b - a;
    final f = d - c;
    final g = d + c;
    final h = b + a;
    return _Ext(e * f % _p, g * h % _p, f * g % _p, e * h % _p);
  }

  _Ext neg() => _Ext((_p - x) % _p, y, z, (_p - t) % _p);

  _Ext times(BigInt k) {
    var r = zero;
    for (var i = k.bitLength - 1; i >= 0; i--) {
      r = r + r;
      if ((k >> i) & BigInt.one == BigInt.one) r = r + this;
    }
    return r;
  }

  _Ext clearCofactor() => times(BigInt.from(8));
}

final _Ext _base = () {
  final y = (BigInt.from(4) * BigInt.from(5).modInverse(_p)) % _p;
  final x = _recoverX(y, false)!;
  return _Ext(x, y, BigInt.one, x * y % _p);
}();

/// The x with x² = (y² - 1)/(d y² + 1), even unless [odd]; null if none.
BigInt? _recoverX(BigInt y, bool odd) {
  final y2 = y * y % _p;
  final u = (y2 - BigInt.one) % _p;
  final v = (_d * y2 + BigInt.one) % _p;
  // x = u v³ (u v⁷)^((p-5)/8)
  final v3 = v * v % _p * v % _p;
  final v7 = v3 * v3 % _p * v % _p;
  var x =
      u * v3 % _p * (u * v7 % _p).modPow((_p - BigInt.from(5)) >> 3, _p) % _p;
  final vx2 = v * x % _p * x % _p;
  if (vx2 == u) {
    // x is a root
  } else if (vx2 == (_p - u) % _p) {
    x = x * _sqrtM1 % _p;
  } else {
    return null;
  }
  if (x.isOdd) x = (_p - x) % _p;
  if (odd) x = (_p - x) % _p;
  return x;
}

/// noble `Point.fromBytes(bytes, zip215)`: null where it throws.
_Ext? _decodePoint(Uint8List bytes, {required bool zip215}) {
  if (bytes.length != 32) return null;
  final normed = Uint8List.fromList(bytes);
  final last = bytes[31];
  normed[31] = last & 0x7f;
  final y = _le(normed);
  if (y >= (zip215 ? _mask : _p)) return null;
  final yr = y % _p;
  var x = _recoverX(yr, false);
  if (x == null) return null;
  final signBit = (last & 0x80) != 0;
  if (!zip215 && x == BigInt.zero && signBit) return null;
  if (signBit != x.isOdd) x = (_p - x) % _p;
  return _Ext(x, yr, BigInt.one, x * yr % _p);
}

/// Whether [raw] decodes as an Ed25519 key the way ed25519-dalek and noble
/// (`zip215: true`) read one.
bool ed25519KeyDecodes(Uint8List raw) =>
    _decodePoint(raw, zip215: true) != null;

/// Strict Ed25519 verification (noble `ed25519.verify`, `zip215: false`).
bool ed25519Verify(Uint8List publicKey, Uint8List message, Uint8List sig) {
  if (publicKey.length != 32 || sig.length != 64) return false;
  final a = _decodePoint(publicKey, zip215: false);
  final rBytes = Uint8List.sublistView(sig, 0, 32);
  final r = _decodePoint(rBytes, zip215: false);
  final s = _le(Uint8List.sublistView(sig, 32));
  if (a == null || r == null || s >= _l) return false;
  if (a.clearCofactor().isZero) return false;
  // TweetNaCl checks [S]B - [k]A against R's encoding: when that holds the
  // cofactored equation holds too.
  try {
    if (nacl.VerifyKey(publicKey).verify(
      signature: nacl.Signature(Uint8List.fromList(sig)),
      message: message,
    )) {
      return true;
    }
  } on Object {
    // refused: fall through to the cofactored equation
  }
  final h = crypto.sha512.convert([...rBytes, ...publicKey, ...message]);
  final k = _le(h.bytes) % _l;
  final diff = r + a.times(k) + _base.times(s).neg();
  return diff.clearCofactor().isZero;
}

/// The X25519 key an Ed25519 key converts to (ed25519-dalek
/// `to_montgomery`: u = (1 + y) / (1 - y)), read as noble reads it
/// (`Point.fromBytes(raw, true)`); null when [raw] is not a curve point or is
/// of small order.
Uint8List? ed25519ToX25519(Uint8List raw) {
  final point = _decodePoint(raw, zip215: true);
  if (point == null || point.clearCofactor().isZero) return null;
  final y = point.y;
  final u =
      (BigInt.one + y) %
      _p *
      ((_p + BigInt.one - y) % _p).modPow(_p - BigInt.two, _p) %
      _p;
  final out = Uint8List(32);
  var v = u;
  for (var k = 0; k < 32; k++) {
    out[k] = (v & BigInt.from(255)).toInt();
    v >>= 8;
  }
  return out;
}

// ─── ECDSA ──────────────────────────────────────────────────────────────

final ECDomainParameters _secp256k1 = ECCurve_secp256k1();
final ECDomainParameters _p256 = ECCurve_secp256r1();

final BigInt _secp256k1P = BigInt.parse(
  'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
  radix: 16,
);
final BigInt _p256P = BigInt.parse(
  'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
  radix: 16,
);

/// The curve of an ECDSA verfer code.
enum EcdsaCurve { secp256k1, p256 }

ECDomainParameters _params(EcdsaCurve c) =>
    c == EcdsaCurve.secp256k1 ? _secp256k1 : _p256;

/// noble `Point.fromBytes` for a compressed SEC1 point: null where it throws.
ECPoint? ecdsaPoint(EcdsaCurve c, Uint8List raw) {
  final params = _params(c);
  final p = c == EcdsaCurve.secp256k1 ? _secp256k1P : _p256P;
  if (raw.length == 33 && (raw[0] == 2 || raw[0] == 3)) {
    final x = _be(Uint8List.sublistView(raw, 1));
    if (x >= p) return null;
    final a = params.curve.a!.toBigInteger()!;
    final b = params.curve.b!.toBigInteger()!;
    final rhs = (x * x % p * x + a * x + b) % p;
    // p ≡ 3 (mod 4) for both curves.
    var y = rhs.modPow((p + BigInt.one) >> 2, p);
    if (y * y % p != rhs) return null;
    if (y.isOdd != (raw[0] == 3)) y = (p - y) % p;
    return params.curve.createPoint(x, y);
  }
  if (raw.length == 65 && raw[0] == 4) {
    final x = _be(Uint8List.sublistView(raw, 1, 33));
    final y = _be(Uint8List.sublistView(raw, 33));
    if (x >= p || y >= p) return null;
    final a = params.curve.a!.toBigInteger()!;
    final b = params.curve.b!.toBigInteger()!;
    if ((y * y - (x * x * x + a * x + b)) % p != BigInt.zero) return null;
    return params.curve.createPoint(x, y);
  }
  return null;
}

/// A refusal to decode a point, worded as @noble/curves 2.4 words it.
class PointError implements Exception {
  PointError(this.message);
  final String message;

  @override
  String toString() => 'PointError: $message';
}

/// noble `Point.fromBytes(raw).toBytes(false)`: the uncompressed SEC1
/// encoding of [raw], or a [PointError] with noble's message.
Uint8List ecdsaUncompressed(EcdsaCurve c, Uint8List raw) {
  final params = _params(c);
  final p = c == EcdsaCurve.secp256k1 ? _secp256k1P : _p256P;
  final a = params.curve.a!.toBigInteger()!;
  final b = params.curve.b!.toBigInteger()!;
  BigInt field(List<int> bytes) {
    final v = _be(bytes);
    if (v >= p) {
      throw PointError('invalid field element: outside of range 0..ORDER');
    }
    return v;
  }

  BigInt x;
  BigInt y;
  if (raw.length == 33 && (raw[0] == 2 || raw[0] == 3)) {
    x = field(Uint8List.sublistView(raw, 1));
    final rhs = (x * x % p * x + a * x + b) % p;
    y = rhs.modPow((p + BigInt.one) >> 2, p);
    if (y * y % p != rhs) {
      throw PointError(
        'bad point: is not on curve, sqrt error: Cannot find square root',
      );
    }
    if (y.isOdd != (raw[0] & 1 == 1)) y = (p - y) % p;
  } else if (raw.length == 65 && raw[0] == 4) {
    x = field(Uint8List.sublistView(raw, 1, 33));
    y = field(Uint8List.sublistView(raw, 33));
    if ((y * y - (x * x * x + a * x + b)) % p != BigInt.zero) {
      throw PointError('bad point: is not on curve');
    }
  } else {
    throw PointError(
      'bad point: got length ${raw.length}, expected compressed=33 or '
      'uncompressed=65',
    );
  }
  final out = Uint8List(65)..[0] = 4;
  for (var i = 0; i < 32; i++) {
    out[32 - i] = ((x >> (8 * i)) & BigInt.from(255)).toInt();
    out[64 - i] = ((y >> (8 * i)) & BigInt.from(255)).toInt();
  }
  return out;
}

/// The order of [c]'s group.
BigInt ecdsaOrder(EcdsaCurve c) => _params(c).n;

/// ECDSA over SHA-256 (noble `verify` with `prehash: true`); [r] and [s] are
/// already known to be in [1, n).
bool ecdsaVerify(
  EcdsaCurve c,
  ECPoint q,
  Uint8List message,
  BigInt r,
  BigInt s, {
  required bool lowS,
}) {
  final params = _params(c);
  final n = params.n;
  if (lowS && s > (n >> 1)) return false;
  final e = _be(crypto.sha256.convert(message).bytes) % n;
  final w = s.modInverse(n);
  final u1 = e * w % n;
  final u2 = r * w % n;
  final point = (params.G * u1)! + (q * u2)!;
  if (point == null || point.isInfinity) return false;
  return point.x!.toBigInteger()! % n == r;
}
