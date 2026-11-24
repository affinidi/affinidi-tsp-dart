// BLAKE3 hashing in pure Dart.
//
// A direct port of the BLAKE3 reference implementation
// (https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs,
// CC0-1.0 / Apache-2.0), default hash mode only, with extendable output. KERI
// and CESR use it for Blake3-256 (`E`) and Blake3-512 (`0D`) digests; keyed
// hashing and key derivation are not needed and not implemented.
//
// Written for both the Dart VM (64-bit ints) and the web (JS numbers): every
// word lives in a Uint32List or is masked to 32 bits, sums never exceed 2^35,
// and the 64-bit block counter is split with division instead of a shift.
// Checked against the official BLAKE3 test vectors in test/blake3_test.dart.

import 'dart:typed_data';

const int _outLen = 32;

/// The longest output [Blake3.finalize] produces. KERI digests need 32 or 64
/// bytes; the cap stops a caller that forwards an untrusted length from
/// allocating and computing an arbitrarily large output.
const int blake3MaxOutputLength = 1024;
const int _blockLen = 64;
const int _chunkLen = 1024;

const int _chunkStart = 1 << 0;
const int _chunkEnd = 1 << 1;
const int _parent = 1 << 2;
const int _root = 1 << 3;

const List<int> _iv = [
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, //
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const List<int> _msgPermutation = [
  2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8, //
];

const int _mask32 = 0xFFFFFFFF;
const int _two32 = 0x100000000;

int _rotr(int x, int n) => ((x >>> n) | (x << (32 - n))) & _mask32;

void _g(Uint32List s, int a, int b, int c, int d, int mx, int my) {
  s[a] = (s[a] + s[b] + mx) & _mask32;
  s[d] = _rotr(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) & _mask32;
  s[b] = _rotr(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b] + my) & _mask32;
  s[d] = _rotr(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) & _mask32;
  s[b] = _rotr(s[b] ^ s[c], 7);
}

void _round(Uint32List s, Uint32List m) {
  // Columns.
  _g(s, 0, 4, 8, 12, m[0], m[1]);
  _g(s, 1, 5, 9, 13, m[2], m[3]);
  _g(s, 2, 6, 10, 14, m[4], m[5]);
  _g(s, 3, 7, 11, 15, m[6], m[7]);
  // Diagonals.
  _g(s, 0, 5, 10, 15, m[8], m[9]);
  _g(s, 1, 6, 11, 12, m[10], m[11]);
  _g(s, 2, 7, 8, 13, m[12], m[13]);
  _g(s, 3, 4, 9, 14, m[14], m[15]);
}

Uint32List _permute(Uint32List m) {
  final out = Uint32List(16);
  for (var i = 0; i < 16; i++) {
    out[i] = m[_msgPermutation[i]];
  }
  return out;
}

/// The BLAKE3 compression function: all 16 output words.
Uint32List _compress(
  Uint32List chainingValue,
  Uint32List blockWords,
  int counter,
  int blockLen,
  int flags,
) {
  final s = Uint32List(16);
  for (var i = 0; i < 8; i++) {
    s[i] = chainingValue[i];
  }
  s[8] = _iv[0];
  s[9] = _iv[1];
  s[10] = _iv[2];
  s[11] = _iv[3];
  s[12] = counter % _two32;
  s[13] = counter ~/ _two32;
  s[14] = blockLen;
  s[15] = flags;
  var m = Uint32List.fromList(blockWords);
  for (var r = 0; r < 7; r++) {
    _round(s, m);
    if (r < 6) m = _permute(m);
  }
  for (var i = 0; i < 8; i++) {
    s[i] ^= s[i + 8];
    s[i + 8] ^= chainingValue[i];
  }
  return s;
}

Uint32List _first8(Uint32List words) =>
    Uint32List.fromList(words.sublist(0, 8));

Uint32List _wordsFromLeBytes(Uint8List bytes) {
  final words = Uint32List(bytes.length ~/ 4);
  for (var i = 0; i < words.length; i++) {
    final o = i * 4;
    words[i] =
        bytes[o] |
        (bytes[o + 1] << 8) |
        (bytes[o + 2] << 16) |
        ((bytes[o + 3] << 24) & _mask32);
  }
  return words;
}

class _Output {
  _Output(
    this.inputChainingValue,
    this.blockWords,
    this.counter,
    this.blockLen,
    this.flags,
  );

  final Uint32List inputChainingValue;
  final Uint32List blockWords;
  final int counter;
  final int blockLen;
  final int flags;

  Uint32List chainingValue() => _first8(
    _compress(inputChainingValue, blockWords, counter, blockLen, flags),
  );

  Uint8List rootOutputBytes(int length) {
    final out = Uint8List(length);
    var outputBlockCounter = 0;
    var offset = 0;
    while (offset < length) {
      final words = _compress(
        inputChainingValue,
        blockWords,
        outputBlockCounter,
        blockLen,
        flags | _root,
      );
      for (var w = 0; w < 16 && offset < length; w++) {
        final word = words[w];
        for (var b = 0; b < 4 && offset < length; b++) {
          out[offset++] = (word >>> (8 * b)) & 0xFF;
        }
      }
      outputBlockCounter++;
    }
    return out;
  }
}

class _ChunkState {
  _ChunkState(Uint32List keyWords, this.chunkCounter, this.flags)
    : chainingValue = Uint32List.fromList(keyWords);

  Uint32List chainingValue;
  final int chunkCounter;
  final int flags;
  final Uint8List block = Uint8List(_blockLen);
  int blockLen = 0;
  int blocksCompressed = 0;

  int get length => _blockLen * blocksCompressed + blockLen;

  int _startFlag() => blocksCompressed == 0 ? _chunkStart : 0;

  void update(Uint8List input, int start, int end) {
    var i = start;
    while (i < end) {
      if (blockLen == _blockLen) {
        chainingValue = _first8(
          _compress(
            chainingValue,
            _wordsFromLeBytes(block),
            chunkCounter,
            _blockLen,
            flags | _startFlag(),
          ),
        );
        blocksCompressed++;
        block.fillRange(0, _blockLen, 0);
        blockLen = 0;
      }
      final want = _blockLen - blockLen;
      final take = (end - i) < want ? (end - i) : want;
      block.setRange(blockLen, blockLen + take, input, i);
      blockLen += take;
      i += take;
    }
  }

  _Output output() => _Output(
    chainingValue,
    _wordsFromLeBytes(block),
    chunkCounter,
    blockLen,
    flags | _startFlag() | _chunkEnd,
  );
}

_Output _parentOutput(
  Uint32List left,
  Uint32List right,
  Uint32List keyWords,
  int flags,
) {
  final blockWords = Uint32List(16)
    ..setRange(0, 8, left)
    ..setRange(8, 16, right);
  return _Output(keyWords, blockWords, 0, _blockLen, _parent | flags);
}

/// An incremental BLAKE3 hasher (default hash mode).
class Blake3 {
  /// A new hasher.
  Blake3() : _key = Uint32List.fromList(_iv) {
    _chunk = _ChunkState(_key, 0, 0);
  }

  final Uint32List _key;
  late _ChunkState _chunk;
  final List<Uint32List> _cvStack = [];

  /// Adds [input] to the hash.
  void update(List<int> input) {
    final bytes = input is Uint8List ? input : Uint8List.fromList(input);
    var i = 0;
    while (i < bytes.length) {
      if (_chunk.length == _chunkLen) {
        final chunkCv = _chunk.output().chainingValue();
        final totalChunks = _chunk.chunkCounter + 1;
        _addChunkChainingValue(chunkCv, totalChunks);
        _chunk = _ChunkState(_key, totalChunks, 0);
      }
      final want = _chunkLen - _chunk.length;
      final take = (bytes.length - i) < want ? (bytes.length - i) : want;
      _chunk.update(bytes, i, i + take);
      i += take;
    }
  }

  void _addChunkChainingValue(Uint32List newCv, int totalChunks) {
    var cv = newCv;
    var total = totalChunks;
    while (total.isEven) {
      cv = _parentOutput(_cvStack.removeLast(), cv, _key, 0).chainingValue();
      total ~/= 2;
    }
    _cvStack.add(cv);
  }

  /// The hash of everything added so far, [length] bytes long (default 32).
  /// Lengths above 32 use BLAKE3's extendable output, up to
  /// [blake3MaxOutputLength]. Does not reset the hasher.
  Uint8List finalize([int length = _outLen]) {
    if (length < 0 || length > blake3MaxOutputLength) {
      throw RangeError.range(length, 0, blake3MaxOutputLength, 'length');
    }
    var output = _chunk.output();
    for (var i = _cvStack.length - 1; i >= 0; i--) {
      output = _parentOutput(_cvStack[i], output.chainingValue(), _key, 0);
    }
    return output.rootOutputBytes(length);
  }
}

/// BLAKE3 of [data], [length] bytes long (default 32).
Uint8List blake3(List<int> data, [int length = _outLen]) =>
    (Blake3()..update(data)).finalize(length);
