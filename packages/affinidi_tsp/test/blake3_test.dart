import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:affinidi_tsp/src/crypto/blake3.dart';
import 'package:test/test.dart';

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List _pattern(int length) =>
    Uint8List.fromList(List<int>.generate(length, (i) => i % 251));

void main() {
  group('BLAKE3 official test vectors (hash mode)', () {
    final vectors =
        jsonDecode(
              File('test/fixtures/blake3/test_vectors.json').readAsStringSync(),
            )
            as Map<String, dynamic>;
    final cases = (vectors['cases'] as List).cast<Map<String, dynamic>>();

    test('the fixture has every case', () => expect(cases, hasLength(35)));

    for (final c in cases) {
      final len = c['input_len'] as int;
      final expected = c['hash'] as String;
      test('input_len $len: 32-byte hash and full extended output', () {
        final input = _pattern(len);
        expect(_hex(blake3(input)), expected.substring(0, 64));
        expect(_hex(blake3(input, expected.length ~/ 2)), expected);
      });

      test('input_len $len: incremental updates match one-shot', () {
        final input = _pattern(len);
        final h = Blake3();
        // Uneven pieces that straddle block (64) and chunk (1024) boundaries.
        var i = 0;
        var step = 1;
        while (i < input.length) {
          final end = (i + step) > input.length ? input.length : i + step;
          h.update(input.sublist(i, end));
          i = end;
          step = (step * 3 + 7) % 1500 + 1;
        }
        expect(_hex(h.finalize()), expected.substring(0, 64));
      });
    }
  });

  // Digests from @noble/hashes (the library vti-didcomm-js uses for KERI
  // digests), so the Dart and JS did:webs resolvers compute identical SAIDs.
  group('BLAKE3 agrees with @noble/hashes', () {
    const noble = {
      '': [
        'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262',
        'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262'
            'e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a',
      ],
      'abc': [
        '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85',
        '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85'
            '1fb250ae7393f5d02813b65d521a0d492d9ba09cf7ce7f4cffd900f23374bf0b',
      ],
      'KERI': [
        '5ebfed0be3ebd0025593cc933e142623c0f56c4e17709b95eef796c30680ea7d',
        '5ebfed0be3ebd0025593cc933e142623c0f56c4e17709b95eef796c30680ea7d'
            '7ef9f6a83dd6d0bb5cfad73e54bd131c5f24219f0fbdbf8c8bc0f160a12cbf20',
      ],
    };
    noble.forEach((input, digests) {
      test('"$input"', () {
        final bytes = utf8.encode(input);
        expect(_hex(blake3(bytes)), digests[0]);
        expect(_hex(blake3(bytes, 64)), digests[1]);
      });
    });

    test('5000 bytes of (i*7) % 256', () {
      final data = Uint8List.fromList(
        List<int>.generate(5000, (i) => (i * 7) % 256),
      );
      expect(
        _hex(blake3(data)),
        '53ab6e7d7b5d3d2412bc5a3bc47a4d7a49570a2ec9aff1421c1b865d2cce682a',
      );
    });
  });

  test('finalize does not reset and rejects a negative length', () {
    final h = Blake3()..update(utf8.encode('abc'));
    expect(_hex(h.finalize()), _hex(h.finalize()));
    expect(() => h.finalize(-1), throwsArgumentError);
  });
}
