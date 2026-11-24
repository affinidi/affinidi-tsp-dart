// The did:webs conformance vectors recorded from `affinidi-did-webs` (see
// test/fixtures/did_webs/vectors/rust-vectors/README.md), read as
// vti-didcomm-js `test/support-did-webs-vectors.js` reads them.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

const String didWebsFixtures = 'test/fixtures/did_webs';
const String rustVectors = '$didWebsFixtures/vectors/rust-vectors';

/// A fixture file under `test/fixtures/did_webs/vectors/`.
Uint8List didWebsFixture(String name) =>
    File('$didWebsFixtures/vectors/$name').readAsBytesSync();

final Map<String, Uint8List> _blobs = {};

/// A stored artifact, by name.
Uint8List vectorBlob(String name) =>
    _blobs[name] ??= File('$rustVectors/blobs/$name').readAsBytesSync();

/// Every record, by the Rust test file it came from.
Map<String, List<Map<String, Object?>>> loadVectors() {
  final out = <String, List<Map<String, Object?>>>{};
  final files = Directory(rustVectors).listSync().whereType<File>().toList()
    ..sort((a, b) => a.path.compareTo(b.path));
  for (final f in files) {
    final name = f.uri.pathSegments.last;
    String text;
    if (name.endsWith('.jsonl')) {
      text = f.readAsStringSync();
    } else if (name.endsWith('.jsonl.gz')) {
      text = utf8.decode(gzip.decode(f.readAsBytesSync()));
    } else {
      continue;
    }
    out[name.replaceFirst(RegExp(r'\.jsonl(\.gz)?$'), '')] = [
      for (final line in const LineSplitter().convert(text))
        if (line.isNotEmpty) jsonDecode(line) as Map<String, Object?>,
    ];
  }
  return out;
}

/// A recorded mutation, applied as the Rust vector generator applied it.
Uint8List mutate(Uint8List base, Map<String, Object?>? m) {
  if (m == null) return base;
  switch (m['type']) {
    case 'replace':
      final out = Uint8List.fromList(base);
      out[m['at']! as int] = m['byte']! as int;
      return out;
    case 'splice':
      final start = m['start']! as int;
      final end = m['end']! as int;
      final ins = m['insert'] as List<Object?>?;
      final insert = ins == null
          ? Uint8List(0)
          : base.sublist(ins[0]! as int, ins[1]! as int);
      return Uint8List.fromList([
        ...base.sublist(0, start),
        ...insert,
        ...base.sublist(end),
      ]);
    case 'swap':
      final a = (m['a']! as List).cast<int>();
      final b = (m['b']! as List).cast<int>();
      return Uint8List.fromList([
        ...base.sublist(0, a[0]),
        ...base.sublist(b[0], b[1]),
        ...base.sublist(a[0], a[1]),
        ...base.sublist(b[1]),
      ]);
  }
  throw StateError('unknown mutation ${m['type']}');
}
