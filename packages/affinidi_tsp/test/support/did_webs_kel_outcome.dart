// What the KEL layer answers for a stream, in the shape
// `test/tool/did_webs_kel_golden.mjs` records the JS reference's answers.
// Free of dart:io so the same code runs compiled to JavaScript.

import 'dart:typed_data';

import 'package:affinidi_tsp/src/did_webs/cesr.dart';
import 'package:affinidi_tsp/src/did_webs/kel.dart';

/// Sequence numbers `asOf` is tried at, at most, per identifier.
const int maxAsOf = 24;

Map<String, Object?> _err(Object e) => switch (e) {
  StreamError(:final message) => {'error': 'Stream', 'message': message},
  KelError(:final message) => {'error': 'Kel', 'message': message},
  KeriError(:final type, :final message) => {
    'error': 'Keri:$type',
    'message': message,
  },
  _ => {'error': 'dart', 'message': '$e'},
};

Object? _attempt(Object? Function() fn) {
  try {
    return fn();
  } on Exception catch (e) {
    return _err(e);
  }
}

/// A key state as the golden file writes it.
Map<String, Object?> stateJson(KeyState s) => {
  'prefix': s.prefix,
  'sn': s.sn,
  'said': s.said,
  'lastEventDigest': s.lastEventDigest,
  'keys': s.keys,
  'nextKeys': s.nextKeys,
  'threshold': thresholdJson(s.threshold),
  'nextThreshold': thresholdJson(s.nextThreshold),
  'backers': s.backers,
  'backerThreshold': s.backerThreshold,
  'config': s.config,
  'delegated': s.delegated,
  'delegator': s.delegator,
  'protocolMajor': s.protocolMajor,
};

Map<String, Object?> _logEvent(LoggedEvent e) => {
  'sn': e.sn,
  'said': e.said,
  'seals': e.seals.length,
  'est': e.establishment?.sn,
};

/// Everything the golden file records for [bytes].
Map<String, Object?> kelOutcome(Uint8List bytes) {
  Kels kels;
  try {
    kels = Kels.parse(bytes);
  } on Exception catch (e) {
    return {'parse': _err(e)};
  }
  final ids = [
    for (final prefix in kels.prefixes.toList())
      () {
        final sns = kels.sequenceNumbers(prefix);
        return <String, Object?>{
          'prefix': prefix,
          'state': _attempt(() => stateJson(kels.keyState(prefix))),
          'deactivated': kels.isDeactivated(prefix),
          'inception': kels.inceptionSaid(prefix),
          'sns': sns,
          'anchored': _attempt(
            () => kels.anchoredDigests(prefix).toList()..sort(_jsCompare),
          ),
          'log': _attempt(() {
            final log = kels.issuerLog(prefix);
            return {
              'events': log.events.map(_logEvent).toList(),
              'superseded': log.superseded.map(_logEvent).toList(),
              'limit': log.limit,
            };
          }),
          'asOf': [
            for (final sn in sns.toSet().take(maxAsOf))
              _attempt(() {
                final at = kels.asOf(prefix, sn);
                return {
                  'sn': sn,
                  'state': _attempt(() => stateJson(at.keyState(prefix))),
                };
              }),
          ],
        };
      }(),
  ];
  final groups = <Object?>[];
  for (var i = 0; i < kels.messages.length; i++) {
    final msg = kels.messages[i];
    for (final g in transIdxSigGroups(msg)) {
      groups.add({
        'message': i,
        'prefix': g.prefix,
        'said': g.said,
        'result': _attempt(
          () => kels.verifySignatureGroup(g.prefix, msg.serder.raw, g).sn,
        ),
      });
    }
  }
  return {
    'parse': {'ok': kels.messages.length},
    'ilks': [for (final m in kels.messages) sadStr(sadGet(m.serder.sad, 't'))],
    'ids': ids,
    'groups': groups,
  };
}

/// JS `Array.prototype.sort` order: by UTF-16 code units.
int _jsCompare(String a, String b) => a.compareTo(b);
