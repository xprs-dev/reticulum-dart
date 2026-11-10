// Reticulum in the browser (portal/docs/plan-browser-reticulum.md): this file
// compiles to rns.js (tool/build_rns_js.sh) and puts one object on the page,
// `XprsRns`, with Promise-returning calls:
//
//   connect(url)            the gateway (wss://.../rns); its hello, as JSON
//   resolve(call)           what the gateway knows of a station, as JSON
//   open(rnsPublicKeyHex)   a link to that station's xprs/wapp destination; true/false
//   prove(nonce)            the station's signed {session, identity, link}, as JSON
//   api(method, path, queryJson, body)  one API call over the link:
//                           {status, type, body: Uint8Array, headers: JSON}
//   close()
//
// Only platform-neutral parts of reticulum-dart are imported (no dart:io).
import 'dart:async';
import 'dart:convert';
import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:typed_data';

import 'package:reticulum/src/services/reticulum/rns_gateway_client.dart';
import 'package:reticulum/src/services/reticulum/rns_identity.dart';
import 'package:reticulum/src/services/reticulum/rns_request.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';
import 'package:reticulum/src/util/xprs_crypto.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

WebSocketChannel? _ws;
RnsGatewayClient? _gw;
RnsRequestClient? _link;
final _control = StreamController<Map<String, dynamic>>.broadcast();
final List<String> _logs = [];
void _log(String m) {
  _logs.add(m);
  if (_logs.length > 200) _logs.removeAt(0);
}

Future<Map<String, dynamic>> _ask(Map<String, Object?> j) async {
  final f = _control.stream.first;
  _ws!.sink.add(jsonEncode(j));
  return f.timeout(const Duration(seconds: 15));
}

Future<String> _connect(String url) async {
  await _close();
  final ws = WebSocketChannel.connect(Uri.parse(url));
  await ws.ready;
  _ws = ws;
  final gw = _gw = RnsGatewayClient((f) => ws.sink.add(f), log: _log);
  void frame(Uint8List b) {
    gw.onFrame(b).catchError((Object e, StackTrace st) {
      _log('frame failed: $e\n$st');
    });
  }
  ws.stream.listen((m) {
    if (m is List<int>) {
      frame(Uint8List.fromList(m));
    } else if (m is ByteBuffer) {
      frame(m.asUint8List());
    } else if (m is String) {
      try {
        _control.add(jsonDecode(m) as Map<String, dynamic>);
      } catch (_) {}
    }
  }, onDone: () {
    _link = null;
  }, onError: (_) {});
  return jsonEncode(await _ask({'op': 'hello'}));
}

Future<String> _resolve(String call) async =>
    jsonEncode(await _ask({'op': 'resolve', 'call': call}));

Future<bool> _open(String pubHex) async {
  final gw = _gw;
  if (gw == null || pubHex.length != 128) return false;
  final pub = Uint8List.fromList(List.generate(
      64, (i) => int.parse(pubHex.substring(2 * i, 2 * i + 2), radix: 16)));
  final old = _link;
  if (old != null) gw.drop(old);
  final c = _link = gw.client(RnsIdentity.fromPublicKey(pub));
  return c.open();
}

Future<String> _prove(String nonce) async {
  final c = _link;
  if (c == null) return 'null';
  final r = await c.request('/xprs/prove', nonce, timeout: const Duration(seconds: 30));
  final hex = c.linkId?.map((x) => x.toRadixString(16).padLeft(2, '0')).join() ?? '';
  return jsonEncode({if (r is Map) ...r.map((k, v) => MapEntry('$k', v)), 'link': hex});
}

Future<JSObject> _api(String method, String path, String queryJson, JSAny? body) async {
  final c = _link;
  final out = JSObject();
  void set(String k, JSAny? v) => out.setProperty(k.toJS, v);
  if (c == null) {
    set('status', 0.toJS);
    return out;
  }
  Object? b;
  if (body != null && body.isA<JSString>()) b = (body as JSString).toDart;
  if (body != null && body.isA<JSUint8Array>()) b = (body as JSUint8Array).toDart;
  var q = <String, String>{};
  try {
    q = (jsonDecode(queryJson.isEmpty ? '{}' : queryJson) as Map)
        .map((k, v) => MapEntry('$k', '$v'));
  } catch (_) {}
  final r = await c.request('/xprs/api', {'m': method, 'p': path, 'q': q, if (b != null) 'b': b},
      timeout: const Duration(minutes: 5));
  if (r is! Map) {
    set('status', 0.toJS);
    return out;
  }
  final rb = r['b'];
  set('status', ((r['s'] as num?) ?? 0).toInt().toJS);
  set('type', '${r['t'] ?? ''}'.toJS);
  set('body', (rb is List<int> ? Uint8List.fromList(rb) : Uint8List(0)).toJS);
  set('headers', jsonEncode(r['h'] ?? {}).toJS);
  return out;
}

/// A field of a wire (`m:` is the rest of the line).
String? _field(String w, String k) {
  if (k == 'm') {
    final i = w.indexOf(' m:');
    return i < 0 ? null : w.substring(i + 3);
  }
  final head = w.contains(' m:') ? w.substring(0, w.indexOf(' m:')) : w;
  for (final t in head.split(' ')) {
    if (t.startsWith('$k:')) return t.substring(k.length + 1);
  }
  return null;
}

/// What a signature covers: the wire without `sig:` and `via:` (XPRS.md 5, 6.1).
String _signedText(String w) {
  final mi = w.indexOf(' m:');
  final head = mi < 0 ? w : w.substring(0, mi);
  final tail = mi < 0 ? '' : w.substring(mi);
  final kept = head.split(' ').where((t) => !t.startsWith('sig:') && !t.startsWith('via:'));
  return kept.join(' ') + tail;
}

bool _sigOk(String w, Uint8List pub) {
  final s = _field(w, 'sig');
  if (s == null) return false;
  final sig = XprsCrypto.b85decode(s);
  if (sig == null || sig.length != 48) return false;
  final digest = NostrCrypto.sha256Bytes(Uint8List.fromList(utf8.encode(_signedText(w))));
  return XprsCrypto.verify(digest, sig, pub);
}

/// Check a station's /xprs/prove answer for [call], [nonce] and this link
/// (spec/API-HTTP.md): its callsign derives from `k:`, both wires are signed
/// with that key, and the session names this link and the nonce.
String _verify(String proofJson, String call, String nonce) {
  String no(String why) => jsonEncode({'ok': false, 'why': why});
  Map<String, dynamic> p;
  try {
    p = jsonDecode(proofJson) as Map<String, dynamic>;
  } catch (_) {
    return no('no proof');
  }
  final c = call.toUpperCase().split('-').first;
  final id = '${p['identity'] ?? ''}', sess = '${p['session'] ?? ''}', link = '${p['link'] ?? ''}';
  if (id.isEmpty || sess.isEmpty || link.isEmpty) return no('the station sent no proof');
  if ((_field(id, 'f') ?? '').toUpperCase().split('-').first != c) return no('the identity is not $c');
  final npub = _field(id, 'k');
  if (npub == null) return no('the identity carries no key');
  String keyHex;
  try {
    keyHex = NostrCrypto.decodeNpub(npub);
  } catch (_) {
    return no('the key is not an npub');
  }
  if (c.length < 4 || NostrCrypto.deriveCallsign(keyHex, length: c.length - 2) != c.substring(2)) {
    return no('$c is not derived from that key');
  }
  final pub = Uint8List.fromList(List.generate(32, (i) => int.parse(keyHex.substring(2 * i, 2 * i + 2), radix: 16)));
  if (!_sigOk(id, pub)) return no('the identity is not signed by its key');
  if ((_field(sess, 'f') ?? '').toUpperCase().split('-').first != c) return no('the session is not from $c');
  if (_field(sess, 'm') != '$link.$nonce') return no('the session does not name this link');
  if (!_sigOk(sess, pub)) return no('the session is not signed by $c');
  return jsonEncode({'ok': true, 'key': keyHex, 'nick': _field(id, 'nick')});
}

Future<void> _close() async {
  final g = _gw, l = _link;
  if (g != null && l != null) g.drop(l);
  _link = null;
  _gw = null;
  await _ws?.sink.close();
  _ws = null;
}

@JS('XprsRns')
external set _xprsRns(JSObject v);

void main() {
  final o = JSObject();
  o.setProperty('connect'.toJS, ((JSString u) => _connect(u.toDart).then((s) => s.toJS).toJS).toJS);
  o.setProperty('resolve'.toJS, ((JSString c) => _resolve(c.toDart).then((s) => s.toJS).toJS).toJS);
  o.setProperty('open'.toJS, ((JSString k) => _open(k.toDart).then((b) => b.toJS).toJS).toJS);
  o.setProperty('prove'.toJS, ((JSString n) => _prove(n.toDart).then((s) => s.toJS).toJS).toJS);
  o.setProperty('api'.toJS,
      ((JSString m, JSString p, JSString q, JSAny? b) => _api(m.toDart, p.toDart, q.toDart, b).toJS).toJS);
  o.setProperty('close'.toJS, (() => _close().toJS).toJS);
  o.setProperty('logs'.toJS, (() => _logs.join('\n').toJS).toJS);
  o.setProperty('verify'.toJS,
      ((JSString p, JSString c, JSString n) => _verify(p.toDart, c.toDart, n.toDart).toJS).toJS);
  _xprsRns = o;
}
