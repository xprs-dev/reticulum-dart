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
  _xprsRns = o;
}
