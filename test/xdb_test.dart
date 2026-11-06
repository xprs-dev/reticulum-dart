// XDb is zxdb's ZxDb (package:zx, tested there: test/zxdb_handle_test.dart).
// What this package adds: the injectable openers and the phone-sized store
// options every store runs with.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

void main() {
  test(':memory: through dbOpener is a fresh database each time', () {
    final a = dbOpener(':memory:');
    a.execute('CREATE TABLE t (n INTEGER)');
    final b = dbOpener(':memory:');
    expect(() => b.select('SELECT * FROM t'), throwsA(isA<XDbException>()));
    a.dispose();
    b.dispose();
    expect(File(':memory:').existsSync(), isFalse);
  });

  test('a store file opens with LZ4 pages and small caches', () {
    final o = xdbStoreOptions();
    expect(o.compression, 'fast');
    expect(o.pageCacheBytes, lessThanOrEqualTo(4 << 20));
    expect(o.durable, isFalse);
    expect(xdbStoreOptions(durable: true).durable, isTrue);
  });

  test('a file round-trips through the default opener', () {
    final dir = Directory.systemTemp.createTempSync('xdb_test');
    addTearDown(() => dir.deleteSync(recursive: true));
    final db = dbOpener('${dir.path}/a.zx');
    db.transaction(() {
      db.execute('CREATE TABLE t (k TEXT PRIMARY KEY, n INTEGER)');
      db.execute("INSERT INTO t VALUES ('a', 1)");
    });
    db.dispose();
    final again = dbOpener('${dir.path}/a.zx');
    expect(again.select('SELECT n FROM t').single['n'], 1);
    again.dispose();
  });
}
