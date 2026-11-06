// XDb, the one database handle (lib/src/util/xdb.dart): the slice of the
// old sqlite3 API the stores use, on zxdb, plus what zxdb needs from it —
// compaction when a file doubles, one database per file per isolate.
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

void main() {
  late Directory dir;
  setUp(() => dir = Directory.systemTemp.createTempSync('xdb_test'));
  tearDown(() => dir.deleteSync(recursive: true));

  test('rows read by name and by position, blobs come back as bytes', () {
    final db = xdbOpenMemory();
    db.execute('CREATE TABLE t (k TEXT PRIMARY KEY, n INTEGER, b BLOB)');
    db.execute('INSERT INTO t VALUES (?, ?, ?)',
        ['a', 1, Uint8List.fromList([1, 2, 3])]);
    expect(db.updatedRows, 1);
    final rows = db.select('SELECT k, n, b, COUNT(*) AS c FROM t');
    expect(rows.columnNames, ['k', 'n', 'b', 'c']);
    expect(rows.single['k'], 'a');
    expect(rows.single[1], 1);
    expect(rows.single['b'], [1, 2, 3]);
    expect(rows.single['c'], 1);
    expect(rows.single.keys, ['k', 'n', 'b', 'c']);
    expect(db.select('SELECT * FROM t WHERE k = ?', ['zz']), isEmpty);
    db.dispose();
  });

  test('a failing statement throws XDbException with SQLite\'s message', () {
    final db = xdbOpenMemory();
    db.execute('CREATE TABLE t (k TEXT PRIMARY KEY)');
    db.execute("INSERT INTO t VALUES ('a')");
    expect(
        () => db.execute("INSERT INTO t VALUES ('a')"),
        throwsA(isA<XDbException>().having(
            (e) => e.message, 'message', contains('UNIQUE constraint failed'))));
    db.dispose();
  });

  test('transaction commits once, and rolls back when the body throws', () {
    final db = xdbOpenMemory();
    db.execute('CREATE TABLE t (n INTEGER)');
    db.transaction(() {
      for (var i = 0; i < 5; i++) {
        db.execute('INSERT INTO t VALUES (?)', [i]);
      }
    });
    expect(db.select('SELECT COUNT(*) c FROM t').single['c'], 5);
    expect(
        () => db.transaction(() {
              db.execute('INSERT INTO t VALUES (99)');
              throw StateError('no');
            }),
        throwsStateError);
    expect(db.select('SELECT COUNT(*) c FROM t').single['c'], 5);
    expect(db.inTransaction, isFalse);
    db.dispose();
  });

  test(':memory: through dbOpener is a fresh database each time', () {
    final a = dbOpener(':memory:');
    a.execute('CREATE TABLE t (n INTEGER)');
    final b = dbOpener(':memory:');
    expect(() => b.select('SELECT * FROM t'), throwsA(isA<XDbException>()));
    a.dispose();
    b.dispose();
    expect(File(':memory:').existsSync(), isFalse);
  });

  test('a file: two handles share one database; the last dispose closes it',
      () {
    final path = '${dir.path}/s.zx';
    final a = xdbOpenFile(path);
    a.execute('CREATE TABLE t (n INTEGER)');
    final b = xdbOpenFile(path);
    b.execute('INSERT INTO t VALUES (1)');
    expect(a.select('SELECT n FROM t').single['n'], 1);
    a.dispose();
    expect(b.select('SELECT n FROM t').single['n'], 1);
    b.dispose();
    final c = xdbOpenFile(path);
    expect(c.select('SELECT n FROM t').single['n'], 1, reason: 'persisted');
    c.dispose();
  });

  test('a password protects the file', () {
    final path = '${dir.path}/p.zx';
    final a = xdbOpenFile(path, password: 'aabbcc');
    a.execute('CREATE TABLE t (n INTEGER)');
    a.execute('INSERT INTO t VALUES (7)');
    a.dispose();
    expect(() => xdbOpenFile(path, password: 'wrong'),
        throwsA(isA<XDbException>()));
    final b = xdbOpenFile(path, password: 'aabbcc');
    expect(b.select('SELECT n FROM t').single['n'], 7);
    b.dispose();
  });

  test('the file is compacted when it doubles, and prepared statements '
      'survive it', () {
    final path = '${dir.path}/g.zx';
    final db = xdbOpenFile(path);
    db.execute('CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT)');
    db.transaction(() {
      for (var i = 0; i < 2000; i++) {
        db.execute('INSERT INTO t VALUES (?, ?)', [i, 'value $i' * 4]);
      }
    });
    final st = db.prepare('UPDATE t SET v = ? WHERE k = ?');
    var peak = 0;
    // Autocommits append to the file; past twice its size (+4 MiB) the
    // handle compacts it by itself.
    for (var i = 0; i < 1500; i++) {
      st.execute(['changed $i', i]);
      if (db.bytes > peak) peak = db.bytes;
    }
    expect(db.bytes, lessThan(peak), reason: 'a compaction ran');
    expect(db.select('SELECT v FROM t WHERE k = 1499').single['v'],
        'changed 1499');
    st.execute(['after', 0]);
    expect(db.select('SELECT v FROM t WHERE k = 0').single['v'], 'after');
    db.dispose();
  });
}
