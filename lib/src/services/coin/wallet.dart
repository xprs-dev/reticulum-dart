/*
 * wallet — local holdings of participation-coin bearer tokens (Proofs).
 *
 * One SQLite file holding the unspent Proofs this device owns, keyed by the
 * token secret (so the same token can never be stored twice). Spent proofs are
 * retained with state='spent' for the device's own double-spend self-check.
 * Path-injectable (':memory:' for tests); native only, a no-op on web — same
 * shape as ActivityArchive / the other coin-independent stores.
 *
 * This is the wallet's storage layer only; minting/redeeming/settlement live in
 * the mint and ATM layers. coin_ec/bearer_token + sqlite3 + dart:io.
 */
import 'dart:io';

import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:sqlite3/sqlite3.dart';

import '../../util/db_opener.dart';

import 'bearer_token.dart';
import 'coin_keyset.dart';

class CoinWallet {
  CoinWallet._(this._dbPath);

  final String _dbPath; // ':memory:' = no disk
  Database? _db;
  bool _failed = false;

  /// Open (creating the schema). Use ':memory:' for tests.
  factory CoinWallet.open(String path) {
    final w = CoinWallet._(path);
    w._ensureDb();
    return w;
  }

  Database? _ensureDb() {
    if (kIsWeb || _failed) return null;
    final existing = _db;
    if (existing != null) return existing;
    try {
      final Database db;
      if (_dbPath == ':memory:') {
        db = sqlite3.openInMemory();
      } else {
        final parent = File(_dbPath).parent;
        if (!parent.existsSync()) parent.createSync(recursive: true);
        db = dbOpener(_dbPath);
        db.execute('PRAGMA journal_mode = WAL;');
        db.execute('PRAGMA synchronous = NORMAL;');
      }
      db.execute('''
        CREATE TABLE IF NOT EXISTS proofs(
          secret      TEXT PRIMARY KEY,
          coin        TEXT NOT NULL,
          keyset_id   TEXT NOT NULL,
          amount      INTEGER NOT NULL,
          c           TEXT NOT NULL,
          r           TEXT NOT NULL,
          e           TEXT NOT NULL,
          s           TEXT NOT NULL,
          state       TEXT NOT NULL DEFAULT 'unspent',
          received_at INTEGER NOT NULL
        );
      ''');
      db.execute(
          'CREATE INDEX IF NOT EXISTS idx_proofs_coin ON proofs(coin, state);');
      _db = db;
      return db;
    } catch (_) {
      _failed = true;
      return null;
    }
  }

  int _nowMs() => DateTime.now().millisecondsSinceEpoch;

  /// Store an unspent [proof] for [coinId]. Returns false if we already hold a
  /// token with this secret (idempotent; never duplicates).
  bool add(String coinId, Proof proof) {
    final db = _ensureDb();
    if (db == null) return false;
    final existing = db.select(
        'SELECT 1 FROM proofs WHERE secret = ?', [proof.secretHex]);
    if (existing.isNotEmpty) return false;
    final p = proof.toJson();
    db.execute(
      'INSERT INTO proofs(secret, coin, keyset_id, amount, c, r, e, s, state, received_at)'
      " VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'unspent', ?)",
      [
        proof.secretHex,
        coinId,
        proof.keysetId,
        proof.amount,
        p['C'],
        p['r'],
        p['e'],
        p['s'],
        _nowMs(),
      ],
    );
    return true;
  }

  int addAll(String coinId, Iterable<Proof> proofs) {
    var n = 0;
    for (final p in proofs) {
      if (add(coinId, p)) n++;
    }
    return n;
  }

  /// Total unspent balance for [coinId].
  int balance(String coinId) {
    final db = _ensureDb();
    if (db == null) return 0;
    final rows = db.select(
        "SELECT COALESCE(SUM(amount),0) AS bal FROM proofs WHERE coin = ? AND state = 'unspent'",
        [coinId]);
    return (rows.first['bal'] as int?) ?? 0;
  }

  /// All unspent proofs for [coinId], largest denomination first.
  List<Proof> unspent(String coinId) {
    final db = _ensureDb();
    if (db == null) return const [];
    final rows = db.select(
        "SELECT * FROM proofs WHERE coin = ? AND state = 'unspent' ORDER BY amount DESC",
        [coinId]);
    return [for (final r in rows) _rowToProof(r)];
  }

  /// Greedily pick unspent proofs covering [amount]; empty if balance is short.
  /// Does not mark them spent — call [markSpent] once the spend is committed.
  List<Proof> selectForAmount(String coinId, int amount) {
    if (amount <= 0) return const [];
    final picked = <Proof>[];
    var total = 0;
    for (final p in unspent(coinId)) {
      if (total >= amount) break;
      picked.add(p);
      total += p.amount;
    }
    if (total < amount) return const [];
    return picked;
  }

  /// Mark a token spent (retained for the device's own double-spend self-check).
  void markSpent(String secretHex) {
    final db = _ensureDb();
    if (db == null) return;
    db.execute(
        "UPDATE proofs SET state = 'spent' WHERE secret = ?", [secretHex]);
  }

  /// Have we already spent the token with this secret? (local self-check)
  bool isSpent(String secretHex) {
    final db = _ensureDb();
    if (db == null) return false;
    final rows = db.select(
        "SELECT state FROM proofs WHERE secret = ?", [secretHex]);
    return rows.isNotEmpty && rows.first['state'] == 'spent';
  }

  Proof _rowToProof(Row r) => Proof.fromJson({
        'a': r['amount'],
        'id': r['keyset_id'],
        'secret': r['secret'],
        'C': r['c'],
        'r': r['r'],
        'e': r['e'],
        's': r['s'],
      })!;

  void close() {
    _db?.dispose();
    _db = null;
  }
}

/// Convenience: the denominations of [amount] a wallet would need to receive,
/// re-exported so callers don't reach into coin_keyset directly.
List<int> walletSplit(int amount) => splitAmount(amount);
