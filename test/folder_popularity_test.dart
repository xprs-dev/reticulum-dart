import 'dart:ffi';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/src/services/files/folder_popularity.dart';
import 'package:sqlite3/open.dart';

// A fixed instant inside a month (day 15, noon UTC) so tests never touch a wall
// clock. ym = year*100 + month.
int _ms(int year, int month) =>
    DateTime.utc(year, month, 15, 12).millisecondsSinceEpoch;

void main() {
  // CI/dev hosts often ship only the runtime .so.0, not the dev symlink.
  open.overrideFor(
      OperatingSystem.linux, () => DynamicLibrary.open('libsqlite3.so.0'));

  group('FolderPopularity', () {
    test('ymOf packs year and month', () {
      expect(FolderPopularity.ymOf(_ms(2026, 7)), 202607);
      expect(FolderPopularity.ymOf(_ms(2025, 12)), 202512);
    });

    test('counts unique seeders and leechers in the live month', () {
      final p = FolderPopularity.open(':memory:');
      final now = _ms(2026, 7);
      p.sampleSeeders('F', ['a', 'b', 'a'], now); // 'a' repeated → counts once
      p.recordLeecher('F', 'x', now);
      p.recordLeecher('F', 'x', now); // same leecher, same month → once
      p.recordLeecher('F', 'y', now);

      final s = p.series('F', now);
      expect(s, hasLength(1));
      expect(s.single.ym, 202607);
      expect(s.single.seeders, 2);
      expect(s.single.leechers, 2);
      p.close();
    });

    test('a finished month collapses to totals and stops growing raw rows', () {
      final p = FolderPopularity.open(':memory:');
      final june = _ms(2026, 6);
      p.sampleSeeders('F', ['a', 'b'], june);
      p.recordLeecher('F', 'x', june);

      // Cross into July: writing in the new month rolls June up to pop_month.
      final july = _ms(2026, 7);
      p.sampleSeeders('F', ['a', 'c'], july); // July: 'a' again + new 'c'

      final s = p.series('F', july, months: 12);
      expect(s.map((m) => m.ym), [202606, 202607]);
      // June is finalized to its totals; the live July month counts on its own.
      expect(s[0].seeders, 2);
      expect(s[0].leechers, 1);
      expect(s[1].seeders, 2);
      expect(s[1].leechers, 0);

      // A seeder id from June may reappear in July independently.
      p.sampleSeeders('F', ['b'], july);
      final s2 = p.series('F', july);
      expect(s2[1].seeders, 3); // a, c, b in July
      expect(s2[0].seeders, 2); // June total untouched
      p.close();
    });

    test('series caps to the last N months', () {
      final p = FolderPopularity.open(':memory:');
      for (var m = 1; m <= 6; m++) {
        p.sampleSeeders('F', ['s$m'], _ms(2026, m));
      }
      final s = p.series('F', _ms(2026, 6), months: 3);
      expect(s.map((m) => m.ym), [202604, 202605, 202606]);
      p.close();
    });

    test('folders are isolated', () {
      final p = FolderPopularity.open(':memory:');
      final now = _ms(2026, 7);
      p.sampleSeeders('A', ['a'], now);
      p.sampleSeeders('B', ['b', 'c'], now);
      expect(p.series('A', now).single.seeders, 1);
      expect(p.series('B', now).single.seeders, 2);
      p.close();
    });
  });
}
