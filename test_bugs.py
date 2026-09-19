#!/usr/bin/env python3
"""記事で扱った3つのバグを、直っていることで確認するテスト

    python3 test_bugs.py

どれも「例外を出さずに間違える」種類なので、
壊れていても実行は成功してしまう。必ず戻り値を見ること。
"""
import datetime
import re
import syslogparse as sp

fails = []


def check(name, got, want):
    if got == want:
        print('ok   %s' % name)
    else:
        print('FAIL %s\n       got  %r\n       want %r' % (name, got, want))
        fails.append(name)


# --- バグ1: RFC 3164 の1桁日は空白埋め（4.1.2）------------------------
# "Aug  7" は g と 7 のあいだが空白2つ。\d{2} で受けると毎月1〜9日が全滅する。
RE_BUGGY = re.compile(r'^<(?P<pri>\d{1,3})>(?P<mon>[A-Z][a-z]{2}) (?P<day>\d{2}) ')

LINE_1DIGIT = "<13>Aug  7 09:03:11 host02 sshd[4123]: test"
LINE_2DIGIT = "<13>Aug 17 09:03:11 host02 sshd[4124]: test"

check('bug1 旧実装は1桁日にマッチしない',
      RE_BUGGY.match(LINE_1DIGIT) is None, True)
check('bug1 現行は1桁日を解析できる',
      sp.parse(LINE_1DIGIT)['format'], 'RFC3164')
check('bug1 現行は2桁日も解析できる',
      sp.parse(LINE_2DIGIT)['format'], 'RFC3164')

# --- バグ2: 年またぎ補正の向き ----------------------------------------
# 12/31に書かれたログを32秒後に処理する。前年に倒してはいけない。
now = datetime.datetime(2026, 12, 31, 23, 59, 59)
dt = sp.resolve_year('Dec', 31, 23, 59, 27, now=now)
check('bug2 32秒前のログが1年先にならない', dt.year, 2026)

# 逆に、1/1に受け取った12/31のログは前年に倒す。
now2 = datetime.datetime(2027, 1, 1, 0, 0, 30)
dt2 = sp.resolve_year('Dec', 31, 23, 59, 59, now=now2)
check('bug2 年またぎ直後は前年に解決する', dt2.year, 2026)

# --- バグ3: PRI の分解は整数除算 --------------------------------------
# Python3 の / は真の除算。13 / 8 は 1.625 になる。
check('bug3 facilityが整数', sp.decode_pri(13)['facility'], 1)
check('bug3 severityが整数', sp.decode_pri(13)['severity'], 5)

# RFC 5424 に載っている2つの例で検算する
check('RFC 5424 例 pri=0',
      (sp.decode_pri(0)['facility'], sp.decode_pri(0)['severity_name']),
      (0, 'emerg'))
check('RFC 5424 例 pri=165',
      (sp.decode_pri(165)['facility_name'], sp.decode_pri(165)['severity_name']),
      ('local4', 'notice'))

print()
if fails:
    print('%d failed' % len(fails))
    raise SystemExit(1)
print('all passed')
