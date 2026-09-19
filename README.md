# syslogparse

RFC 3164 / RFC 5424 の syslog 行を Python 標準ライブラリだけで解析するスクリプトです。
外部パッケージのインストールは不要です。

RFC 3164 と RFC 5424 が混在したログをそのまま流し込むと、
形式を自動判別して Facility / Severity / タイムスタンプ / ホスト名 / 本文に分解します。

## 使い方

```
git clone https://github.com/ac5net/syslogparse.git
cd syslogparse
cat /var/log/messages | python3 syslogparse.py
```

同梱のサンプルで動作を確認できます。

```
python3 syslogparse.py < testdata/sample.log
```

## 出力例

```
RFC3164 | auth.crit     | 2025-10-11T22:14:15     | host01            | su: 'su root' failed for user1 on /dev/pts/8
RFC3164 | user.notice   | 2026-08-07T09:03:11     | host02            | sshd[4123]: Accepted publickey for deploy from 192
RFC5424 | local4.notice | 2026-08-24T05:14:15.003Z | host03.example.jp | An application event log entry
RFC5424 | kern.emerg    | 2026-08-24T05:14:17.000Z | host03.example.jp | Emergency level test
UNKNOWN | not a syslog line at all
```

## 踏んだバグ

このスクリプトを書く過程で3つ踏みました。**どれも例外を出しません。**
パースは「成功」し、読み込み件数のログも正常に出ます。

### 1. RFC 3164 の1桁日は空白埋め

RFC 3164 4.1.2 にこう書かれています。

> If the day of the month is less than 10, then it MUST be represented as a space and then the number.
> For example, the 7th day of August would be represented as "Aug  7",
> with two spaces between the "g" and the "7".

ゼロ埋めではなく空白埋めで、区切りの空白が2つになります。
`(?P<day>\d{2})` と書くと毎月1日から9日までが一切マッチせず、黙って捨てられます。

### 2. 年またぎ補正の向き

RFC 3164 のタイムスタンプには年が入っていないため、受信側で補う必要があります。
「未来になったら前年」という補正の条件を逆にすると、
**32秒前のログが365日先の日付として記録されます。**

年末以外にテストすると絶対に再現しません。`test_bugs.py` に固定日時のケースを入れてあります。

### 3. `13 / 8` が `1.625` になる

PRIVAL = Facility * 8 + Severity（RFC 5424 6.2.1）なので逆算は除算と剰余ですが、
Python 3 の `/` は真の除算です。`//` を使います。
Facility 番号が小数になっても例外は出ないため、出力を目で見るまで気づきませんでした。

## テスト

3つのバグが直っていることを確認します。

```
python3 test_bugs.py
```

PRI のデコードは RFC 5424 に載っている2つの例（`pri=0` と `pri=165`）で検算しています。

## 解説記事

RFC 3164 と RFC 5424 の対応、Facility / Severity の一覧、
それぞれのバグに至った経緯はブログに書いています。

https://ac-5.net/security/syslog-rfc3164-rfc5424-parse/

## ライセンス

MIT
