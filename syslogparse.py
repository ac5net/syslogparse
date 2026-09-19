#!/usr/bin/env python3
"""syslogparse.py - RFC 3164 / RFC 5424 のsyslog行を解析する

使い方:
    cat /var/log/messages | ./syslogparse.py
"""
import sys, re, datetime

# RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP [SD] SP MSG
RE_5424 = re.compile(
    r'^<(?P<pri>\d{1,3})>(?P<ver>\d{1,2}) '
    r'(?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+)'
    r'(?: (?P<rest>.*))?$'
)

# RFC 3164: <PRI>Mmm d hh:mm:ss HOSTNAME MSG
# dd は1桁のとき空白埋め（RFC 3164 4.1.2）。\d{2} と書くと1桁日で全滅する
RE_3164 = re.compile(
    r'^<(?P<pri>\d{1,3})>'
    r'(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) '
    r'(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2}) '
    r'(?P<host>\S+) (?P<msg>.*)$'
)

MONTHS = {m: i + 1 for i, m in enumerate(
    ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
     'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])}

FACILITY = [
    'kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
    'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock',
    'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7',
]
SEVERITY = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']


def decode_pri(pri):
    """PRIVAL = Facility * 8 + Severity（RFC 5424 6.2.1）

    Python3 の / は真の除算で小数になる。必ず // を使う
    """
    fac, sev = pri // 8, pri % 8
    return {
        'facility': fac,
        'facility_name': FACILITY[fac] if fac < len(FACILITY) else str(fac),
        'severity': sev,
        'severity_name': SEVERITY[sev],
    }


def resolve_year(mon, day, h, mi, s, now=None):
    """RFC 3164 のタイムスタンプには年が無いので補う

    素朴に「現在の年」を入れると、年またぎ直後に約1年先の未来になる。
    未来に大きくずれたら前年とみなす。
    """
    now = now or datetime.datetime.now()
    try:
        dt = datetime.datetime(now.year, MONTHS[mon], day, h, mi, s)
    except ValueError:
        # 2月29日を平年に当てはめた場合など
        return None
    if (dt - now).total_seconds() > 86400:
        try:
            dt = dt.replace(year=now.year - 1)
        except ValueError:
            return None
    return dt


def parse(line, now=None):
    line = line.rstrip('\n')

    m = RE_5424.match(line)
    if m and m.group('ver') == '1':
        d = m.groupdict()
        rest = d.get('rest') or ''
        sd, msg = split_sd(rest)
        out = {'format': 'RFC5424', 'timestamp': d['ts'],
               'host': nil(d['host']), 'app': nil(d['app']),
               'procid': nil(d['procid']), 'msgid': nil(d['msgid']),
               'sd': sd, 'msg': strip_bom(msg)}
        out.update(decode_pri(int(d['pri'])))
        return out

    m = RE_3164.match(line)
    if m:
        d = m.groupdict()
        dt = resolve_year(d['mon'], int(d['day']),
                          int(d['h']), int(d['mi']), int(d['s']), now)
        out = {'format': 'RFC3164',
               'timestamp': dt.isoformat() if dt else None,
               'host': d['host'], 'app': None, 'procid': None,
               'msgid': None, 'sd': None, 'msg': d['msg']}
        out.update(decode_pri(int(d['pri'])))
        return out

    return {'format': 'UNKNOWN', 'raw': line}


def nil(v):
    """NILVALUE の "-" は「値なし」を表す（RFC 5424 6.2）"""
    return None if v == '-' else v


def strip_bom(msg):
    """MSG が UTF-8 のときは先頭に BOM が付く（RFC 5424 6.4）"""
    if msg.startswith('\ufeff'):
        return msg[1:]
    if msg.startswith('BOM'):  # BOMをASCIIで書く実装への保険
        return msg[3:]
    return msg


def split_sd(rest):
    """構造化データ部とMSGを分ける。"-" なら構造化データなし"""
    if rest.startswith('-'):
        return None, rest[1:].lstrip(' ')
    if not rest.startswith('['):
        return None, rest
    # \] でエスケープされた ] は終端ではない（RFC 5424 6.3.3）
    i, depth, esc = 0, 0, False
    while i < len(rest):
        c = rest[i]
        if esc:
            esc = False
        elif c == '\\':
            esc = True
        elif c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
            if depth == 0:
                return rest[:i + 1], rest[i + 1:].lstrip(' ')
        i += 1
    return rest, ''


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        r = parse(line)
        if r['format'] == 'UNKNOWN':
            print('UNKNOWN | %s' % r['raw'][:70])
            continue
        print('%s | %s.%s | %s | %s | %s' % (
            r['format'], r['facility_name'], r['severity_name'],
            r['timestamp'], r['host'] or '-', (r['msg'] or '')[:50]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
