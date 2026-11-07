#!/bin/sh
# Отдельная служба хранения; stop не меняет VPN и не снимает защиту.
PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin
export PATH
case "${1:-}" in
  start)
    /opt/sbin/vpn-history mount || logger -t vpn-history 'Раздел истории недоступен; VPN не изменяется'
    nohup /opt/sbin/vpn-history run >/dev/null 2>&1 < /dev/null &
    ;;
  stop)
    history_pid=$(cat /tmp/vpn-history/pid 2>/dev/null || true)
    case "$history_pid" in ''|*[!0-9]*) exit 0;; esac
    [ -r "/proc/$history_pid/cmdline" ] || exit 0
    tr '\000' ' ' < "/proc/$history_pid/cmdline" | grep -q '/opt/sbin/vpn-history run' || exit 0
    kill "$history_pid"
    history_wait=15
    while kill -0 "$history_pid" 2>/dev/null; do
      [ "$history_wait" -gt 0 ] || exit 1
      sleep 1; history_wait=$((history_wait - 1))
    done
    ;;
  restart) "$0" stop && "$0" start;;
  status) /opt/sbin/vpn-history status;;
  *) echo 'Использование: S07vpn-history start|stop|restart|status' >&2; exit 2;;
esac
