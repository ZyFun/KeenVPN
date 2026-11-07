#!/bin/sh
# Независимый writer SQLite. Его отказ не участвует в выборе VPN-выхода.
set -u
PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077
history_uuid=00000000-0000-0000-0000-000000000002
history_mount=/tmp/mnt/00000000-0000-0000-0000-000000000002
history_store=/tmp/mnt/00000000-0000-0000-0000-000000000002/example/history
history_run=/tmp/vpn-history
history_queue=/tmp/vpn-history-queue
internet_queue=/tmp/vpn-internet-queue
history_cfg=/opt/etc/vpn-history
history_sql_pid=
history_sleep_pid=

mounted_store() {
  history_device=$(awk -v p="$history_mount" '$2==p && $3=="ext4" && $4~/(^|,)rw(,|$)/ {print $1}' /proc/mounts)
  case "$history_device" in /dev/sd[a-z][0-9]*) ;; *) return 1;; esac
  [ "$(printf '%s\n' "$history_device" | wc -l)" -eq 1 ] || return 1
  blkid "$history_device" | grep -F "UUID=\"$history_uuid\"" >/dev/null || return 1
  [ -d "$history_store" ] && [ ! -L "$history_store" ] || return 1
  [ "$(cat "$history_store/.store-id" 2>/dev/null)" = "$history_uuid" ]
}
mount_volume() {
  # Выбран отдельный DATA по UUID. Автомонтирования и fallback на /opt нет.
  mounted_store
}
write_status() {
  jq -nc --arg status "$1" --argjson now "$(date +%s)" '{status:$status,checked_at:$now}' > "$history_run/status.json.new" &&
    mv "$history_run/status.json.new" "$history_run/status.json"
}
run_sql_file() {
  # Относительный путь БД и cwd на разделе исключают запись под снятый mount.
  (cd "$history_store" && mounted_store &&
    exec sqlite3 -batch -bail -cmd '.timeout 1000' ./history.sqlite < "$1") > "$history_run/sql.out" 2> "$history_run/sql.error" &
  history_sql_pid=$!
  wait "$history_sql_pid"
  history_result=$?
  history_sql_pid=
  return "$history_result"
}
flush_history() {
  mounted_store || { write_status storage_unavailable; return 1; }
  [ -f "$history_store/history.sqlite" ] && [ ! -L "$history_store/history.sqlite" ] || { write_status database_missing; return 1; }
  history_size=$(du -sk "$history_store" | awk '{print $1}')
  # До 256 МиБ БД и до 256 МиБ временного rollback-журнала.
  [ "$history_size" -le 131072 ] || { write_status storage_budget_exceeded; return 1; }
  history_free=$(df -k "$history_store" | awk 'NR==2 {print $4}')
  [ "${history_free:-0}" -ge 65536 ] || { write_status storage_low_space; return 1; }
  # Условия схемы проверяются без скрытой миграции или смены journal_mode.
  history_version=$(cd "$history_store" && mounted_store && sqlite3 -readonly ./history.sqlite 'PRAGMA user_version; PRAGMA journal_mode;') || { write_status database_unreadable; return 1; }
  [ "$history_version" = "$(printf '3\ndelete')" ] || { write_status database_incompatible; return 1; }
  set --
  for history_file in "$history_queue"/*.json; do
    [ ! -f "$history_file" ] || set -- "$@" "$history_file"
  done
  [ "$#" -le 120 ] || { write_status queue_limit; return 1; }
  internet_count=0
  for history_file in "$internet_queue"/*.json; do
    [ -f "$history_file" ] || continue
    [ "$internet_count" -lt 20 ] || break
    # Повреждение прямой диагностики не останавливает сохранение VPN-проб.
    if jq -es 'length==1 and .[0].kind=="internet"' "$history_file" >/dev/null 2>&1 &&
       jq -s . "$history_file" | jq -e -f "$history_cfg/validate.jq" >/dev/null 2>&1; then
      set -- "$@" "$history_file"
      internet_count=$((internet_count+1))
    fi
  done
  [ "$#" -gt 0 ] || { write_status waiting_for_samples; return 0; }
  jq -sc . "$@" > "$history_run/batch.json.new" || { write_status invalid_json; return 1; }
  jq -e -f "$history_cfg/validate.jq" "$history_run/batch.json.new" >/dev/null || { write_status invalid_sample; return 1; }
  mv "$history_run/batch.json.new" "$history_run/batch.json" || return 1
  if run_sql_file "$history_cfg/ingest.sql"; then
    # Удалять только уже зафиксированные снимки, не новые файлы следующего цикла.
    for history_file in "$@"; do
      case "$history_file" in /tmp/vpn-history-queue/*.json|/tmp/vpn-internet-queue/*.json) rm -f "$history_file";; *) return 1;; esac
    done
    write_status committed
  else
    write_status sqlite_error
    return 1
  fi
}
cleanup() {
  trap - EXIT HUP INT TERM
  [ -z "$history_sleep_pid" ] || kill "$history_sleep_pid" 2>/dev/null || true
  [ -z "$history_sql_pid" ] || kill "$history_sql_pid" 2>/dev/null || true
  rm -f "$history_run/pid"
  rmdir "$history_run/lock" 2>/dev/null || true
  exit 0
}
case "${1:-status}" in
  mount) mount_volume; exit $?;;
  status)
    [ ! -f "$history_run/status.json" ] || cat "$history_run/status.json"
    if mounted_store && [ -f "$history_store/history.sqlite" ]; then
      (cd "$history_store" && mounted_store && sqlite3 -readonly -json ./history.sqlite \
        'SELECT (SELECT count(*) FROM cycles) AS cycles,(SELECT count(*) FROM probes) AS probes,(SELECT count(*) FROM events) AS events,(SELECT min(utc) FROM cycles) AS first_utc,(SELECT max(utc) FROM cycles) AS last_utc;')
    fi
    exit 0;;
  export-csv)
    mounted_store || exit 1
    cd "$history_store" || exit 1
    mounted_store || exit 1
    # Согласованный SELECT, без создания второй БД на USB.
    exec sqlite3 -readonly -header -csv -cmd '.timeout 1000' ./history.sqlite 'SELECT * FROM probe_history ORDER BY started_utc,run_key,seq,channel;';;
  export-internet-csv)
    mounted_store || exit 1
    cd "$history_store" || exit 1
    mounted_store || exit 1
    exec sqlite3 -readonly -header -csv -cmd '.timeout 1000' ./history.sqlite 'SELECT * FROM internet_history ORDER BY started_utc,run_key,seq,target_id;';;
  export-paths-csv|export-path-events-csv|export-path-usage-csv)
    mounted_store || exit 1
    cd "$history_store" || exit 1
    mounted_store || exit 1
    case "$1" in
      export-paths-csv) history_view=path_history;;
      export-path-events-csv) history_view=path_events;;
      export-path-usage-csv) history_view=path_periods;;
    esac
    exec sqlite3 -readonly -header -csv -cmd '.timeout 1000' ./history.sqlite "SELECT * FROM $history_view;";;
  export-db)
    mounted_store || exit 1
    mkdir -p "$history_run" || exit 1
    mkdir "$history_run/export.lock" 2>/dev/null || exit 1
    trap 'rm -f /tmp/vpn-history/export.sqlite; rmdir /tmp/vpn-history/export.lock 2>/dev/null || true' EXIT HUP INT TERM
    cd "$history_store" || exit 1
    mounted_store || exit 1
    # Согласованный SQLite backup только в RAM, не вторая копия на USB.
    sqlite3 -readonly -batch -bail -cmd '.timeout 1000' ./history.sqlite ".backup '/tmp/vpn-history/export.sqlite'" || exit 1
    cat /tmp/vpn-history/export.sqlite
    exit $?;;
  run) ;;
  *) echo 'Использование: vpn-history mount|run|status|export-csv|export-internet-csv|export-paths-csv|export-path-events-csv|export-path-usage-csv|export-db' >&2; exit 2;;
esac
mkdir -p "$history_run" "$history_queue"
chmod 700 "$history_run" "$history_queue"
if ! mkdir "$history_run/lock" 2>/dev/null; then
  history_old=$(cat "$history_run/pid" 2>/dev/null || true)
  case "$history_old" in
    ''|*[!0-9]*) ;;
    *) if [ -r "/proc/$history_old/cmdline" ] && tr '\000' ' ' < "/proc/$history_old/cmdline" | grep -q '/opt/sbin/vpn-history run'; then exit 0; fi;;
  esac
  rmdir "$history_run/lock" 2>/dev/null && mkdir "$history_run/lock" || exit 1
fi
echo $$ > "$history_run/pid"
trap cleanup EXIT HUP INT TERM
while :; do
  flush_history || true
  sleep 60 & history_sleep_pid=$!
  wait "$history_sleep_pid" || true
  history_sleep_pid=
done
