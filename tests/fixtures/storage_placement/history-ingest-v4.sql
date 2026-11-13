-- Только фиксированный SQL; содержимое проб является данными JSON, не SQL-кодом.
PRAGMA foreign_keys=ON;
PRAGMA synchronous=FULL;
PRAGMA temp_store=MEMORY;
PRAGMA cache_size=-512;
PRAGMA max_page_count=16384;
BEGIN IMMEDIATE;
CREATE TEMP TABLE incoming AS SELECT value AS payload FROM json_each(CAST(readfile('/tmp/vpn-history/batch.json') AS TEXT));
INSERT OR IGNORE INTO runs(run_key,first_utc)
 SELECT json_extract(payload,'$.run'),json_extract(payload,'$.utc') FROM incoming;
-- Очистка собственных старых записей, без полной копии или VACUUM.
DELETE FROM cycles WHERE utc < CAST(strftime('%s','now') AS INTEGER)-864000;
DELETE FROM events WHERE utc < CAST(strftime('%s','now') AS INTEGER)-864000;
DELETE FROM internet_cycles WHERE utc < CAST(strftime('%s','now') AS INTEGER)-864000;
-- При приближении к лимиту освободить запас страниц внутри того же файла.
CREATE TEMP TABLE budget AS SELECT
 (SELECT page_count FROM pragma_page_count)-(SELECT freelist_count FROM pragma_freelist_count)>14336 AS trim;
DELETE FROM cycles WHERE id IN(SELECT id FROM cycles ORDER BY utc,id
 LIMIT (SELECT CASE WHEN trim THEN (SELECT (count(*)+3)/4 FROM cycles) ELSE 0 END FROM budget));
DELETE FROM events WHERE id IN(SELECT id FROM events ORDER BY utc,id
 LIMIT (SELECT CASE WHEN trim THEN (SELECT (count(*)+3)/4 FROM events) ELSE 0 END FROM budget));
DELETE FROM internet_cycles WHERE id IN(SELECT id FROM internet_cycles ORDER BY utc,id
 LIMIT (SELECT CASE WHEN trim THEN (SELECT (count(*)+3)/4 FROM internet_cycles) ELSE 0 END FROM budget));
INSERT OR IGNORE INTO cycles(run_id,seq,utc,mono,xray_pid,active,target,api_ok,dropped)
 SELECT r.id,json_extract(i.payload,'$.seq'),json_extract(i.payload,'$.utc'),json_extract(i.payload,'$.mono'),
 json_extract(i.payload,'$.xray_pid'),a.id,t.id,json_extract(i.payload,'$.api_ok'),json_extract(i.payload,'$.dropped')
 FROM incoming i JOIN runs r ON r.run_key=json_extract(i.payload,'$.run')
 JOIN channels a ON a.tag=json_extract(i.payload,'$.active') JOIN channels t ON t.tag=json_extract(i.payload,'$.target')
 WHERE json_extract(i.payload,'$.kind')='sample';
INSERT OR IGNORE INTO probes(cycle_id,channel_id,started_utc,ended_utc,started_mono,ended_mono,ok,curl_exit,http_code,total_ms,ttfb_ms)
 SELECT c.id,CASE p.key WHEN 'primary' THEN 1 WHEN 'backup' THEN 2 WHEN 'hysteria' THEN 3 END,
 json_extract(p.value,'$.started_utc'),json_extract(p.value,'$.ended_utc'),
 json_extract(p.value,'$.started_mono'),json_extract(p.value,'$.ended_mono'),
 json_extract(p.value,'$.ok'),json_extract(p.value,'$.curl_exit'),json_extract(p.value,'$.http_code'),
 json_extract(p.value,'$.total_ms'),json_extract(p.value,'$.ttfb_ms')
 FROM incoming i JOIN runs r ON r.run_key=json_extract(i.payload,'$.run')
 JOIN cycles c ON c.run_id=r.id AND c.seq=json_extract(i.payload,'$.seq')
 JOIN json_each(i.payload) p ON p.key IN('primary','backup','hysteria')
 WHERE json_extract(i.payload,'$.kind')='sample';
INSERT OR IGNORE INTO events(run_id,seq,utc,mono,kind,active,target)
 SELECT r.id,json_extract(i.payload,'$.seq'),json_extract(i.payload,'$.utc'),json_extract(i.payload,'$.mono'),
 json_extract(i.payload,'$.event'),a.id,t.id
 FROM incoming i JOIN runs r ON r.run_key=json_extract(i.payload,'$.run')
 JOIN channels a ON a.tag=json_extract(i.payload,'$.active') JOIN channels t ON t.tag=json_extract(i.payload,'$.target')
 WHERE json_extract(i.payload,'$.event') IS NOT NULL;
-- Метаданные путей отсутствуют у старой очереди: остаются NULL.
UPDATE cycles AS c SET
 active_path=json_extract(i.payload,'$.active_path'),target_path=json_extract(i.payload,'$.target_path'),
 previous_path=json_extract(i.payload,'$.previous_path'),path_changed_mono=json_extract(i.payload,'$.path_changed_mono')
 FROM incoming i JOIN runs r ON r.run_key=json_extract(i.payload,'$.run')
 WHERE c.run_id=r.id AND c.seq=json_extract(i.payload,'$.seq') AND json_extract(i.payload,'$.kind')='sample'
 AND c.active_path IS NULL AND json_extract(i.payload,'$.active_path') IS NOT NULL;
UPDATE events AS e SET active_path=json_extract(i.payload,'$.active_path'),target_path=json_extract(i.payload,'$.target_path')
 FROM incoming i JOIN runs r ON r.run_key=json_extract(i.payload,'$.run')
 WHERE e.run_id=r.id AND e.seq=json_extract(i.payload,'$.seq') AND e.active_path IS NULL;
INSERT OR IGNORE INTO path_probes
 SELECT c.id,p.key,json_extract(p.value,'$.started_utc'),json_extract(p.value,'$.ended_utc'),
 json_extract(p.value,'$.started_mono'),json_extract(p.value,'$.ended_mono'),json_extract(p.value,'$.ok'),
 json_extract(p.value,'$.curl_exit'),json_extract(p.value,'$.http_code'),json_extract(p.value,'$.total_ms'),json_extract(p.value,'$.ttfb_ms')
 FROM incoming i JOIN runs r ON r.run_key=json_extract(i.payload,'$.run')
 JOIN cycles c ON c.run_id=r.id AND c.seq=json_extract(i.payload,'$.seq')
 JOIN json_each(i.payload,'$.paths') p WHERE json_extract(i.payload,'$.kind')='sample';
INSERT OR IGNORE INTO internet_cycles(run_id,seq,utc,mono,trigger_mono,active,xray_pid,config_rev,trigger_still_failed,dropped)
 SELECT r.id,json_extract(i.payload,'$.seq'),json_extract(i.payload,'$.utc'),json_extract(i.payload,'$.mono'),
 json_extract(i.payload,'$.trigger_mono'),a.id,json_extract(i.payload,'$.xray_pid'),json_extract(i.payload,'$.config_rev'),
 json_extract(i.payload,'$.trigger_still_failed'),json_extract(i.payload,'$.dropped')
 FROM incoming i JOIN runs r ON r.run_key=json_extract(i.payload,'$.run')
 JOIN channels a ON a.tag=json_extract(i.payload,'$.active') WHERE json_extract(i.payload,'$.kind')='internet';
INSERT OR IGNORE INTO internet_probes(cycle_id,target_id,probe_type,target,started_utc,ended_utc,started_mono,ended_mono,ok,exit_code,http_code,total_ms,ttfb_ms)
 SELECT c.id,json_extract(p.value,'$.target_id'),json_extract(p.value,'$.probe_type'),json_extract(p.value,'$.target'),
 json_extract(p.value,'$.started_utc'),json_extract(p.value,'$.ended_utc'),json_extract(p.value,'$.started_mono'),
 json_extract(p.value,'$.ended_mono'),json_extract(p.value,'$.ok'),json_extract(p.value,'$.exit_code'),json_extract(p.value,'$.http_code'),
 json_extract(p.value,'$.total_ms'),json_extract(p.value,'$.ttfb_ms')
 FROM incoming i JOIN runs r ON r.run_key=json_extract(i.payload,'$.run')
 JOIN internet_cycles c ON c.run_id=r.id AND c.seq=json_extract(i.payload,'$.seq')
 JOIN json_each(i.payload,'$.probes') p WHERE json_extract(i.payload,'$.kind')='internet';
DELETE FROM runs WHERE id NOT IN(SELECT run_id FROM cycles) AND id NOT IN(SELECT run_id FROM events) AND id NOT IN(SELECT run_id FROM internet_cycles);
COMMIT;
