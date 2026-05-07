import json
from datetime import datetime
from typing import Any, Dict, List

import psycopg2

from cve_versioning import _constraint_matches_version, _load_version_constraints


def init_db(host: str, port: int, database: str, user: str, password: str):
    conn = psycopg2.connect(
        host=host,
        port=port,
        dbname=database,
        user=user,
        password=password,
    )
    conn.autocommit = False
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cves (
                id BIGSERIAL PRIMARY KEY,
                cve_id TEXT NOT NULL,
                service_name TEXT NOT NULL,
                service_version TEXT,
                year INTEGER,
                description TEXT,
                affected_configurations TEXT,
                version_constraints TEXT,
                fixed_version TEXT,
                recommendation TEXT,
                match_status TEXT DEFAULT 'unknown',
                poc_code TEXT,
                poc_references TEXT,
                reference_links TEXT,
                published_date TEXT,
                last_modified TEXT,
                source TEXT NOT NULL,
                UNIQUE(cve_id, service_name)
            )
            """
        )

        missing_columns = [
            ("service_version", "TEXT"),
            ("version_constraints", "TEXT"),
            ("fixed_version", "TEXT"),
            ("recommendation", "TEXT"),
            ("match_status", "TEXT DEFAULT 'unknown'"),
        ]
        for col_name, col_type in missing_columns:
            cur.execute(
                f"""
                DO $$ BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'cves' AND column_name = '{col_name}'
                    ) THEN
                        ALTER TABLE cves ADD COLUMN {col_name} {col_type};
                    END IF;
                END $$;
                """
            )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
                id BIGSERIAL PRIMARY KEY,
                service_name TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                fetched_count INTEGER DEFAULT 0,
                inserted_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'running',
                note TEXT
            )
            """
        )
    conn.commit()
    return conn


def find_matching_cves(conn, service_name: str, service_version: str = "") -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT cve_id, service_name, service_version, year, description, affected_configurations,
                   version_constraints, fixed_version, recommendation, poc_references,
                   reference_links, published_date, source
            FROM cves
            WHERE service_name = %s
            ORDER BY year DESC, cve_id ASC
            """,
            (service_name,),
        )
        for record in cur.fetchall():
            version_constraints = _load_version_constraints(record[6])
            if service_version:
                if not version_constraints:
                    continue
                if not any(_constraint_matches_version(service_version, constraint) for constraint in version_constraints):
                    continue

            fixed_version = record[7] or ""
            recommendation = record[8] or ""
            if not recommendation and fixed_version:
                recommendation = f"Upgrade to version >= {fixed_version}"

            rows.append(
                {
                    "cve_id": record[0],
                    "service_name": record[1],
                    "service_version": record[2] or service_version,
                    "year": record[3],
                    "description": record[4],
                    "affected_configurations": record[5],
                    "version_constraints": version_constraints,
                    "fixed_version": fixed_version,
                    "recommendation": recommendation,
                    "poc_references": json.loads(record[9]) if record[9] else [],
                    "reference_links": json.loads(record[10]) if record[10] else [],
                    "published_date": record[11],
                    "source": record[12],
                    "match_status": "matched" if service_version else "unknown",
                }
            )

    return rows


def upsert_cves(
    conn,
    service_name: str,
    cves: List[Dict[str, Any]],
    start_year: int,
    end_year: int,
    service_version: str = "",
) -> int:
    inserted = 0
    for cve in cves:
        year = cve.get("year")
        if year is None or year < start_year or year > end_year:
            continue

        affected = cve.get("affected_configurations", "")
        published = cve.get("published_date", "")
        refs = cve.get("reference_links", [])
        pocs = cve.get("poc_references", [])
        version_constraints = cve.get("version_constraints", "[]")
        fixed_version = cve.get("fixed_version", "")
        recommendation = cve.get("recommendation", "")
        stored_service_version = cve.get("service_version", "")
        match_status = cve.get("match_status", "unknown")

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO cves (
                    cve_id,
                    service_name,
                    service_version,
                    year,
                    description,
                    affected_configurations,
                    version_constraints,
                    fixed_version,
                    recommendation,
                    match_status,
                    poc_code,
                    poc_references,
                    reference_links,
                    published_date,
                    last_modified,
                    source
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(cve_id, service_name) DO UPDATE SET
                    service_version=EXCLUDED.service_version,
                    year=EXCLUDED.year,
                    description=EXCLUDED.description,
                    affected_configurations=EXCLUDED.affected_configurations,
                    version_constraints=EXCLUDED.version_constraints,
                    fixed_version=EXCLUDED.fixed_version,
                    recommendation=EXCLUDED.recommendation,
                    match_status=EXCLUDED.match_status,
                    poc_references=EXCLUDED.poc_references,
                    reference_links=EXCLUDED.reference_links,
                    published_date=EXCLUDED.published_date,
                    last_modified=EXCLUDED.last_modified,
                    source=EXCLUDED.source
                """,
                (
                    cve["cve_id"],
                    service_name,
                    stored_service_version,
                    year,
                    cve.get("description", ""),
                    affected,
                    version_constraints,
                    fixed_version,
                    recommendation,
                    match_status,
                    None,
                    json.dumps(pocs, ensure_ascii=True),
                    json.dumps(refs, ensure_ascii=True),
                    published,
                    datetime.utcnow().isoformat(timespec="seconds"),
                    cve.get("source", "cve.circl.lu"),
                ),
            )
        inserted += 1

    conn.commit()
    return inserted


def create_scan_run(conn, service_name: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_runs (service_name, started_at, status)
            VALUES (%s, %s, 'running')
            RETURNING id
            """,
            (service_name, datetime.utcnow().isoformat(timespec="seconds")),
        )
        run_id = cur.fetchone()[0]
    conn.commit()
    return int(run_id)


def finish_scan_run(
    conn,
    run_id: int,
    fetched_count: int,
    inserted_count: int,
    status: str,
    note: str = "",
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_runs
            SET finished_at=%s, fetched_count=%s, inserted_count=%s, status=%s, note=%s
            WHERE id=%s
            """,
            (
                datetime.utcnow().isoformat(timespec="seconds"),
                fetched_count,
                inserted_count,
                status,
                note,
                run_id,
            ),
        )
    conn.commit()
