from cve_service_collector import init_db, fetch_from_nvd, upsert_cves

conn = init_db('localhost', 5432, 'My_Project', 'postgres', 'vanduc0201')
with conn.cursor() as cur:
    cur.execute('DELETE FROM cves')
conn.commit()

rows = fetch_from_nvd('vsftpd')
inserted = upsert_cves(conn, 'vsftpd', rows, 2000, 2026)
print('inserted', inserted)

with conn.cursor() as cur:
    cur.execute("SELECT COUNT(*) FROM cves WHERE version_constraints IS NOT NULL AND version_constraints != '[]'")
    print('with_constraints_in_db', cur.fetchone()[0])
    cur.execute("SELECT cve_id, version_constraints, fixed_version, recommendation FROM cves WHERE version_constraints IS NOT NULL AND version_constraints != '[]' LIMIT 3")
    for row in cur.fetchall():
        print(row[0], row[1][:120], row[2], row[3])

conn.close()
