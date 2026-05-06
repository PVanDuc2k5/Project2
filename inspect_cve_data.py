from cve_service_collector import init_db

conn = init_db('localhost', 5432, 'My_Project', 'postgres', 'vanduc0201')

print('Sample CVE records:')
with conn.cursor() as cur:
    cur.execute('''
        SELECT cve_id, service_name, version_constraints, fixed_version, recommendation
        FROM cves
        WHERE service_name = 'vsftpd'
        LIMIT 3
    ''')
    for row in cur.fetchall():
        cve_id, service_name, vc, fixed, rec = row
        print(f'\n  CVE: {cve_id}')
        vc_preview = (vc[:60] + '...') if vc and len(vc) > 60 else str(vc)
        print(f'    version_constraints: {vc_preview}')
        print(f'    fixed_version: {fixed}')
        print(f'    recommendation: {rec}')

conn.close()
