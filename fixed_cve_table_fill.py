import psycopg2
import re
from psycopg2.extras import execute_values

# Параметры подключения к БД
DB_CONFIG = {
    'dbname': 'uroboros',
    'user': 'owner',
    'password': '1111',
    'host': 'localhost',
    'port': 5432
}

# Регулярное выражение для поиска CVE-идентификаторов по шаблону CVE-YYYY-NNNN
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}')

def main():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False
    cur = conn.cursor()

    try:
        print("Загрузка справочных данных...")

        # 1. Загружаем список версий пакетов из таблицы assm_pkg_vrs (поле pkg_vrs_id) в схеме repositories.
        cur.execute("SELECT pkg_vrs_id FROM repositories.assm_pkg_vrs;")
        pkg_vrs_ids = [row[0] for row in cur.fetchall()]
        pkg_vrs_set = set(pkg_vrs_ids)

        # 2. Загружаем справочник уязвимостей: сопоставление CVE (поле name) -> id (из repositories.vulnerabilities)
        cur.execute("SELECT id, name FROM repositories.vulnerabilities;")
        vuln_rows = cur.fetchall()
        vuln_map = {row[1]: row[0] for row in vuln_rows}  # например: 'CVE-2007-6353' -> vulnerability_id

        # 3. Загружаем данные по версиям пакетов из repositories.pkg_version
        #    Здесь получаем pkg_vrs_id, version и pkg_id для сопоставления с пакетами.
        cur.execute("SELECT pkg_vrs_id, version, pkg_id FROM repositories.pkg_version;")
        pkg_version_rows = cur.fetchall()
        pkg_version_map = {row[0]: {'version': row[1], 'pkg_id': row[2]} for row in pkg_version_rows}

        # 4. Загружаем данные по пакетам из repositories.package: pkg_id -> pkg_name.
        cur.execute("SELECT pkg_id, pkg_name FROM repositories.package;")
        package_rows = cur.fetchall()
        package_map = {row[0]: row[1] for row in package_rows}

        # 5. Для репозитория строим mapping: (version, pkg_name) -> pkg_vrs_id, только для версий из assm_pkg_vrs.
        repo_ver_pkg_map = {}
        for pkg_vrs in pkg_vrs_set:
            details = pkg_version_map.get(pkg_vrs)
            if details:
                version = details['version']
                pkg_id = details['pkg_id']
                pkg_name = package_map.get(pkg_id)
                if pkg_name:
                    repo_ver_pkg_map[(version, pkg_name)] = pkg_vrs

        # 6. Загружаем записи из changelog (repositories.changelog)
        #    Фильтруем только те, у которых pkg_vrs_id входит в список assm_pkg_vrs.
        cur.execute(
            "SELECT id, pkg_vrs_id, log_desc FROM repositories.changelog WHERE pkg_vrs_id = ANY(%s);",
            (list(pkg_vrs_set),)
        )
        changelog_rows = cur.fetchall()
        changelog_list = [{'id': row[0], 'pkg_vrs_id': row[1], 'log_desc': row[2]} for row in changelog_rows]
        print(f"Найдено {len(changelog_list)} записей в changelog для выбранных версий.")

        # 7. Формируем mapping для каждой версии пакета: pkg_vrs_id -> минимальный (ранний) id записи из changelog.
        #    Это значение позже используется для fixed_tracker_string_number.
        changelog_pk_map = {}
        for row in changelog_list:
            pkg_vrs = row['pkg_vrs_id']
            if pkg_vrs not in changelog_pk_map or row['id'] < changelog_pk_map[pkg_vrs]:
                changelog_pk_map[pkg_vrs] = row['id']

        # 8. Обрабатываем записи changelog для поиска вхождений CVE.
        #    Для каждой уникальной пары (pkg_vrs_id, CVE) (учитывая vulnerability_id) будет создана запись.
        upsert_data = {}  # ключ: (pkg_vrs_id, vulnerability_id), значение: словарь с данными для вставки
        for entry in changelog_list:
            pkg_vrs = entry['pkg_vrs_id']
            log_desc = entry['log_desc']
            matches = CVE_PATTERN.findall(log_desc)
            if not matches:
                continue
            for cve in set(matches):
                vulnerability_id = vuln_map.get(cve)
                if vulnerability_id is None:
                    print(f"Предупреждение: {cve} не найден в vulnerabilities (changelog id: {entry['id']}).")
                    continue
                key = (pkg_vrs, vulnerability_id)
                if key not in upsert_data:
                    upsert_data[key] = {
                        'changelog_string_number': entry['id'],
                        'fixed_tracker_string_number': None
                    }
        # 9. Обрабатываем данные из debtracker, с дополнительным сравнением по version и pkg_name.
        #    Из debtracker извлекаем: cve_name, fixed_pkg_vrs_id, version и pkg_name.
        cur.execute("""
            SELECT dc.cve_name, cr.fixed_pkg_vrs_id, pv.version, p.pkg_name
            FROM debtracker.cve dc
            JOIN debtracker.cve_rep cr ON dc.cve_id = cr.cve_id
            JOIN debtracker.pkg_version pv ON pv.pkg_vrs_id = cr.fixed_pkg_vrs_id
            JOIN debtracker.package p ON p.pkg_id = pv.pkg_id;
        """)
        debtracker_rows = cur.fetchall()
        for row in debtracker_rows:
            deb_cve_name = row[0]
            # debtracker_fixed_pkg_vrs_id = row[1]  --> не используем напрямую, так как id не совпадают
            deb_version = row[2]
            deb_pkg_name = row[3]
            # Находим в mapping репозитория соответствующую версию и пакет по (version, pkg_name)
            repo_pkg_vrs_id = repo_ver_pkg_map.get((deb_version, deb_pkg_name))
            if repo_pkg_vrs_id is None:
                # Если в репозитории не найдено соответствующей версии по данным debtracker, пропускаем
                continue
            vulnerability_id = vuln_map.get(deb_cve_name)
            if vulnerability_id is None:
                print(f"Предупреждение: {deb_cve_name} из debtracker не найден в vulnerabilities.")
                continue
            key = (repo_pkg_vrs_id, vulnerability_id)
            # Если запись уже есть — обновляем fixed_tracker_string_number, если его ещё нет.
            current = upsert_data.get(key, {'changelog_string_number': None, 'fixed_tracker_string_number': None})
            if current['fixed_tracker_string_number'] is None:
                # Берём значение из mapping для данной версии из changelog
                current['fixed_tracker_string_number'] = changelog_pk_map.get(repo_pkg_vrs_id)
            upsert_data[key] = current

        # 10. Подготавливаем список записей для bulk-вставки / upsert.
        records = []
        for (pkg_vrs, vulnerability_id), data in upsert_data.items():
            records.append((
                pkg_vrs,
                vulnerability_id,
                data.get('changelog_string_number'),
                data.get('fixed_tracker_string_number'),
                None  # manual_input_user_id оставляем NULL
            ))
        print(f"Всего записей для вставки: {len(records)}")

        # 11. Bulk upsert в таблицу repositories.fixed_cve_status.
        upsert_query = """
            INSERT INTO repositories.fixed_cve_status 
                (pkg_vrs_id, vulnerability_id, changelog_string_number, fixed_tracker_string_number, manual_input_user_id)
            VALUES %s
            ON CONFLICT (pkg_vrs_id, vulnerability_id)
            DO UPDATE SET
                changelog_string_number = COALESCE(repositories.fixed_cve_status.changelog_string_number, EXCLUDED.changelog_string_number),
                fixed_tracker_string_number = COALESCE(repositories.fixed_cve_status.fixed_tracker_string_number, EXCLUDED.fixed_tracker_string_number)
        """
        if records:
            execute_values(cur, upsert_query, records, page_size=100)
            conn.commit()
            print(f"Выполнена вставка/обновление {len(records)} записей в fixed_cve_status.")
        else:
            print("Нет данных для вставки в fixed_cve_status.")

    except Exception as e:
        conn.rollback()
        print("Ошибка выполнения:", e)
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    main()
