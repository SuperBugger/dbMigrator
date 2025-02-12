#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3
import psycopg2
from psycopg2.extras import execute_batch, execute_values
import logging
import sys

# Конфигурация подключения
SQLITE_DB = '/home/ivandor/Загрузки/uroboros.db.250211'
POSTGRES_CONFIG = {
    'dbname': 'uroboros',
    'user': 'owner',
    'password': '1111',
    'host': 'localhost',
    'port': '5432'
}

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler("migration_incremental.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class IdMapper:
    """
    Класс для хранения соотношения старых и новых идентификаторов.
    Структура: { 'projects': {old_id: new_id, ...}, 'assemblies': {...}, ... }
    """
    def __init__(self):
        self.mappings = {
            'projects': {},
            'assemblies': {},
            'src_packages': {},
            'pkg_versions': {},
            'changes': {},
            'urgency': {},
            'vulnerabilities': {}
        }
        logger.debug("Инициализация IdMapper")

    def add_mapping(self, table, old_id, new_id):
        self.mappings.setdefault(table, {})[old_id] = new_id
        # logger.debug(f"Добавлен маппинг: {table}[{old_id}] -> {new_id}")

    def get_new_id(self, table, old_id):
        return self.mappings.get(table, {}).get(old_id)


def load_existing_mappings(pg_conn, id_mapper):
    """
    Загружает уже существующие маппинги из таблицы id_mappings в объект IdMapper.
    """
    logger.info("Загрузка существующих маппингов из id_mappings")
    try:
        with pg_conn.cursor() as cur:
            cur.execute("SELECT table_name, old_id, new_id FROM id_mappings")
            rows = cur.fetchall()
            for table_name, old_id, new_id in rows:
                id_mapper.add_mapping(table_name, old_id, new_id)
        logger.info(f"Загружено маппингов: {sum(len(v) for v in id_mapper.mappings.values())}")
    except Exception as e:
        logger.error(f"Ошибка загрузки маппингов: {e}")
        raise


def update_id_mappings(pg_conn, id_mapper):
    """
    Обновляет (дополняет) таблицу id_mappings новыми соотношениями.
    """
    logger.info("Обновление таблицы id_mappings")
    try:
        with pg_conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS id_mappings (
                    table_name TEXT,
                    old_id INTEGER,
                    new_id INTEGER
                )
            """)
            pg_conn.commit()
            cur.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'id_mappings_pk'
                    ) THEN
                        ALTER TABLE id_mappings
                        ADD CONSTRAINT id_mappings_pk PRIMARY KEY (table_name, old_id);
                    END IF;
                END $$;
            """)
            pg_conn.commit()
            for table_name, mapping in id_mapper.mappings.items():
                if not mapping:
                    continue
                data = [(table_name, old_id, new_id) for old_id, new_id in mapping.items()]
                execute_values(
                    cur,
                    """
                    INSERT INTO id_mappings (table_name, old_id, new_id)
                    VALUES %s
                    ON CONFLICT (table_name, old_id) DO NOTHING
                    """,
                    data,
                    template="(%s, %s, %s)",
                    page_size=1000
                )
            pg_conn.commit()
            logger.info("Таблица id_mappings успешно обновлена")
    except Exception as e:
        pg_conn.rollback()
        logger.error(f"Ошибка обновления id_mappings: {e}")
        raise


def setup_postgres_schemas(conn):
    """
    Создаёт временную схему staging и необходимые таблицы в ней.
    """
    logger.info("Настройка временной схемы PostgreSQL (staging)")
    try:
        with conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS staging CASCADE")
            cur.execute("CREATE SCHEMA staging")
            staging_tables = [
                """CREATE TABLE staging.projects (
                    old_id INTEGER PRIMARY KEY,
                    name TEXT,
                    rls_ref INTEGER,
                    description TEXT,
                    vendor TEXT,
                    arc_ref INTEGER
                )""",
                """CREATE TABLE staging.assemblies (
                    old_id INTEGER PRIMARY KEY,
                    time INTEGER,
                    description TEXT,
                    prj_ref INTEGER,
                    pbr_ref INTEGER
                )""",
                """CREATE TABLE staging.src_packages (
                    old_id INTEGER PRIMARY KEY,
                    name TEXT
                )""",
                """CREATE TABLE staging.pkg_versions (
                    old_id INTEGER PRIMARY KEY,
                    time INTEGER,
                    maintainer TEXT,
                    src_pkg_ref INTEGER,
                    version TEXT
                )""",
                """CREATE TABLE staging.asm_pkg_vsn_lnk (
                    asm_ref INTEGER,
                    pkg_vsn_ref INTEGER
                )""",
                """CREATE TABLE staging.changes (
                    old_id INTEGER PRIMARY KEY,
                    pkg_vsn_ref INTEGER,
                    special TEXT
                )""",
                """CREATE TABLE staging.urgency (
                    old_id INTEGER PRIMARY KEY,
                    name TEXT
                )""",
                """CREATE TABLE staging.vulnerabilities (
                    old_id INTEGER PRIMARY KEY,
                    name TEXT
                )""",
                """CREATE TABLE staging.chg_vln_lnk (
                    chg_ref INTEGER,
                    vln_ref INTEGER
                )""",
                """CREATE TABLE staging.publishers (
                    old_id INTEGER PRIMARY KEY,
                    name TEXT
                )"""
            ]
            for table_sql in staging_tables:
                logger.debug(f"Создание временной таблицы: {table_sql.split('(')[0]} ...")
                cur.execute(table_sql)
            indexes = [
                "CREATE INDEX idx_staging_projects ON staging.projects (old_id)",
                "CREATE INDEX idx_staging_assemblies_prj_ref ON staging.assemblies (prj_ref)",
                "CREATE INDEX idx_staging_pkg_versions_src ON staging.pkg_versions (src_pkg_ref)",
                "CREATE INDEX idx_staging_asm_lnk ON staging.asm_pkg_vsn_lnk (asm_ref, pkg_vsn_ref)",
                "CREATE INDEX idx_staging_chg_vln ON staging.chg_vln_lnk (chg_ref, vln_ref)"
            ]
            for index_sql in indexes:
                logger.debug(f"Создание индекса: {index_sql}")
                cur.execute(index_sql)
            conn.commit()
            logger.info("Временная схема staging создана успешно")
    except Exception as e:
        conn.rollback()
        logger.error(f"Ошибка при создании временной схемы: {e}")
        raise


def migrate_to_staging(sqlite_conn, pg_conn):
    """
    Перенос данных из SQLite в схему staging в PostgreSQL.
    """
    logger.info("Начало миграции данных в staging")
    id_mapper = IdMapper()
    try:
        sql_cur = sqlite_conn.cursor()
        pg_cur = pg_conn.cursor()
        # publishers
        logger.info("Перенос publishers...")
        sql_cur.execute("SELECT id, name FROM publishers")
        publishers = sql_cur.fetchall()
        if publishers:
            execute_batch(pg_cur,
                          "INSERT INTO staging.publishers (old_id, name) VALUES (%s, %s)",
                          publishers)
            logger.info(f"Перенесено publishers: {len(publishers)}")
        else:
            logger.warning("Таблица publishers пуста")
        # projects (с объединением с publishers)
        logger.info("Перенос projects...")
        sql_cur.execute("""
            SELECT p.id, p.name, p.rls_ref, p.description, pub.name, p.arc_ref 
            FROM projects p
            JOIN publishers pub ON p.pbr_ref = pub.id
        """)
        projects = sql_cur.fetchall()
        if projects:
            execute_batch(pg_cur,
                          """INSERT INTO staging.projects 
                             (old_id, name, rls_ref, description, vendor, arc_ref)
                             VALUES (%s, %s, %s, %s, %s, %s)""",
                          projects)
            logger.info(f"Перенесено projects: {len(projects)}")
        else:
            logger.warning("Таблица projects пуста")
        # assemblies
        logger.info("Перенос assemblies...")
        sql_cur.execute("SELECT id, time, description, prj_ref, pbr_ref FROM assemblies")
        assemblies = sql_cur.fetchall()
        if assemblies:
            execute_batch(pg_cur,
                          """INSERT INTO staging.assemblies 
                             (old_id, time, description, prj_ref, pbr_ref)
                             VALUES (%s, %s, %s, %s, %s)""",
                          assemblies)
            logger.info(f"Перенесено assemblies: {len(assemblies)}")
        else:
            logger.warning("Таблица assemblies пуста")
        # src_packages
        logger.info("Перенос src_packages...")
        sql_cur.execute("SELECT id, name FROM src_packages")
        packages = sql_cur.fetchall()
        if packages:
            execute_batch(pg_cur,
                          "INSERT INTO staging.src_packages (old_id, name) VALUES (%s, %s)",
                          packages)
            logger.info(f"Перенесено src_packages: {len(packages)}")
        else:
            logger.warning("Таблица src_packages пуста")
        # pkg_versions
        logger.info("Перенос pkg_versions...")
        sql_cur.execute("SELECT id, time, maintainer, src_pkg_ref, version FROM pkg_versions")
        versions = sql_cur.fetchall()
        if versions:
            execute_batch(pg_cur,
                          """INSERT INTO staging.pkg_versions 
                             (old_id, time, maintainer, src_pkg_ref, version)
                             VALUES (%s, %s, %s, %s, %s)""",
                          versions)
            logger.info(f"Перенесено pkg_versions: {len(versions)}")
        else:
            logger.warning("Таблица pkg_versions пуста")
        # asm_pkg_vsn_lnk
        logger.info("Перенос asm_pkg_vsn_lnk...")
        sql_cur.execute("SELECT asm_ref, pkg_vsn_ref FROM asm_pkg_vsn_lnk")
        links = sql_cur.fetchall()
        if links:
            execute_batch(pg_cur,
                          "INSERT INTO staging.asm_pkg_vsn_lnk (asm_ref, pkg_vsn_ref) VALUES (%s, %s)",
                          links)
            logger.info(f"Перенесено связей asm_pkg_vsn_lnk: {len(links)}")
        else:
            logger.warning("Таблица asm_pkg_vsn_lnk пуста")
        # changes
        logger.info("Перенос changes...")
        sql_cur.execute("SELECT id, pkg_vsn_ref, special FROM changes")
        changes = sql_cur.fetchall()
        if changes:
            execute_batch(pg_cur,
                          "INSERT INTO staging.changes (old_id, pkg_vsn_ref, special) VALUES (%s, %s, %s)",
                          changes)
            logger.info(f"Перенесено changes: {len(changes)}")
        else:
            logger.warning("Таблица changes пуста")
        # urgency
        logger.info("Перенос urgency...")
        sql_cur.execute("SELECT id, name FROM urgency")
        urgency = sql_cur.fetchall()
        if urgency:
            execute_batch(pg_cur,
                          "INSERT INTO staging.urgency (old_id, name) VALUES (%s, %s)",
                          urgency)
            logger.info(f"Перенесено urgency: {len(urgency)}")
        else:
            logger.warning("Таблица urgency пуста")
        # vulnerabilities
        logger.info("Перенос vulnerabilities...")
        sql_cur.execute("SELECT id, name FROM vulnerabilities")
        vulns = sql_cur.fetchall()
        if vulns:
            execute_batch(pg_cur,
                          "INSERT INTO staging.vulnerabilities (old_id, name) VALUES (%s, %s)",
                          vulns)
            logger.info(f"Перенесено vulnerabilities: {len(vulns)}")
        else:
            logger.warning("Таблица vulnerabilities пуста")
        # chg_vln_lnk
        logger.info("Перенос chg_vln_lnk...")
        sql_cur.execute("SELECT chg_ref, vln_ref FROM chg_vln_lnk")
        chg_vln = sql_cur.fetchall()
        if chg_vln:
            execute_batch(pg_cur,
                          "INSERT INTO staging.chg_vln_lnk (chg_ref, vln_ref) VALUES (%s, %s)",
                          chg_vln)
            logger.info(f"Перенесено связей chg_vln_lnk: {len(chg_vln)}")
        else:
            logger.warning("Таблица chg_vln_lnk пуста")
        pg_conn.commit()
        logger.info("Миграция в staging завершена успешно")
        return id_mapper
    except Exception as e:
        pg_conn.rollback()
        logger.error(f"Ошибка миграции в staging: {e}")
        raise


def process_staging_data(pg_conn, id_mapper):
    """
    Обработка данных из staging и перенос в основные таблицы.
    """
    logger.info("Начало обработки данных из staging")
    try:
        with pg_conn.cursor() as cur:
            # 1. Обработка projects
            logger.info("Обработка проектов (projects) – вставляем только новые записи")
            cur.execute("""
                SELECT s.old_id
                FROM staging.projects s
                LEFT JOIN id_mappings m ON s.old_id = m.old_id AND m.table_name = 'projects'
                WHERE m.old_id IS NULL
                ORDER BY s.old_id
            """)
            new_old_ids = [row[0] for row in cur.fetchall()]
            if new_old_ids:
                cur.execute("""
                    WITH new_data AS (
                        SELECT s.old_id,
                               COALESCE(s.name, 'unknown') AS prj_name,
                               NULLIF(s.rls_ref, 0) AS rel_id,
                               s.description AS prj_desc,
                               COALESCE(s.vendor, 'unknown') AS vendor,
                               NULLIF(s.arc_ref, 0) AS arch_id
                        FROM staging.projects s
                        WHERE s.old_id = ANY(%s)
                        ORDER BY s.old_id
                    )
                    INSERT INTO repositories.project (prj_name, rel_id, prj_desc, vendor, arch_id)
                    SELECT prj_name, rel_id, prj_desc, vendor, arch_id
                    FROM new_data
                    RETURNING prj_id
                """, (new_old_ids,))
                new_project_ids = [row[0] for row in cur.fetchall()]
                for old_id, new_id in zip(new_old_ids, new_project_ids):
                    id_mapper.add_mapping('projects', old_id, new_id)
                logger.info(f"Обработано новых проектов: {len(new_project_ids)}")
                update_id_mappings(pg_conn, id_mapper)
            else:
                logger.info("Новых проектов для обработки нет")

            # 2. Обработка assemblies
            logger.info("Обработка сборок (assemblies) – вставляем только новые записи")
            cur.execute("""
                WITH assemblies_data AS (
                    SELECT a.old_id,
                           COALESCE(to_timestamp(NULLIF(a.time, 0)), NOW()) AS assm_date_created,
                           COALESCE(a.description, 'No description') AS description,
                           m_proj.new_id AS prj_id
                    FROM staging.assemblies a
                    INNER JOIN id_mappings m_proj ON a.prj_ref = m_proj.old_id AND m_proj.table_name = 'projects'
                    LEFT JOIN id_mappings m_asm ON a.old_id = m_asm.old_id AND m_asm.table_name = 'assemblies'
                    WHERE m_asm.old_id IS NULL
                ),
                inserted_assemblies AS (
                    INSERT INTO repositories.assembly (assm_date_created, assm_desc, prj_id, assm_version)
                    SELECT assm_date_created, description, prj_id, ' '
                    FROM assemblies_data
                    RETURNING assm_id, prj_id, assm_date_created, assm_desc
                )
                SELECT ia.assm_id, ad.old_id
                FROM inserted_assemblies ia
                JOIN assemblies_data ad
                  ON ia.prj_id = ad.prj_id
                 AND ia.assm_date_created = ad.assm_date_created
                 AND ia.assm_desc = ad.description
            """)
            assemblies_mapping = cur.fetchall()
            for new_id, old_id in assemblies_mapping:
                id_mapper.add_mapping('assemblies', old_id, new_id)
            logger.info(f"Обработано новых сборок: {len(assemblies_mapping)}")
            update_id_mappings(pg_conn, id_mapper)

            # 3. Обработка src_packages
            logger.info("Обработка исходных пакетов (src_packages) – вставляем только новые записи")
            cur.execute("""
                SELECT s.old_id, s.name
                FROM staging.src_packages s
                LEFT JOIN id_mappings m ON s.old_id = m.old_id AND m.table_name = 'src_packages'
                WHERE s.name IS NOT NULL AND m.old_id IS NULL
                ORDER BY s.old_id
            """)
            new_src = cur.fetchall()
            if new_src:
                for old_id, pkg_name in new_src:
                    cur.execute("""
                        INSERT INTO repositories.package (pkg_name)
                        VALUES (%s)
                        ON CONFLICT (pkg_name) DO UPDATE SET pkg_name = EXCLUDED.pkg_name
                        RETURNING pkg_id
                    """, (pkg_name,))
                    pkg_id = cur.fetchone()[0]
                    id_mapper.add_mapping('src_packages', old_id, pkg_id)
                logger.info(f"Обработано новых src_packages: {len(new_src)}")
                update_id_mappings(pg_conn, id_mapper)
            else:
                logger.info("Новых src_packages для обработки нет")

            # 4. Обработка pkg_versions – обрабатываем по одной записи, чтобы избежать блокировок
            logger.info("Обработка версий пакетов (pkg_versions) – вставляем только новые записи")
            cur.execute("""
                SELECT pv.old_id, pv.time, pv.maintainer, pv.src_pkg_ref, pv.version
                FROM staging.pkg_versions pv
                LEFT JOIN id_mappings m_ver ON pv.old_id = m_ver.old_id AND m_ver.table_name = 'pkg_versions'
                WHERE m_ver.old_id IS NULL
                ORDER BY pv.old_id
            """)
            new_versions = cur.fetchall()
            processed_versions = 0
            if new_versions:
                for old_id, time_val, maintainer, src_pkg_ref, version in new_versions:
                    pkg_id = id_mapper.get_new_id('src_packages', src_pkg_ref)
                    if pkg_id is None:
                        logger.error(f"Для pkg_versions с old_id {old_id}: не найден mapping для src_pkg_ref {src_pkg_ref}")
                        continue
                    cur.execute("""
                        INSERT INTO repositories.pkg_version (pkg_date_created, author_name, pkg_id, version)
                        VALUES (
                            COALESCE(to_timestamp(NULLIF(%s, 0)), NOW()),
                            NULLIF(%s, ''),
                            %s,
                            COALESCE(NULLIF(%s, ''), '0.0.0')
                        )
                        ON CONFLICT (version, pkg_id) DO NOTHING
                        RETURNING pkg_vrs_id
                    """, (time_val, maintainer, pkg_id, version))
                    res = cur.fetchone()
                    if res is None:
                        cur.execute("""
                            SELECT pkg_vrs_id FROM repositories.pkg_version
                            WHERE pkg_id = %s AND version = COALESCE(NULLIF(%s, ''), '0.0.0')
                        """, (pkg_id, version))
                        res = cur.fetchone()
                    if res:
                        pkg_vrs_id = res[0]
                        id_mapper.add_mapping('pkg_versions', old_id, pkg_vrs_id)
                        processed_versions += 1
                logger.info(f"Обработано новых pkg_versions: {processed_versions}")
                update_id_mappings(pg_conn, id_mapper)
            else:
                logger.info("Новых pkg_versions для обработки нет")

            # 5. Обработка urgency
            logger.info("Обработка urgency – вставляем только новые записи")
            cur.execute("""
                SELECT s.old_id, s.name
                FROM staging.urgency s
                LEFT JOIN id_mappings m ON s.old_id = m.old_id AND m.table_name = 'urgency'
                WHERE s.name IS NOT NULL AND m.old_id IS NULL
                ORDER BY s.old_id
            """)
            new_urg = cur.fetchall()
            if new_urg:
                new_urg_old_ids = [row[0] for row in new_urg]
                cur.execute("""
                    WITH new_data AS (
                        SELECT s.old_id, s.name AS urg_name
                        FROM staging.urgency s
                        WHERE s.old_id = ANY(%s)
                        ORDER BY s.old_id
                    )
                    INSERT INTO repositories.urgency (urg_name)
                    SELECT urg_name
                    FROM new_data
                    RETURNING urg_id
                """, (new_urg_old_ids,))
                new_urg_ids = [row[0] for row in cur.fetchall()]
                for old_id, new_id in zip(new_urg_old_ids, new_urg_ids):
                    id_mapper.add_mapping('urgency', old_id, new_id)
                logger.info(f"Обработано новых urgency: {len(new_urg_ids)}")
                update_id_mappings(pg_conn, id_mapper)
            else:
                logger.info("Новых urgency для обработки нет")

            # 6. Обработка vulnerabilities
            logger.info("Обработка vulnerabilities – вставляем только новые записи")
            cur.execute("""
                SELECT s.old_id, s.name
                FROM staging.vulnerabilities s
                LEFT JOIN id_mappings m ON s.old_id = m.old_id AND m.table_name = 'vulnerabilities'
                WHERE s.name IS NOT NULL AND m.old_id IS NULL
                ORDER BY s.old_id
            """)
            new_vuln = cur.fetchall()
            if new_vuln:
                new_vuln_old_ids = [row[0] for row in new_vuln]
                cur.execute("""
                    WITH new_data AS (
                        SELECT s.old_id, s.name AS vuln_name
                        FROM staging.vulnerabilities s
                        WHERE s.old_id = ANY(%s)
                        ORDER BY s.old_id
                    )
                    INSERT INTO repositories.vulnerabilities (name)
                    SELECT vuln_name
                    FROM new_data
                    RETURNING id
                """, (new_vuln_old_ids,))
                new_vuln_ids = [row[0] for row in cur.fetchall()]
                for old_id, new_id in zip(new_vuln_old_ids, new_vuln_ids):
                    id_mapper.add_mapping('vulnerabilities', old_id, new_id)
                logger.info(f"Обработано новых vulnerabilities: {len(new_vuln_ids)}")
                update_id_mappings(pg_conn, id_mapper)
            else:
                logger.info("Новых vulnerabilities для обработки нет")

            # 7. Обработка связей assembly-package
            logger.info("Обработка связей assembly-package")
            cur.execute("""
                INSERT INTO repositories.assm_pkg_vrs (assm_id, pkg_vrs_id)
                SELECT a.new_id, p.new_id
                FROM staging.asm_pkg_vsn_lnk l
                JOIN id_mappings a ON l.asm_ref = a.old_id AND a.table_name = 'assemblies'
                JOIN id_mappings p ON l.pkg_vsn_ref = p.old_id AND p.table_name = 'pkg_versions'
                WHERE NOT EXISTS (
                    SELECT 1 FROM repositories.assm_pkg_vrs ap
                    WHERE ap.assm_id = a.new_id AND ap.pkg_vrs_id = p.new_id
                )
            """)
            logger.info(f"Добавлено связей assembly-package: {cur.rowcount}")

            # 8. Обработка changelog (changes)
            logger.info("Обработка changelog (changes) – вставляем только новые записи")
            cur.execute("""
                SELECT c.old_id, c.special, pv.time, p.new_id
                FROM staging.changes c
                INNER JOIN id_mappings p ON c.pkg_vsn_ref = p.old_id AND p.table_name = 'pkg_versions'
                LEFT JOIN id_mappings m ON c.old_id = m.old_id AND m.table_name = 'changes'
                JOIN staging.pkg_versions pv ON c.pkg_vsn_ref = pv.old_id
                WHERE m.old_id IS NULL
            """)
            changes_to_process = cur.fetchall()
            processed_changes = 0
            for old_id, special, time_val, pkg_vrs_new_id in changes_to_process:
                log_desc = special if special is not None else ''
                cur.execute("""
                    INSERT INTO repositories.changelog (log_desc, pkg_vrs_id, date_added, log_ident)
                    VALUES (%s, %s, COALESCE(to_timestamp(NULLIF(%s, 0)), NOW()), '')
                    RETURNING id
                """, (log_desc, pkg_vrs_new_id, time_val))
                result = cur.fetchone()
                if result:
                    new_chg_id = result[0]
                    id_mapper.add_mapping('changes', old_id, new_chg_id)
                    processed_changes += 1
            logger.info(f"Обработано новых записей changelog: {processed_changes}")
            update_id_mappings(pg_conn, id_mapper)

            pg_conn.commit()
            logger.info("Обработка данных успешно завершена")
    except Exception as e:
        pg_conn.rollback()
        logger.error(f"Ошибка обработки данных: {e}", exc_info=True)
        raise


def main():
    pg_conn = None
    sqlite_conn = None
    try:
        logger.info("=== НАЧАЛО МИГРАЦИИ (инкрементальная) ===")
        logger.info(f"Подключение к SQLite: {SQLITE_DB}")
        sqlite_conn = sqlite3.connect(SQLITE_DB)
        logger.info("Подключение к PostgreSQL")
        pg_conn = psycopg2.connect(**POSTGRES_CONFIG)
        pg_conn.autocommit = False
        logger.info("Инициализация временной схемы (staging)")
        setup_postgres_schemas(pg_conn)
        id_mapper = IdMapper()
        load_existing_mappings(pg_conn, id_mapper)
        logger.info("Этап 1: Перенос данных в staging")
        id_mapper = migrate_to_staging(sqlite_conn, pg_conn)
        logger.info("Этап 2: Обработка данных из staging и перенос в основную схему")
        process_staging_data(pg_conn, id_mapper)
        logger.info("=== МИГРАЦИЯ ЗАВЕРШЕНА УСПЕШНО ===")
    except Exception as e:
        logger.error(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
        sys.exit(1)
    finally:
        logger.info("Начало очистки временной схемы (staging)")
        if pg_conn:
            try:
                with pg_conn.cursor() as cur:
                    cur.execute("DROP SCHEMA IF EXISTS staging CASCADE")
                pg_conn.commit()
                logger.info("Временная схема staging успешно удалена")
            except Exception as cleanup_error:
                logger.error(f"Ошибка при удалении временной схемы: {cleanup_error}", exc_info=True)
            finally:
                pg_conn.close()
                logger.info("Соединение с PostgreSQL закрыто")
        if sqlite_conn:
            sqlite_conn.close()
            logger.info("Соединение с SQLite закрыто")


if __name__ == "__main__":
    main()
