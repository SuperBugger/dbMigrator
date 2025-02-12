import sqlite3
import psycopg2
from datetime import datetime, timezone
from psycopg2.extras import execute_batch, execute_values
import logging
import sys

# Конфигурация
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
        logging.FileHandler("migration_full.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class IdMapper:
    def __init__(self):
        self.mappings = {
            'projects': {}, 'assemblies': {}, 'src_packages': {},
            'pkg_versions': {}, 'urgency': {}, 'vulnerabilities': {},
            'publishers': {}, 'changes': {}
        }
        logger.debug("Инициализация IdMapper")

    def add_mapping(self, table, old_id, new_id):
        self.mappings[table][old_id] = new_id
        logger.debug(f"Добавлен маппинг: {table}[{old_id}] -> {new_id}")

    def get_new_id(self, table, old_id):
        return self.mappings[table].get(old_id)


def create_id_mappings(pg_conn, id_mapper):
    """Переносит данные из IdMapper в SQL-таблицу id_mappings"""
    with pg_conn.cursor() as cur:
        # Очищаем таблицу перед заполнением (опционально)
        cur.execute("TRUNCATE public.id_mappings")

        # Для каждой таблицы в IdMapper
        for table_name in id_mapper.mappings:
            mappings = id_mapper.mappings[table_name]
            if not mappings:
                continue

            # Подготавливаем данные для вставки
            data = [(table_name, old_id, new_id) for old_id, new_id in mappings.items()]

            # Пакетная вставка
            execute_values(
                cur,
                "INSERT INTO public.id_mappings (table_name, old_id, new_id) VALUES %s",
                data,
                template="(%s, %s, %s)",
                page_size=5000
            )
        pg_conn.commit()

def setup_postgres_schemas(conn):
    """Создание временной схемы и таблиц"""
    logger.info("Настройка временной схемы PostgreSQL")
    with conn.cursor() as cur:
        try:
            cur.execute("DROP SCHEMA IF EXISTS staging CASCADE")
            cur.execute("CREATE SCHEMA staging")

            staging_tables = [
                """CREATE TABLE staging.projects (
                    old_id INTEGER PRIMARY KEY,
                    name TEXT,
                    rls_ref INTEGER,
                    description TEXT,
                    vendor TEXT,
                    arc_ref INTEGER)""",

                """CREATE TABLE staging.assemblies (
                    old_id INTEGER PRIMARY KEY,
                    time INTEGER,
                    description TEXT,
                    prj_ref INTEGER,
                    pbr_ref INTEGER)""",

                """CREATE TABLE staging.src_packages (
                    old_id INTEGER PRIMARY KEY,
                    name TEXT)""",

                """CREATE TABLE staging.pkg_versions (
                    old_id INTEGER PRIMARY KEY,
                    time INTEGER,
                    maintainer TEXT,
                    src_pkg_ref INTEGER,
                    version TEXT)""",

                """CREATE TABLE staging.asm_pkg_vsn_lnk (
                    asm_ref INTEGER,
                    pkg_vsn_ref INTEGER)""",

                """CREATE TABLE staging.changes (
                    old_id INTEGER PRIMARY KEY,
                    pkg_vsn_ref INTEGER,
                    special TEXT)""",

                """CREATE TABLE staging.urgency (
                    old_id INTEGER PRIMARY KEY,
                    name TEXT)""",

                """CREATE TABLE staging.vulnerabilities (
                    old_id INTEGER PRIMARY KEY,
                    name TEXT)""",

                """CREATE TABLE staging.chg_vln_lnk (
                    chg_ref INTEGER,
                    vln_ref INTEGER)""",

                """CREATE TABLE staging.publishers (
                    old_id INTEGER PRIMARY KEY,
                    name TEXT)"""
            ]

            for table in staging_tables:
                logger.debug(f"Создание временной таблицы: {table[:60]}...")
                cur.execute(table)

            indexes = [
                "CREATE INDEX idx_staging_projects ON staging.projects (old_id)",
                "CREATE INDEX idx_staging_assemblies_prj_ref ON staging.assemblies (prj_ref)",
                "CREATE INDEX idx_staging_pkg_versions_src ON staging.pkg_versions (src_pkg_ref)",
                "CREATE INDEX idx_staging_asm_lnk ON staging.asm_pkg_vsn_lnk (asm_ref, pkg_vsn_ref)",
                "CREATE INDEX idx_staging_chg_vln ON staging.chg_vln_lnk (chg_ref, vln_ref)"
            ]

            for index in indexes:
                logger.debug(f"Создание индекса: {index}")
                cur.execute(index)

            conn.commit()
            logger.info("Временная схема создана успешно")

        except Exception as e:
            conn.rollback()
            logger.error(f"Ошибка при создании временной схемы: {e}")
            raise


def migrate_to_staging(sqlite_conn, pg_conn):
    """Перенос данных из SQLite во временную схему staging"""
    logger.info("Начало миграции в staging")
    id_mapper = IdMapper()

    try:
        sql_cur = sqlite_conn.cursor()
        pg_cur = pg_conn.cursor()

        # Миграция publishers
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

        # Миграция projects
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

        # Миграция assemblies
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

        # Миграция src_packages
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

        # Миграция pkg_versions
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

        # Миграция asm_pkg_vsn_lnk
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

        # Миграция changes
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

        # Миграция urgency
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

        # Миграция vulnerabilities
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

        # Миграция chg_vln_lnk
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


def create_id_mappings(pg_conn, id_mapper):
    logger.info("Создание таблицы маппинга ID")
    try:
        with pg_conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS id_mappings")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS id_mappings (
                    table_name TEXT,
                    old_id INTEGER,
                    new_id INTEGER
                )
            """)

            tables = [
                ('projects', id_mapper.mappings['projects']),
                ('assemblies', id_mapper.mappings['assemblies']),
                ('src_packages', id_mapper.mappings['src_packages']),
                ('pkg_versions', id_mapper.mappings['pkg_versions']),
                ('changes', id_mapper.mappings['changes']),
                ('urgency', id_mapper.mappings['urgency']),
                ('vulnerabilities', id_mapper.mappings['vulnerabilities'])
            ]

            for table_name, mapping in tables:
                if mapping:
                    data = [(table_name, old_id, new_id) for old_id, new_id in mapping.items()]
                    execute_values(
                        cur,
                        "INSERT INTO id_mappings VALUES %s",
                        data,
                        template="(%s, %s, %s)",
                        page_size=1000
                    )
            pg_conn.commit()

    except Exception as e:
        pg_conn.rollback()
        logger.error(f"Ошибка создания маппингов: {e}")
        raise


def process_staging_data(pg_conn, id_mapper):
    """Обработка данных и перенос в основную схему"""
    logger.info("Начало обработки данных staging")
    try:
        with pg_conn.cursor() as cur:
            # Проверка целостности данных
            logger.info("Проверка целостности данных...")

            cur.execute("SELECT COUNT(*) FROM staging.assemblies")
            logger.info(f"Записей в staging.assemblies: {cur.fetchone()[0]}")

            cur.execute("SELECT COUNT(*) FROM staging.pkg_versions")
            logger.info(f"Записей в staging.pkg_versions: {cur.fetchone()[0]}")

            # 1. Проверка проектов
            cur.execute("""
                SELECT COUNT(DISTINCT prj_ref) 
                FROM staging.assemblies 
                WHERE prj_ref NOT IN (
                    SELECT old_id FROM staging.projects
                )
            """)
            invalid_projects = cur.fetchone()[0]
            logger.warning(f"assemblies с несуществующими проектами: {invalid_projects}")

            # 2. Проверка пакетов
            cur.execute("""
                SELECT COUNT(DISTINCT src_pkg_ref) 
                FROM staging.pkg_versions 
                WHERE src_pkg_ref NOT IN (
                    SELECT old_id FROM staging.src_packages
                )
            """)
            invalid_packages = cur.fetchone()[0]
            logger.warning(f"pkg_versions с несуществующими пакетами: {invalid_packages}")

            # Основная обработка данных
            # Обработка projects
            logger.info("Обработка projects...")
            cur.execute("""
                INSERT INTO repositories.project 
                (prj_name, rel_id, prj_desc, vendor, arch_id)
                SELECT 
                    COALESCE(name, 'unknown'),
                    NULLIF(rls_ref, 0),
                    description,
                    COALESCE(vendor, 'unknown'),
                    NULLIF(arc_ref, 0)
                FROM staging.projects
                RETURNING prj_id
            """)
            new_projects = cur.fetchall()
            new_project_ids = [row[0] for row in new_projects]

            cur.execute("SELECT old_id FROM staging.projects ORDER BY old_id")
            old_project_ids = [row[0] for row in cur.fetchall()]

            for old_id, new_id in zip(old_project_ids, new_project_ids):
                id_mapper.add_mapping('projects', old_id, new_id)
            logger.info(f"Обработано projects: {len(new_project_ids)}")
            # Вставка маппингов в id_mappings
            create_id_mappings(pg_conn, id_mapper)

            # Обработка assemblies
            logger.info("Обработка assemblies...")
            cur.execute("""
                WITH 
                assemblies_data AS (
                    SELECT 
                        a.old_id,
                        COALESCE(to_timestamp(NULLIF(a.time, 0)), NOW()) AS assm_date_created,
                        COALESCE(a.description, 'No description') AS description,
                        m.new_id AS prj_id
                    FROM staging.assemblies a
                    INNER JOIN id_mappings m 
                        ON a.prj_ref = m.old_id 
                        AND m.table_name = 'projects'
                ),
                inserted_assemblies AS (
                    INSERT INTO repositories.assembly 
                        (assm_date_created, assm_desc, prj_id, assm_version)
                    SELECT 
                        assm_date_created,
                        description,
                        prj_id,
                        ' '
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
            logger.info(f"Обработано assemblies: {len(assemblies_mapping)}")

            # Вставка маппингов в id_mappings
            create_id_mappings(pg_conn, id_mapper)

            logger.debug(f"Маппинг assemblies: {id_mapper.mappings['assemblies']}")

            cur.execute("SELECT old_id, prj_ref, time FROM staging.assemblies LIMIT 10")
            logger.debug(f"Примеры assemblies: {cur.fetchall()}")

            cur.execute("""
                SELECT old_id, time 
                FROM staging.assemblies 
                WHERE time = 0 OR time IS NULL 
                LIMIT 5
            """)
            logger.warning(f"Записи с time=0 или NULL: {cur.fetchall()}")


            # Обработка src_packages
            logger.info("Обработка src_packages...")
            cur.execute("""
                INSERT INTO repositories.package (pkg_name)
                SELECT DISTINCT COALESCE(name, 'unnamed_package')
                FROM staging.src_packages
                WHERE name IS NOT NULL
                RETURNING pkg_id
            """)
            new_packages = cur.fetchall()
            new_package_ids = [row[0] for row in new_packages]

            cur.execute("SELECT old_id FROM staging.src_packages ORDER BY old_id")
            old_package_ids = [row[0] for row in cur.fetchall()]

            for old_id, new_id in zip(old_package_ids, new_package_ids):
                id_mapper.add_mapping('src_packages', old_id, new_id)
            logger.info(f"Обработано src_packages: {len(new_package_ids)}")
            # Вставка маппингов в id_mappings
            create_id_mappings(pg_conn, id_mapper)

            # Обработка pkg_versions
            logger.info("Обработка pkg_versions...")
            cur.execute("""
                WITH 
                versions_data AS (
                    SELECT
                        pv.old_id,
                        COALESCE(to_timestamp(NULLIF(pv.time, 0)), NOW()) AS pkg_date_created,
                        NULLIF(pv.maintainer, '') AS author_name,
                        m.new_id AS pkg_id,
                        COALESCE(NULLIF(pv.version, ''), '0.0.0') AS version
                    FROM staging.pkg_versions pv
                    INNER JOIN id_mappings m 
                        ON pv.src_pkg_ref = m.old_id 
                        AND m.table_name = 'src_packages'
                ),
                inserted_versions AS (
                    INSERT INTO repositories.pkg_version 
                        (pkg_date_created, author_name, pkg_id, version)
                    SELECT 
                        pkg_date_created,
                        author_name,
                        pkg_id,
                        version
                    FROM versions_data
                    RETURNING pkg_vrs_id, pkg_date_created, author_name, pkg_id, version
                )
                SELECT iv.pkg_vrs_id, vd.old_id
                FROM inserted_versions iv
                JOIN versions_data vd 
                    ON iv.pkg_date_created = vd.pkg_date_created
                    AND iv.author_name = vd.author_name
                    AND iv.pkg_id = vd.pkg_id
                    AND iv.version = vd.version
            """)

            versions_mapping = cur.fetchall()
            for new_id, old_id in versions_mapping:
                id_mapper.add_mapping('pkg_versions', old_id, new_id)
            logger.info(f"Обработано pkg_versions: {len(versions_mapping)}")
            # Вставка маппингов в id_mappings
            create_id_mappings(pg_conn, id_mapper)
            logger.debug(f"Маппинг pkg_versions: {id_mapper.mappings['pkg_versions']}")

            # Обработка urgency
            logger.info("Обработка urgency...")
            cur.execute("""
                INSERT INTO repositories.urgency (urg_name)
                SELECT DISTINCT COALESCE(name, 'unknown')
                FROM staging.urgency
                WHERE name IS NOT NULL
                RETURNING urg_id
            """)
            new_urgency_ids = [row[0] for row in cur.fetchall()]

            cur.execute("SELECT old_id FROM staging.urgency ORDER BY old_id")
            old_urgency_ids = [row[0] for row in cur.fetchall()]

            for old_id, new_id in zip(old_urgency_ids, new_urgency_ids):
                id_mapper.add_mapping('urgency', old_id, new_id)
            logger.info(f"Обработано urgency: {len(new_urgency_ids)}")

            # Вставка маппингов в id_mappings
            create_id_mappings(pg_conn, id_mapper)

            # Обработка vulnerabilities
            logger.info("Обработка vulnerabilities...")
            cur.execute("""
                INSERT INTO repositories.vulnerabilities (name)
                SELECT DISTINCT COALESCE(name, 'unnamed_vulnerability')
                FROM staging.vulnerabilities
                WHERE name IS NOT NULL
                RETURNING id
            """)
            new_vuln_ids = [row[0] for row in cur.fetchall()]

            cur.execute("SELECT old_id FROM staging.vulnerabilities ORDER BY old_id")
            old_vuln_ids = [row[0] for row in cur.fetchall()]

            for old_id, new_id in zip(old_vuln_ids, new_vuln_ids):
                id_mapper.add_mapping('vulnerabilities', old_id, new_id)
            logger.info(f"Обработано vulnerabilities: {len(new_vuln_ids)}")

            # Вставка маппингов в id_mappings
            create_id_mappings(pg_conn, id_mapper)

            # Обработка связей assembly-package
            logger.info("Обработка связей assembly-package...")
            cur.execute("""
                INSERT INTO repositories.assm_pkg_vrs (assm_id, pkg_vrs_id)
                SELECT 
                    a.new_id,
                    p.new_id
                FROM staging.asm_pkg_vsn_lnk l
                JOIN id_mappings a 
                    ON l.asm_ref = a.old_id 
                    AND a.table_name = 'assemblies'
                JOIN id_mappings p 
                    ON l.pkg_vsn_ref = p.old_id 
                    AND p.table_name = 'pkg_versions'
                WHERE a.new_id IS NOT NULL 
                    AND p.new_id IS NOT NULL
            """)
            logger.info(f"Добавлено связей assembly-package: {cur.rowcount}")
            # Вставка маппингов в id_mappings
            create_id_mappings(pg_conn, id_mapper)

            # Количество связей до обработки
            cur.execute("SELECT COUNT(*) FROM staging.asm_pkg_vsn_lnk")
            total_links = cur.fetchone()[0]
            logger.debug(f"Всего связей в исходных данных: {total_links}")

            # Логирование проблемных связей
            cur.execute("""
                SELECT 
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE a.new_id IS NULL) AS missing_assemblies,
                    COUNT(*) FILTER (WHERE p.new_id IS NULL) AS missing_packages
                FROM staging.asm_pkg_vsn_lnk l
                LEFT JOIN id_mappings a 
                    ON l.asm_ref = a.old_id 
                    AND a.table_name = 'assemblies'
                LEFT JOIN id_mappings p 
                    ON l.pkg_vsn_ref = p.old_id 
                    AND p.table_name = 'pkg_versions'
            """)
            stats = cur.fetchone()
            logger.warning(
                f"Некорректных связей: {stats[0]} "
                f"(отсутствуют assemblies: {stats[1]}, пакеты: {stats[2]})"
            )

            # Вывод примеров проблемных записей
            cur.execute("""
                SELECT 
                    l.asm_ref, 
                    l.pkg_vsn_ref,
                    a.new_id AS mapped_asm_id,
                    p.new_id AS mapped_pkg_id
                FROM staging.asm_pkg_vsn_lnk l
                LEFT JOIN id_mappings a 
                    ON l.asm_ref = a.old_id 
                    AND a.table_name = 'assemblies'
                LEFT JOIN id_mappings p 
                    ON l.pkg_vsn_ref = p.old_id 
                    AND p.table_name = 'pkg_versions'
                WHERE a.new_id IS NULL OR p.new_id IS NULL
                LIMIT 10
            """)
            bad_links = cur.fetchall()
            if bad_links:
                logger.error("Примеры проблемных связей (asm_ref | pkg_vsn_ref | mapped_asm_id | mapped_pkg_id):")
                for link in bad_links:
                    logger.error(f"  {link[0]} | {link[1]} | {link[2]} | {link[3]}")

            # Обработка changelog
            logger.info("Обработка changelog...")
            cur.execute("""
                WITH changelog_data AS (
                    SELECT
                        c.old_id,
                        COALESCE(c.special, '') AS log_desc,
                        p.new_id AS pkg_vrs_id,
                        COALESCE(to_timestamp(pv.time), NOW()) AS date_added,
                        COALESCE(STRING_AGG(v.name, ', '), '') AS log_ident
                    FROM staging.changes c
                    INNER JOIN id_mappings p 
                        ON c.pkg_vsn_ref = p.old_id 
                        AND p.table_name = 'pkg_versions'
                    LEFT JOIN staging.chg_vln_lnk lnk 
                        ON c.old_id = lnk.chg_ref
                    LEFT JOIN staging.vulnerabilities v 
                        ON lnk.vln_ref = v.old_id
                    JOIN staging.pkg_versions pv 
                        ON c.pkg_vsn_ref = pv.old_id
                    GROUP BY c.old_id, c.special, p.new_id, pv.time
                )
                INSERT INTO repositories.changelog 
                (log_desc, pkg_vrs_id, date_added, log_ident)
                SELECT 
                    log_desc,
                    pkg_vrs_id,
                    date_added,
                    log_ident
                FROM changelog_data
                WHERE log_desc IS NOT NULL
            """)
            inserted_changes = cur.rowcount
            logger.info(f"Добавлено записей changelog: {inserted_changes}")
            # Вставка маппингов в id_mappings
            create_id_mappings(pg_conn, id_mapper)

            # Финализация
            pg_conn.commit()
            logger.info("Обработка данных успешно завершена")

    except Exception as e:
        pg_conn.rollback()
        logger.error(f"Ошибка обработки данных: {str(e)}", exc_info=True)
        raise


def main():
    try:
        logger.info("=== НАЧАЛО МИГРАЦИИ ===")

        # Подключение к SQLite
        logger.info(f"Подключение к SQLite: {SQLITE_DB}")
        sqlite_conn = sqlite3.connect(SQLITE_DB)

        # Подключение к PostgreSQL
        logger.info("Подключение к PostgreSQL")
        pg_conn = psycopg2.connect(**POSTGRES_CONFIG)
        pg_conn.autocommit = False

        # Инициализация временной схемы
        logger.info("Инициализация временной схемы")
        setup_postgres_schemas(pg_conn)

        # Перенос данных в staging
        logger.info("Этап 1: Перенос данных в staging")
        id_mapper = migrate_to_staging(sqlite_conn, pg_conn)

        # Создание таблицы маппингов
        logger.info("Этап 2: Создание таблицы маппингов")
        create_id_mappings(pg_conn, id_mapper)

        # Обработка данных
        logger.info("Этап 3: Обработка и перенос в основную схему")
        process_staging_data(pg_conn, id_mapper)

        logger.info("=== МИГРАЦИЯ УСПЕШНО ЗАВЕРШЕНА ===")

    except Exception as e:
        logger.error(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
        sys.exit(1)

    finally:
        logger.info("Завершение работы и очистка")

        # Всегда удаляем временную схему
        if pg_conn:
            # try:
            #     with pg_conn.cursor() as cur:
            #         cur.execute("DROP SCHEMA IF EXISTS staging CASCADE")
            #         pg_conn.commit()
            #         logger.info("Временная схема staging удалена")
            # except Exception as e:
            #     logger.error(f"Ошибка при удалении временной схемы: {e}")
            # finally:
                pg_conn.close()
                logger.info("Соединение с PostgreSQL закрыто")

        if 'sqlite_conn' in locals():
            sqlite_conn.close()
            logger.info("Соединение с SQLite закрыто")


if __name__ == "__main__":
    main()
