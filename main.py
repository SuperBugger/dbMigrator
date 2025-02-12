import datetime
import logging
from sqlalchemy import (
    create_engine, MetaData, Table, Column, Integer, String, Text, DateTime,
    ForeignKey, select, func, text, PrimaryKeyConstraint
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

# ------------------------------------------------------------
# Настройка логирования
# ------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("db_migration.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# ------------------------------------------------------------
# Конфигурация подключения
# ------------------------------------------------------------
SQLITE_DB_PATH = '/home/ivandor/Загрузки/uroboros.db'
POSTGRES_URL = 'postgresql+psycopg2://owner:1111@localhost:5432/uroboros'

# ------------------------------------------------------------
# Настройка подключений
# ------------------------------------------------------------
logger.info("Настройка подключений к базам данных.")
sqlite_engine = create_engine(f"sqlite:///{SQLITE_DB_PATH}")
pg_engine = create_engine(POSTGRES_URL)

# Создание MetaData объектов без использования 'bind'
sqlite_meta = MetaData()
repositories_meta = MetaData(schema='repositories')  # MetaData для схемы 'repositories' в PostgreSQL

# Создание сессий
SessionPG = sessionmaker(bind=pg_engine)
pg_session = SessionPG()

SessionSQ = sessionmaker(bind=sqlite_engine)
sq_session = SessionSQ()

# ------------------------------------------------------------
# Карта Соответствий Таблиц и Столбцов
# ------------------------------------------------------------
TABLE_COLUMN_MAPPING = {
    'project': {
        'prj_id': ('projects', 'id'),
        'prj_name': ('projects', 'name'),
        'rel_id': ('projects', 'rls_ref'),
        'prj_desc': ('projects', 'description'),
        'vendor': ('publishers', 'name'),
        'arch_id': ('projects', 'arc_ref'),
    },
    'assembly': {
        'assm_id': ('assemblies', 'id'),
        'assm_date_created': ('assemblies', 'time'),
        'assm_desc': ('assemblies', 'description'),
        'prj_id': ('assemblies', 'prj_ref'),
        'assm_version': None,  # Пока вставить null
    },
    'package': {
        'pkg_id': ('src_packages', 'id'),
        'pkg_name': ('src_packages', 'name'),
    },
    'pkg_version': {
        'pkg_vrs_id': ('pkg_versions', 'id'),
        'pkg_date_created': ('pkg_versions', 'time'),
        'author_name': ('pkg_versions', 'maintainer'),
        'pkg_id': ('pkg_versions', 'src_pkg_ref'),
        'version': ('pkg_versions', 'version'),
    },
    'assm_pkg_vrs': {
        'pkg_vrs_id': ('asm_pkg_vsn_lnk', 'pkg_vsn_ref'),
        'assm_id': ('asm_pkg_vsn_lnk', 'asm_ref'),
    },
    'changelog': {
        'id': ('changes', 'id'),
        'log_desc': ('changes', 'special'),
        'urg_id': None,  # Пока вставить null
        'pkg_vrs_id': ('changes', 'pkg_vsn_ref'),
        'date_added': ('pkg_versions', 'time'),
        'log_ident': ('vulnerabilities', 'name'),
        'rep_name': None,  # Пока вставить null
    },
    'urgency': {
        'urg_id': ('urgency', 'id'),
        'urg_name': ('urgency', 'name'),
    },
}


# ------------------------------------------------------------
# Дополнительные функции
# ------------------------------------------------------------
def unixtime_to_datetime(utime):
    """Преобразовать Unix timestamp (int) в datetime с таймзоной (UTC)."""
    if utime is None:
        return None
    return datetime.datetime.utcfromtimestamp(utime)


# ------------------------------------------------------------
# Функция для создания отображений для внешних ключей
# ------------------------------------------------------------
def create_id_mappings(pg_session, repositories_meta, logger):
    """
    Создает маппинги старых ID из SQLite на новые ID в PostgreSQL.

    :param pg_session: Сессия SQLAlchemy для PostgreSQL.
    :param repositories_meta: MetaData для схемы 'repositories'.
    :param logger: Объект логирования.
    :return: Словарь с маппингами.
    """
    logger.info("Создание маппингов ID для внешних ключей.")
    mappings = {}

    # Для каждой таблицы, создаем маппинг старый_id -> new_id
    for postgres_table in TABLE_COLUMN_MAPPING.keys():
        if postgres_table in ['assm_pkg_vrs', 'chg_vln_lnk']:
            continue  # Связующие таблицы обрабатываются отдельно
        table = repositories_meta.tables[postgres_table]
        if 'id' in table.c:
            id_column = 'id'
        elif 'prj_id' in table.c:
            id_column = 'prj_id'
        elif 'assm_id' in table.c:
            id_column = 'assm_id'
        elif 'pkg_id' in table.c:
            id_column = 'pkg_id'
        elif 'pkg_vrs_id' in table.c:
            id_column = 'pkg_vrs_id'
        elif 'urg_id' in table.c:
            id_column = 'urg_id'
        else:
            id_column = 'id3'  # По умолчанию

        mappings[f"{postgres_table}_map"] = {}
        logger.info(f"Создание маппинга для таблицы '{postgres_table}'.")

        try:
            results = pg_session.execute(select(table)).fetchall()
            for row in results:
                old_id = row.id if 'id' in row else row.prj_id if 'prj_id' in row else row.assm_id if 'assm_id' in row else row.pkg_id if 'pkg_id' in row else row.pkg_vrs_id if 'pkg_vrs_id' in row else row.urg_id if 'urg_id' in row else None
                new_id = row.id3 if 'id3' in row else getattr(row, id_column)
                mappings[f"{postgres_table}_map"][old_id] = new_id
                logger.debug(f"Маппинг '{postgres_table}': {old_id} → {new_id}")
        except Exception as e:
            logger.error(f"Ошибка при создании маппинга для таблицы '{postgres_table}': {e}")

    logger.info("Маппинги ID созданы успешно.")
    return mappings


# ------------------------------------------------------------
# Функция для миграции таблицы 'project'
# ------------------------------------------------------------
def migrate_project(sqlite_engine, pg_session, repositories_meta, mappings, logger):
    """
    Миграция данных из SQLite таблиц 'projects' и 'publishers' в PostgreSQL таблицу 'project'.

    :param sqlite_engine: Engine SQLAlchemy для SQLite.
    :param pg_session: Сессия SQLAlchemy для PostgreSQL.
    :param repositories_meta: MetaData для схемы 'repositories'.
    :param mappings: Словарь с маппингами.
    :param logger: Объект логирования.
    """
    logger.info("Миграция таблицы 'project'.")

    # Отражение таблиц SQLite
    sqlite_meta = MetaData()
    sqlite_meta.reflect(bind=sqlite_engine)

    projects_table = sqlite_meta.tables['projects']
    publishers_table = sqlite_meta.tables['publishers']

    # Выполнение JOIN между projects и publishers
    query = select(
        projects_table.c.id.label('id'),
        projects_table.c.name.label('name'),
        projects_table.c.rls_ref.label('rls_ref'),
        projects_table.c.description.label('description'),
        publishers_table.c.name.label('vendor'),
        projects_table.c.arc_ref.label('arc_ref')
    ).select_from(
        projects_table.join(publishers_table, projects_table.c.pbr_ref == publishers_table.c.id)
    )

    results = sqlite_engine.execute(query).fetchall()

    postgres_table = repositories_meta.tables['project']

    for row in results:
        insert_data = {
            'prj_id': row.id,
            # Поскольку PostgreSQL использует serial4, этот столбец обычно автоинкрементируется. Возможно, его не следует указывать
            'prj_name': row.name,
            'rel_id': row.rls_ref,
            'prj_desc': row.description,
            'vendor': row.vendor,
            'arch_id': row.arc_ref,
        }

        # Удаляем 'prj_id', чтобы PostgreSQL сам его сгенерировал
        insert_data.pop('prj_id', None)

        try:
            insert_stmt = postgres_table.insert().values(**insert_data).returning(postgres_table.c.prj_id)
            result = pg_session.execute(insert_stmt)
            new_prj_id = result.scalar()
            mappings['project_map'][row.id] = new_prj_id
            logger.debug(f"Маппинг 'project': {row.id} → {new_prj_id}")
        except IntegrityError as e:
            logger.error(f"IntegrityError при вставке 'project' с SQLite id={row.id}: {e}")
            pg_session.rollback()
            continue
        except Exception as e:
            logger.error(f"Ошибка при вставке 'project' с SQLite id={row.id}: {e}")
            pg_session.rollback()
            continue

    try:
        pg_session.commit()
    except Exception as e:
        logger.error(f"Ошибка при коммите после миграции 'project': {e}")
        pg_session.rollback()


# ------------------------------------------------------------
# Функция для миграции таблицы 'assembly'
# ------------------------------------------------------------
def migrate_assembly(sqlite_engine, pg_session, repositories_meta, mappings, logger):
    """
    Миграция данных из SQLite таблицы 'assemblies' в PostgreSQL таблицу 'assembly'.

    :param sqlite_engine: Engine SQLAlchemy для SQLite.
    :param pg_session: Сессия SQLAlchemy для PostgreSQL.
    :param repositories_meta: MetaData для схемы 'repositories'.
    :param mappings: Словарь с маппингами.
    :param logger: Объект логирования.
    """
    logger.info("Миграция таблицы 'assembly'.")

    # Отражение таблиц SQLite
    sqlite_meta = MetaData()
    sqlite_meta.reflect(bind=sqlite_engine)

    assemblies_table = sqlite_meta.tables['assemblies']

    # Выполнение выборки данных
    query = select(
        assemblies_table.c.id.label('id'),
        assemblies_table.c.prj_ref.label('prj_ref'),
        assemblies_table.c.pbr_ref.label('pbr_ref'),  # Пока не используется
        assemblies_table.c.time.label('time'),
        assemblies_table.c.description.label('description')
    )

    results = sqlite_engine.execute(query).fetchall()

    postgres_table = repositories_meta.tables['assembly']

    for row in results:
        insert_data = {
            'assm_id': row.id,  # Обычно не указывается для serial4
            'assm_date_created': unixtime_to_datetime(row.time),
            'assm_desc': row.description,
            'prj_id': mappings['project_map'].get(row.prj_ref, None),
            'assm_version': None,  # Пока вставить null
        }

        # Проверка наличия соответствующего prj_id
        if insert_data['prj_id'] is None:
            logger.error(f"Отсутствует маппинг prj_ref={row.prj_ref} для assembly id={row.id}")
            continue

        # Удаляем 'assm_id', чтобы PostgreSQL сам его сгенерировал
        insert_data.pop('assm_id', None)

        try:
            insert_stmt = postgres_table.insert().values(**insert_data).returning(postgres_table.c.assm_id)
            result = pg_session.execute(insert_stmt)
            new_assm_id = result.scalar()
            mappings['assembly_map'][row.id] = new_assm_id
            logger.debug(f"Маппинг 'assembly': {row.id} → {new_assm_id}")
        except IntegrityError as e:
            logger.error(f"IntegrityError при вставке 'assembly' с SQLite id={row.id}: {e}")
            pg_session.rollback()
            continue
        except Exception as e:
            logger.error(f"Ошибка при вставке 'assembly' с SQLite id={row.id}: {e}")
            pg_session.rollback()
            continue

    try:
        pg_session.commit()
    except Exception as e:
        logger.error(f"Ошибка при коммите после миграции 'assembly': {e}")
        pg_session.rollback()


# ------------------------------------------------------------
# Функция для миграции таблицы 'package'
# ------------------------------------------------------------
def migrate_package(sqlite_engine, pg_session, repositories_meta, mappings, logger):
    """
    Миграция данных из SQLite таблицы 'src_packages' в PostgreSQL таблицу 'package'.

    :param sqlite_engine: Engine SQLAlchemy для SQLite.
    :param pg_session: Сессия SQLAlchemy для PostgreSQL.
    :param repositories_meta: MetaData для схемы 'repositories'.
    :param mappings: Словарь с маппингами.
    :param logger: Объект логирования.
    """
    logger.info("Миграция таблицы 'package'.")

    # Отражение таблиц SQLite
    sqlite_meta = MetaData()
    sqlite_meta.reflect(bind=sqlite_engine)

    src_packages_table = sqlite_meta.tables['src_packages']

    # Выполнение выборки данных
    query = select(
        src_packages_table.c.id.label('id'),
        src_packages_table.c.name.label('name')
    )

    results = sqlite_engine.execute(query).fetchall()

    postgres_table = repositories_meta.tables['package']

    for row in results:
        insert_data = {
            'pkg_id': row.id,  # Обычно не указывается для serial4
            'pkg_name': row.name,
        }

        # Удаляем 'pkg_id', чтобы PostgreSQL сам его сгенерировал
        insert_data.pop('pkg_id', None)

        try:
            insert_stmt = postgres_table.insert().values(**insert_data).returning(postgres_table.c.pkg_id)
            result = pg_session.execute(insert_stmt)
            new_pkg_id = result.scalar()
            mappings['package_map'][row.id] = new_pkg_id
            logger.debug(f"Маппинг 'package': {row.id} → {new_pkg_id}")
        except IntegrityError as e:
            logger.error(f"IntegrityError при вставке 'package' с SQLite id={row.id}: {e}")
            pg_session.rollback()
            continue
        except Exception as e:
            logger.error(f"Ошибка при вставке 'package' с SQLite id={row.id}: {e}")
            pg_session.rollback()
            continue

    try:
        pg_session.commit()
    except Exception as e:
        logger.error(f"Ошибка при коммите после миграции 'package': {e}")
        pg_session.rollback()


# ------------------------------------------------------------
# Функция для миграции таблицы 'pkg_version'
# ------------------------------------------------------------
def migrate_pkg_version(sqlite_engine, pg_session, repositories_meta, mappings, logger):
    """
    Миграция данных из SQLite таблицы 'pkg_versions' в PostgreSQL таблицу 'pkg_version'.

    :param sqlite_engine: Engine SQLAlchemy для SQLite.
    :param pg_session: Сессия SQLAlchemy для PostgreSQL.
    :param repositories_meta: MetaData для схемы 'repositories'.
    :param mappings: Словарь с маппингами.
    :param logger: Объект логирования.
    """
    logger.info("Миграция таблицы 'pkg_version'.")

    # Отражение таблиц SQLite
    sqlite_meta = MetaData()
    sqlite_meta.reflect(bind=sqlite_engine)

    pkg_versions_table = sqlite_meta.tables['pkg_versions']

    # Выполнение выборки данных
    query = select(
        pkg_versions_table.c.id.label('id'),
        pkg_versions_table.c.time.label('time'),
        pkg_versions_table.c.maintainer.label('maintainer'),
        pkg_versions_table.c.src_pkg_ref.label('src_pkg_ref'),
        pkg_versions_table.c.version.label('version')
    )

    results = sqlite_engine.execute(query).fetchall()

    postgres_table = repositories_meta.tables['pkg_version']

    for row in results:
        insert_data = {
            'pkg_vrs_id': row.id,  # Обычно не указывается для serial4
            'pkg_date_created': unixtime_to_datetime(row.time),
            'author_name': row.maintainer,
            'pkg_id': mappings['package_map'].get(row.src_pkg_ref, None),
            'version': row.version,
        }

        # Удаляем 'pkg_vrs_id', чтобы PostgreSQL сам его сгенерировал
        insert_data.pop('pkg_vrs_id', None)

        # Проверка наличия соответствующего pkg_id
        if insert_data['pkg_id'] is None:
            logger.error(f"Отсутствует маппинг src_pkg_ref={row.src_pkg_ref} для pkg_version id={row.id}")
            continue

        try:
            insert_stmt = postgres_table.insert().values(**insert_data).returning(postgres_table.c.pkg_vrs_id)
            result = pg_session.execute(insert_stmt)
            new_pkg_vrs_id = result.scalar()
            mappings['pkg_version_map'][row.id] = new_pkg_vrs_id
            logger.debug(f"Маппинг 'pkg_version': {row.id} → {new_pkg_vrs_id}")
        except IntegrityError as e:
            logger.error(f"IntegrityError при вставке 'pkg_version' с SQLite id={row.id}: {e}")
            pg_session.rollback()
            continue
        except Exception as e:
            logger.error(f"Ошибка при вставке 'pkg_version' с SQLite id={row.id}: {e}")
            pg_session.rollback()
            continue

    try:
        pg_session.commit()
    except Exception as e:
        logger.error(f"Ошибка при коммите после миграции 'pkg_version': {e}")
        pg_session.rollback()


# ------------------------------------------------------------
# Функция для миграции таблицы 'changelog'
# ------------------------------------------------------------
def migrate_changelog(sqlite_engine, pg_session, repositories_meta, mappings, logger):
    """
    Миграция данных из SQLite таблицы 'changes' в PostgreSQL таблицу 'changelog'.

    :param sqlite_engine: Engine SQLAlchemy для SQLite.
    :param pg_session: Сессия SQLAlchemy для PostgreSQL.
    :param repositories_meta: MetaData для схемы 'repositories'.
    :param mappings: Словарь с маппингами.
    :param logger: Объект логирования.
    """
    logger.info("Миграция таблицы 'changelog'.")

    # Отражение таблиц SQLite
    sqlite_meta = MetaData()
    sqlite_meta.reflect(bind=sqlite_engine)

    changes_table = sqlite_meta.tables['changes']
    vulnerabilities_table = sqlite_meta.tables['vulnerabilities']
    chg_vln_lnk_table = sqlite_meta.tables['chg_vln_lnk']
    pkg_versions_table = sqlite_meta.tables['pkg_versions']

    # Выполнение выборки данных с JOIN
    # Сначала получаем данные из changes
    changes_query = select(
        changes_table.c.id.label('change_id'),
        changes_table.c.pkg_vsn_ref.label('pkg_vsn_ref'),
        changes_table.c.special.label('special'),
    )

    changes_results = sqlite_engine.execute(changes_query).fetchall()

    # Получаем соответствия chg_vln_lnk
    chg_vln_lnk_query = select(
        chg_vln_lnk_table.c.chg_ref.label('chg_ref'),
        chg_vln_lnk_table.c.vln_ref.label('vln_ref'),
    )

    chg_vln_lnk_results = sqlite_engine.execute(chg_vln_lnk_query).fetchall()
    chg_vln_map = {}
    for row in chg_vln_lnk_results:
        chg_vln_map.setdefault(row.chg_ref, []).append(row.vln_ref)

    # Получаем названия уязвимостей
    vulnerabilities_query = select(
        vulnerabilities_table.c.id.label('vln_id'),
        vulnerabilities_table.c.name.label('vln_name')
    )

    vulnerabilities_results = sqlite_engine.execute(vulnerabilities_query).fetchall()
    vln_map = {row.vln_id: row.vln_name for row in vulnerabilities_results}

    postgres_table = repositories_meta.tables['changelog']

    for row in changes_results:
        change_id = row.change_id
        pkg_vsn_ref = row.pkg_vsn_ref
        special = row.special

        # Получаем vln_ref через chg_vln_lnk
        vln_refs = chg_vln_map.get(change_id, [])
        log_ident = ', '.join([vln_map.get(vln_ref, '') for vln_ref in vln_refs if vln_ref in vln_map])

        # Получаем pkg_vrs_id из маппинга
        pkg_vrs_id = mappings['pkg_version_map'].get(pkg_vsn_ref, None)
        if pkg_vrs_id is None:
            logger.error(f"Отсутствует маппинг pkg_vsn_ref={pkg_vsn_ref} для changelog change_id={change_id}")
            continue

        # Получаем время из pkg_versions для date_added
        pkg_time_query = select(pkg_versions_table.c.time).where(pkg_versions_table.c.id == pkg_vsn_ref)
        pkg_time_result = sqlite_engine.execute(pkg_time_query).fetchone()
        date_added = unixtime_to_datetime(pkg_time_result.time) if pkg_time_result and pkg_time_result.time else None

        insert_data = {
            'id': change_id,  # Обычно не указывается для serial4
            'log_desc': special,
            'urg_id': None,  # Пока вставить null
            'pkg_vrs_id': pkg_vrs_id,
            'date_added': date_added,
            'log_ident': log_ident,
            'rep_name': None,  # Пока вставить null
        }

        # Удаляем 'id', чтобы PostgreSQL сам его сгенерировал
        insert_data.pop('id', None)

        try:
            insert_stmt = postgres_table.insert().values(**insert_data).returning(postgres_table.c.id)
            result = pg_session.execute(insert_stmt)
            new_chg_id = result.scalar()
            mappings['changelog_map'][change_id] = new_chg_id
            logger.debug(f"Маппинг 'changelog': {change_id} → {new_chg_id}")
        except IntegrityError as e:
            logger.error(f"IntegrityError при вставке 'changelog' с SQLite change_id={change_id}: {e}")
            pg_session.rollback()
            continue
        except Exception as e:
            logger.error(f"Ошибка при вставке 'changelog' с SQLite change_id={change_id}: {e}")
            pg_session.rollback()
            continue

    try:
        pg_session.commit()
    except Exception as e:
        logger.error(f"Ошибка при коммите после миграции 'changelog': {e}")
        pg_session.rollback()


# ------------------------------------------------------------
# Функция для миграции связующей таблицы 'assm_pkg_vrs'
# ------------------------------------------------------------
def migrate_assm_pkg_vrs(sqlite_engine, pg_session, repositories_meta, mappings, logger):
    """
    Миграция данных из SQLite таблицы 'asm_pkg_vsn_lnk' в PostgreSQL таблицу 'assm_pkg_vrs'.

    :param sqlite_engine: Engine SQLAlchemy для SQLite.
    :param pg_session: Сессия SQLAlchemy для PostgreSQL.
    :param repositories_meta: MetaData для схемы 'repositories'.
    :param mappings: Словарь с маппингами.
    :param logger: Объект логирования.
    """
    logger.info("Миграция связующей таблицы 'assm_pkg_vrs'.")

    # Отражение таблиц SQLite
    sqlite_meta = MetaData()
    sqlite_meta.reflect(bind=sqlite_engine)

    asm_pkg_vsn_lnk_table = sqlite_meta.tables['asm_pkg_vsn_lnk']

    # Выполнение выборки данных
    query = select(
        asm_pkg_vsn_lnk_table.c.pkg_vsn_ref.label('pkg_vsn_ref'),
        asm_pkg_vsn_lnk_table.c.asm_ref.label('asm_ref')
    )

    results = sqlite_engine.execute(query).fetchall()

    postgres_table = repositories_meta.tables['assm_pkg_vrs']

    for row in results:
        pkg_vsn_ref = row.pkg_vsn_ref
        asm_ref = row.asm_ref

        # Получаем новые IDs из маппингов
        new_pkg_vrs_id = mappings['pkg_version_map'].get(pkg_vsn_ref, None)
        new_assm_id = mappings['assembly_map'].get(asm_ref, None)

        if new_pkg_vrs_id is None or new_assm_id is None:
            logger.error(f"Отсутствует маппинг pkg_vsn_ref={pkg_vsn_ref} или asm_ref={asm_ref} для assm_pkg_vrs")
            continue

        insert_data = {
            'pkg_vrs_id': new_pkg_vrs_id,
            'assm_id': new_assm_id,
        }

        try:
            insert_stmt = postgres_table.insert().values(**insert_data)
            pg_session.execute(insert_stmt)
            logger.debug(f"Вставлена запись в 'assm_pkg_vrs': pkg_vrs_id={new_pkg_vrs_id}, assm_id={new_assm_id}")
        except IntegrityError as e:
            logger.error(
                f"IntegrityError при вставке в 'assm_pkg_vrs': pkg_vrs_id={new_pkg_vrs_id}, assm_id={new_assm_id}: {e}")
            pg_session.rollback()
            continue
        except Exception as e:
            logger.error(
                f"Ошибка при вставке в 'assm_pkg_vrs': pkg_vrs_id={new_pkg_vrs_id}, assm_id={new_assm_id}: {e}")
            pg_session.rollback()
            continue

    try:
        pg_session.commit()
    except Exception as e:
        logger.error(f"Ошибка при коммите после миграции 'assm_pkg_vrs': {e}")
        pg_session.rollback()


# ------------------------------------------------------------
# Функция для миграции связующей таблицы 'chg_vln_lnk'
# ------------------------------------------------------------
def migrate_chg_vln_lnk(sqlite_engine, pg_session, repositories_meta, mappings, logger):
    """
    Миграция данных из SQLite таблицы 'chg_vln_lnk' в PostgreSQL таблицу 'changelog'.
    Здесь предполагается, что 'log_ident' уже заполнен из 'vulnerabilities'.

    :param sqlite_engine: Engine SQLAlchemy для SQLite.
    :param pg_session: Сессия SQLAlchemy для PostgreSQL.
    :param repositories_meta: MetaData для схемы 'repositories'.
    :param mappings: Словарь с маппингами.
    :param logger: Объект логирования.
    """
    logger.info("Миграция связующей таблицы 'chg_vln_lnk'.")

    # Отражение таблиц SQLite
    sqlite_meta = MetaData()
    sqlite_meta.reflect(bind=sqlite_engine)

    chg_vln_lnk_table = sqlite_meta.tables['chg_vln_lnk']

    # Выполнение выборки данных
    query = select(
        chg_vln_lnk_table.c.chg_ref.label('chg_ref'),
        chg_vln_lnk_table.c.vln_ref.label('vln_ref')
    )

    # results = sqlite_engine.execute(query).fetchall()

    with sqlite_engine.connect() as connection:
        result = connection.execute(query)
        results = result.fetchall()

    postgres_table = repositories_meta.tables['changelog']

    for row in results:
        chg_ref = row.chg_ref
        vln_ref = row.vln_ref

        # Получаем новые IDs из маппингов
        new_chg_id = mappings['changelog_map'].get(chg_ref, None)
        new_vln_id = mappings['vulnerabilities_map'].get(vln_ref, None)

        if new_chg_id is None or new_vln_id is None:
            logger.error(f"Отсутствует маппинг chg_ref={chg_ref} или vln_ref={vln_ref} для chg_vln_lnk")
            continue

        # Здесь необходимо решить, как хранить связи. Например, можно объединить 'log_ident'
        # или хранить их в отдельной таблице. В текущей схеме 'log_ident' уже заполнен.
        # Поэтому, возможно, нет необходимости вставлять дополнительные связи.
        # Если требуется, можно добавить дополнительную логику.
        # В данном случае мы пропускаем, так как 'log_ident' уже заполнен.
        pass  # Нет действия, так как 'log_ident' уже установлен

    # Нет необходимости вставлять в PostgreSQL, так как 'log_ident' уже заполнен
    # Если нужна дополнительная логика, добавьте её здесь

    logger.info("Миграция связующей таблицы 'chg_vln_lnk' завершена (нет действий).")


# ------------------------------------------------------------
# Функция для миграции таблицы 'urgency'
# ------------------------------------------------------------
def migrate_urgency(sqlite_engine, pg_session, repositories_meta, mappings, logger):
    """
    Миграция данных из SQLite таблицы 'urgency' в PostgreSQL таблицу 'urgency'.

    :param sqlite_engine: Engine SQLAlchemy для SQLite.
    :param pg_session: Сессия SQLAlchemy для PostgreSQL.
    :param repositories_meta: MetaData для схемы 'repositories'.
    :param mappings: Словарь с маппингами.
    :param logger: Объект логирования.
    """
    logger.info("Миграция таблицы 'urgency'.")

    # Отражение таблиц SQLite
    sqlite_meta = MetaData()
    sqlite_meta.reflect(bind=sqlite_engine)

    urgency_table = sqlite_meta.tables['urgency']

    # Выполнение выборки данных
    query = select(
        urgency_table.c.id.label('id'),
        urgency_table.c.name.label('name')
    )

    # results = sqlite_engine.execute(query).fetchall()

    with sqlite_engine.connect() as connection:
        result = connection.execute(query)
        results = result.fetchall()

    postgres_table = repositories_meta.tables['repositories.urgency']

    for row in results:
        insert_data = {
            'urg_id': row.id,
            'urg_name': row.name,
        }

        insert_data.pop('urg_id', None)

        try:
            insert_stmt = postgres_table.insert().values(**insert_data).returning(postgres_table.c.urg_id)
            result = pg_session.execute(insert_stmt)
            new_urg_id = result.scalar()
            mappings['urgency_map'][row.id] = new_urg_id
            logger.debug(f"Маппинг 'urgency': {row.id} → {new_urg_id}")
        except IntegrityError as e:
            logger.error(f"IntegrityError при вставке 'urgency' с SQLite id={row.id}: {e}")
            pg_session.rollback()
            continue
        except Exception as e:
            logger.error(f"Ошибка при вставке 'urgency' с SQLite id={row.id}: {e}")
            pg_session.rollback()
            continue

    try:
        pg_session.commit()
    except Exception as e:
        logger.error(f"Ошибка при коммите после миграции 'urgency': {e}")
        pg_session.rollback()


# ------------------------------------------------------------
# Функция для миграции таблицы 'vulnerabilities'
# ------------------------------------------------------------
def migrate_vulnerabilities(sqlite_engine, pg_session, repositories_meta, mappings, logger):
    """
    Миграция данных из SQLite таблицы 'vulnerabilities' в PostgreSQL таблицу 'changelog'.
    Здесь 'log_ident' уже заполняется из 'vulnerabilities.name'.

    :param sqlite_engine: Engine SQLAlchemy для SQLite.
    :param pg_session: Сессия SQLAlchemy для PostgreSQL.
    :param repositories_meta: MetaData для схемы 'repositories'.
    :param mappings: Словарь с маппингами.
    :param logger: Объект логирования.
    """
    logger.info("Миграция таблицы 'vulnerabilities'.")

    # Отражение таблиц SQLite
    sqlite_meta = MetaData()
    sqlite_meta.reflect(bind=sqlite_engine)

    vulnerabilities_table = sqlite_meta.tables['vulnerabilities']

    # Выполнение выборки данных
    query = select(
        vulnerabilities_table.c.id.label('id'),
        vulnerabilities_table.c.name.label('name')
    )

    results = sqlite_engine.execute(query).fetchall()

    postgres_table = repositories_meta.tables['vulnerabilities']

    for row in results:
        insert_data = {
            'id': row.id,  # Обычно не указывается для serial4
            'name': row.name,
        }

        # Удаляем 'id', чтобы PostgreSQL сам его сгенерировал
        insert_data.pop('id', None)

        try:
            insert_stmt = postgres_table.insert().values(**insert_data).returning(postgres_table.c.id)
            result = pg_session.execute(insert_stmt)
            new_vln_id = result.scalar()
            mappings['vulnerabilities_map'][row.id] = new_vln_id
            logger.debug(f"Маппинг 'vulnerabilities': {row.id} → {new_vln_id}")
        except IntegrityError as e:
            logger.error(f"IntegrityError при вставке 'vulnerabilities' с SQLite id={row.id}: {e}")
            pg_session.rollback()
            continue
        except Exception as e:
            logger.error(f"Ошибка при вставке 'vulnerabilities' с SQLite id={row.id}: {e}")
            pg_session.rollback()
            continue

    try:
        pg_session.commit()
    except Exception as e:
        logger.error(f"Ошибка при коммите после миграции 'vulnerabilities': {e}")
        pg_session.rollback()


# ------------------------------------------------------------
# Основная функция миграции
# ------------------------------------------------------------
def migrate_data(sqlite_engine, pg_session, repositories_meta, TABLE_COLUMN_MAPPING, logger):
    """
    Основная функция для миграции данных из SQLite в PostgreSQL.

    :param sqlite_engine: Engine SQLAlchemy для SQLite.
    :param pg_session: Сессия SQLAlchemy для PostgreSQL.
    :param repositories_meta: MetaData для схемы 'repositories'.
    :param TABLE_COLUMN_MAPPING: Словарь соответствий таблиц и столбцов.
    :param logger: Объект логирования.
    """
    # Отражение метаданных PostgreSQL
    logger.info("Отражение всех таблиц в схеме 'repositories'.")
    try:
        repositories_meta.reflect(bind=pg_engine, schema='repositories')
        logger.info(f"Список таблиц в схеме 'repositories': {list(repositories_meta.tables.keys())}")
    except SQLAlchemyError as e:
        logger.error(f"Ошибка при отражении метаданных 'repositories': {e}")
        return

    # Миграция таблиц в порядке, учитывающем внешние ключи
    migrate_urgency(sqlite_engine, pg_session, repositories_meta, {}, logger)
    migrate_vulnerabilities(sqlite_engine, pg_session, repositories_meta, {}, logger)
    migrate_package(sqlite_engine, pg_session, repositories_meta, {}, logger)
    migrate_project(sqlite_engine, pg_session, repositories_meta, {}, logger)
    migrate_assembly(sqlite_engine, pg_session, repositories_meta, {}, logger)
    migrate_pkg_version(sqlite_engine, pg_session, repositories_meta, {}, logger)
    migrate_changelog(sqlite_engine, pg_session, repositories_meta, {}, logger)
    migrate_assm_pkg_vrs(sqlite_engine, pg_session, repositories_meta, {}, logger)
    migrate_chg_vln_lnk(sqlite_engine, pg_session, repositories_meta, {}, logger)

    # Обновление последовательностей
    update_sequences(pg_engine, repositories_meta, logger)

    logger.info("Миграция данных завершена успешно.")


# ------------------------------------------------------------
# Основная часть скрипта миграции
# ------------------------------------------------------------
def main():
    try:
        migrate_data(sqlite_engine, pg_session, repositories_meta, TABLE_COLUMN_MAPPING, logger)
    except Exception as e:
        logger.error(f"Произошла критическая ошибка: {e}")
    finally:
        # Закрытие сессий
        pg_session.close()
        sq_session.close()
        logger.info("Соединения закрыты.")
        # Очистка временной схемы
        # drop_temp_schema(pg_engine)


if __name__ == "__main__":
    main()
