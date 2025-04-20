# migrate_add_description.py
from sqlalchemy import create_engine, text

engine = create_engine('sqlite:///crypt_plus.db')
with engine.connect() as conn:
    conn.execution_options(isolation_level="AUTOCOMMIT")
    conn.execute(text("ALTER TABLE data ADD COLUMN description TEXT;"))