Generic single-database configuration.

## Installation & setup

1. Install alembic

```
pip install alembic
```

2. Create `alembic.ini` in the root project directory.
You can use `alembic.ini.example` file. Mainly set `sqlalchemy.url` property so alembic can connect
to the DB server and do the stuff - more on that later.

You can also exclude some tables from auto-detection.


## Usage

Alembic is typically run locally, connecting to a remote dev DB server.

1. Local forward remote MySQL server:

```
ssh -L 3306:localhost:3306 server
```

2. Generate auto detected upgrade file. Prefer numbered prefix so the patch ordering is clear even after tens of
patches generated.

```
alembic revision --autogenerate -m "boot"
```

Now you can manually inspect newly generated patch file, change something or add data migration logic e.g., from
converting from older to newer format.

3. Upgrade remote database schema:

```
alembic upgrade head
```

If something goes wrong or you want to be sure the upgrade does what you want do a dry run with printing SQL dump with
changes.

```
alembic upgrade head --sql
```

### Default values

Alembic autodetection does not work well with default values - they are not detected.
Add default values manually for tables used by PHP

```
op.add_column('users', sa.Column('magiccc', sa.SmallInteger(), nullable=False, server_default='0'))
```

### Foreign key conversion

```
sa.ForeignKeyConstraint\(\['([\w]+)'\],\s*\['([\w]+)\.([\w]+)'\],\s*name='([\w]+)',\s*ondelete='([\w\s]+)'\)(,?)
op.create_foreign_key('$4', SRC_TABLE, '$2', ['$1'], ['$3'], ondelete='$5' )$6
```
