from django.db import connection
from django.db.migrations.executor import MigrationExecutor


def restore_latest_migration_state():
    executor = MigrationExecutor(connection)
    executor.migrate(executor.loader.graph.leaf_nodes())
