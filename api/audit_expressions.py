from django.db import models
from django.db.models import F, Func, Value


class AuditSearchDocument(Func):
    """Immutable joined text projection shared by a trigram index and queries.

    Migration 0021 serializes this class. SQL changes require a new migration
    and a new index name; they must never rewrite the published expression.
    """

    output_field = models.TextField()

    def __init__(self, *expressions):
        if not expressions:
            raise ValueError("AuditSearchDocument requires at least one field")
        super().__init__(*expressions)

    def as_sql(self, compiler, connection, **extra_context):
        sql_parts = []
        params = []
        for expression in self.get_source_expressions():
            expression_sql, expression_params = compiler.compile(expression)
            if connection.vendor == "postgresql":
                sql_parts.append(f"COALESCE(({expression_sql})::text, '')")
            else:
                sql_parts.append(f"COALESCE(CAST({expression_sql} AS text), '')")
            params.extend(expression_params)
        return " || ' ' || ".join(sql_parts), tuple(params)


def audit_search_document(*field_names):
    return AuditSearchDocument(*field_names)


class AuditCursorBoundary(Func):
    output_field = models.BooleanField()

    def __init__(self, created_at, audit_id, *, direction):
        if direction not in ("older", "newer"):
            raise ValueError("Audit cursor direction must be older or newer")
        self.comparison_operator = "<" if direction == "older" else ">"
        super().__init__(F("created_at"), F("id"), Value(created_at), Value(audit_id))

    def as_sql(self, compiler, connection, **extra_context):
        sql_parts = []
        params = []
        for expression in self.get_source_expressions():
            expression_sql, expression_params = compiler.compile(expression)
            sql_parts.append(expression_sql)
            params.extend(expression_params)
        sql = f"(({sql_parts[0]}, {sql_parts[1]}) {self.comparison_operator} ({sql_parts[2]}, {sql_parts[3]}))"
        return sql, tuple(params)


def audit_cursor_boundary(created_at, audit_id, *, direction):
    return AuditCursorBoundary(created_at, audit_id, direction=direction)
