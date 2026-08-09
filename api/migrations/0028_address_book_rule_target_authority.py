from django.db import migrations, models

MAX_REPORTED_VIOLATIONS = 20


def _describe_ids(values):
    suffix = ",..." if len(values) > MAX_REPORTED_VIOLATIONS else ""
    return ",".join(str(value) for value in values[:MAX_REPORTED_VIOLATIONS]) + suffix


def _legacy_target_key(is_everyone, user_id, group_id):
    if is_everyone and user_id is None and group_id is None:
        return "everyone"
    if not is_everyone and user_id is not None and group_id is None:
        return f"user:{user_id}"
    if not is_everyone and group_id is not None and user_id is None:
        return f"group:{group_id}"
    raise RuntimeError("address-book rule has an invalid target shape")


def _drifted_target_key_ids(cursor):
    cursor.execute(
        """
        SELECT id, is_everyone, user_id, group_id, target_key
        FROM api_addressbookrule
        ORDER BY id
        """
    )
    drifted_ids = []
    while len(drifted_ids) <= MAX_REPORTED_VIOLATIONS:
        rows = cursor.fetchmany(1000)
        if not rows:
            break
        for row_id, is_everyone, user_id, group_id, target_key in rows:
            expected = _legacy_target_key(is_everyone, user_id, group_id)
            if target_key != expected:
                drifted_ids.append(row_id)
                if len(drifted_ids) > MAX_REPORTED_VIOLATIONS:
                    break
    return drifted_ids


def _duplicate_target_ids(cursor, target):
    if target == "user":
        target_filter = "user_id IS NOT NULL"
        partition_fields = "profile_id, user_id"
    elif target == "group":
        target_filter = "group_id IS NOT NULL"
        partition_fields = "profile_id, group_id"
    elif target == "everyone":
        target_filter = "is_everyone"
        partition_fields = "profile_id"
    else:
        raise RuntimeError(f"unsupported address-book rule target: {target}")
    cursor.execute(
        f"""
        SELECT id
        FROM (
            SELECT
                id,
                ROW_NUMBER() OVER (
                    PARTITION BY {partition_fields}
                    ORDER BY id
                ) AS duplicate_rank
            FROM api_addressbookrule
            WHERE {target_filter}
        ) AS ranked_rules
        WHERE duplicate_rank > 1
        ORDER BY id
        LIMIT %s
        """,  # noqa: S608 - target is selected only from the fixed branches above
        [MAX_REPORTED_VIOLATIONS + 1],
    )
    return [row[0] for row in cursor.fetchall()]


def refuse_polluted_rule_targets(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        drifted_ids = _drifted_target_key_ids(cursor)
        duplicate_user_ids = _duplicate_target_ids(cursor, "user")
        duplicate_group_ids = _duplicate_target_ids(cursor, "group")
        duplicate_everyone_ids = _duplicate_target_ids(cursor, "everyone")
    if not any((drifted_ids, duplicate_user_ids, duplicate_group_ids, duplicate_everyone_ids)):
        return
    raise RuntimeError(
        "address-book rule target migration refused polluted rows; "
        f"target_key_ids={_describe_ids(drifted_ids) or '-'}; "
        f"duplicate_user_ids={_describe_ids(duplicate_user_ids) or '-'}; "
        f"duplicate_group_ids={_describe_ids(duplicate_group_ids) or '-'}; "
        f"duplicate_everyone_ids={_describe_ids(duplicate_everyone_ids) or '-'}; "
        "resolve each reported rule explicitly and rerun the migration"
    )


def restore_legacy_target_keys(apps, schema_editor):
    Rule = apps.get_model("api", "AddressBookRule")
    database = schema_editor.connection.alias
    pending = []
    rules = (
        Rule.objects.using(database)
        .only("pk", "is_everyone", "user_id", "group_id", "target_key")
        .order_by("pk")
        .iterator(chunk_size=1000)
    )
    for rule in rules:
        rule.target_key = _legacy_target_key(rule.is_everyone, rule.user_id, rule.group_id)
        pending.append(rule)
        if len(pending) == 1000:
            Rule.objects.using(database).bulk_update(pending, ("target_key",), batch_size=1000)
            pending.clear()
    if pending:
        Rule.objects.using(database).bulk_update(pending, ("target_key",), batch_size=1000)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0027_address_book_scope_authority"),
    ]

    operations = [
        migrations.RunPython(
            refuse_polluted_rule_targets,
            migrations.RunPython.noop,
        ),
        migrations.RemoveConstraint(
            model_name="addressbookrule",
            name="unique_address_book_rule_target",
        ),
        migrations.AlterField(
            model_name="addressbookrule",
            name="target_key",
            field=models.CharField(editable=False, max_length=32, null=True),
        ),
        migrations.AddConstraint(
            model_name="addressbookrule",
            constraint=models.UniqueConstraint(
                condition=models.Q(("user__isnull", False)),
                fields=("profile", "user"),
                name="unique_ab_rule_profile_user",
            ),
        ),
        migrations.AddConstraint(
            model_name="addressbookrule",
            constraint=models.UniqueConstraint(
                condition=models.Q(("group__isnull", False)),
                fields=("profile", "group"),
                name="unique_ab_rule_profile_group",
            ),
        ),
        migrations.AddConstraint(
            model_name="addressbookrule",
            constraint=models.UniqueConstraint(
                condition=models.Q(("is_everyone", True)),
                fields=("profile",),
                name="unique_ab_rule_profile_everyone",
            ),
        ),
        migrations.RunPython(
            migrations.RunPython.noop,
            restore_legacy_target_keys,
        ),
        migrations.RemoveField(
            model_name="addressbookrule",
            name="target_key",
        ),
    ]
