import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

MAX_REPORTED_VIOLATIONS = 20


def _scope_violations(cursor):
    cursor.execute(
        """
        SELECT membership.id
        FROM api_remotepeer_tags AS membership
        JOIN api_remotepeer AS peer ON peer.id = membership.remotepeer_id
        JOIN api_remotetag AS tag ON tag.id = membership.remotetag_id
        WHERE peer.profile_id <> tag.profile_id
        ORDER BY membership.id
        LIMIT %s
        """,
        [MAX_REPORTED_VIOLATIONS + 1],
    )
    peer_tag_ids = [row[0] for row in cursor.fetchall()]
    cursor.execute(
        """
        SELECT membership.id
        FROM api_sharelink_peers AS membership
        JOIN api_sharelink AS link ON link.id = membership.sharelink_id
        JOIN api_remotepeer AS peer ON peer.id = membership.remotepeer_id
        JOIN api_addressbookprofile AS profile ON profile.id = peer.profile_id
        WHERE link.creator_id <> profile.owner_id
        ORDER BY membership.id
        LIMIT %s
        """,
        [MAX_REPORTED_VIOLATIONS + 1],
    )
    share_peer_ids = [row[0] for row in cursor.fetchall()]
    return peer_tag_ids, share_peer_ids


def _refuse_historical_scope_violations(cursor):
    peer_tag_ids, share_peer_ids = _scope_violations(cursor)
    if not peer_tag_ids and not share_peer_ids:
        return

    def describe(values):
        suffix = ",..." if len(values) > MAX_REPORTED_VIOLATIONS else ""
        return ",".join(str(value) for value in values[:MAX_REPORTED_VIOLATIONS]) + suffix

    raise RuntimeError(
        "address-book scope migration refused polluted relationships; "
        f"peer_tag_ids={describe(peer_tag_ids) or '-'}; "
        f"share_peer_ids={describe(share_peer_ids) or '-'}; "
        "isolate the reported rows and rerun the migration"
    )


POSTGRESQL_INSTALL = (
    "ALTER TABLE api_remotepeer_tags ADD COLUMN profile_id integer",
    "ALTER TABLE api_sharelink_peers ADD COLUMN profile_id integer",
    "ALTER TABLE api_sharelink_peers ADD COLUMN owner_id integer",
    """
    UPDATE api_remotepeer_tags AS membership
    SET profile_id = peer.profile_id
    FROM api_remotepeer AS peer
    WHERE peer.id = membership.remotepeer_id
    """,
    """
    UPDATE api_sharelink_peers AS membership
    SET profile_id = peer.profile_id,
        owner_id = profile.owner_id
    FROM api_remotepeer AS peer
    JOIN api_addressbookprofile AS profile ON profile.id = peer.profile_id
    WHERE peer.id = membership.remotepeer_id
    """,
    "ALTER TABLE api_remotepeer_tags ALTER COLUMN profile_id SET NOT NULL",
    "ALTER TABLE api_sharelink_peers ALTER COLUMN profile_id SET NOT NULL",
    "ALTER TABLE api_sharelink_peers ALTER COLUMN owner_id SET NOT NULL",
    "ALTER TABLE api_remotepeer ADD CONSTRAINT remotepeer_id_profile_scope_key UNIQUE (id, profile_id)",
    "ALTER TABLE api_remotetag ADD CONSTRAINT remotetag_id_profile_scope_key UNIQUE (id, profile_id)",
    """
    ALTER TABLE api_addressbookprofile
    ADD CONSTRAINT abprofile_id_owner_scope_key UNIQUE (id, owner_id)
    """,
    "ALTER TABLE api_sharelink ADD CONSTRAINT sharelink_id_creator_scope_key UNIQUE (id, creator_id)",
    """
    ALTER TABLE api_remotepeer_tags
    ADD CONSTRAINT peer_tag_peer_profile_fk
    FOREIGN KEY (remotepeer_id, profile_id)
    REFERENCES api_remotepeer (id, profile_id)
    ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED NOT VALID
    """,
    """
    ALTER TABLE api_remotepeer_tags
    ADD CONSTRAINT peer_tag_tag_profile_fk
    FOREIGN KEY (remotetag_id, profile_id)
    REFERENCES api_remotetag (id, profile_id)
    ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED NOT VALID
    """,
    """
    ALTER TABLE api_sharelink_peers
    ADD CONSTRAINT share_peer_link_owner_fk
    FOREIGN KEY (sharelink_id, owner_id)
    REFERENCES api_sharelink (id, creator_id)
    ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED NOT VALID
    """,
    """
    ALTER TABLE api_sharelink_peers
    ADD CONSTRAINT share_peer_peer_profile_fk
    FOREIGN KEY (remotepeer_id, profile_id)
    REFERENCES api_remotepeer (id, profile_id)
    ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED NOT VALID
    """,
    """
    ALTER TABLE api_sharelink_peers
    ADD CONSTRAINT share_peer_profile_owner_fk
    FOREIGN KEY (profile_id, owner_id)
    REFERENCES api_addressbookprofile (id, owner_id)
    ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED NOT VALID
    """,
    "ALTER TABLE api_remotepeer_tags VALIDATE CONSTRAINT peer_tag_peer_profile_fk",
    "ALTER TABLE api_remotepeer_tags VALIDATE CONSTRAINT peer_tag_tag_profile_fk",
    "ALTER TABLE api_sharelink_peers VALIDATE CONSTRAINT share_peer_link_owner_fk",
    "ALTER TABLE api_sharelink_peers VALIDATE CONSTRAINT share_peer_peer_profile_fk",
    "ALTER TABLE api_sharelink_peers VALIDATE CONSTRAINT share_peer_profile_owner_fk",
    "CREATE INDEX peer_tag_profile_idx ON api_remotepeer_tags (profile_id)",
    "CREATE INDEX share_peer_scope_idx ON api_sharelink_peers (profile_id, owner_id)",
    """
    CREATE FUNCTION api_fill_peer_tag_scope() RETURNS trigger
    LANGUAGE plpgsql AS $$
    DECLARE
        peer_profile_id integer;
        tag_profile_id integer;
    BEGIN
        SELECT peer.profile_id, tag.profile_id
        INTO peer_profile_id, tag_profile_id
        FROM api_remotepeer AS peer
        JOIN api_remotetag AS tag ON tag.id = NEW.remotetag_id
        WHERE peer.id = NEW.remotepeer_id;
        IF peer_profile_id IS NULL OR tag_profile_id IS NULL OR peer_profile_id <> tag_profile_id THEN
            RAISE EXCEPTION 'peer and tag must belong to the same address book'
                USING ERRCODE = '23514', CONSTRAINT = 'peer_tag_scope_match';
        END IF;
        NEW.profile_id := peer_profile_id;
        RETURN NEW;
    END
    $$
    """,
    """
    CREATE TRIGGER api_peer_tag_scope_fill
    BEFORE INSERT OR UPDATE OF remotepeer_id, remotetag_id, profile_id
    ON api_remotepeer_tags
    FOR EACH ROW EXECUTE FUNCTION api_fill_peer_tag_scope()
    """,
    """
    CREATE FUNCTION api_fill_share_peer_scope() RETURNS trigger
    LANGUAGE plpgsql AS $$
    DECLARE
        peer_profile_id integer;
        peer_owner_id integer;
        link_creator_id integer;
    BEGIN
        SELECT peer.profile_id, profile.owner_id, link.creator_id
        INTO peer_profile_id, peer_owner_id, link_creator_id
        FROM api_remotepeer AS peer
        JOIN api_addressbookprofile AS profile ON profile.id = peer.profile_id
        JOIN api_sharelink AS link ON link.id = NEW.sharelink_id
        WHERE peer.id = NEW.remotepeer_id;
        IF peer_profile_id IS NULL OR peer_owner_id IS NULL OR link_creator_id IS NULL
           OR peer_owner_id <> link_creator_id THEN
            RAISE EXCEPTION 'share link may contain only peers owned by its creator'
                USING ERRCODE = '23514', CONSTRAINT = 'share_peer_owner_scope_match';
        END IF;
        NEW.profile_id := peer_profile_id;
        NEW.owner_id := peer_owner_id;
        RETURN NEW;
    END
    $$
    """,
    """
    CREATE TRIGGER api_share_peer_scope_fill
    BEFORE INSERT OR UPDATE OF sharelink_id, remotepeer_id, profile_id, owner_id
    ON api_sharelink_peers
    FOR EACH ROW EXECUTE FUNCTION api_fill_share_peer_scope()
    """,
)


SQLITE_INSTALL = (
    """
    ALTER TABLE api_remotepeer_tags
    ADD COLUMN profile_id integer NULL
    """,
    """
    ALTER TABLE api_sharelink_peers
    ADD COLUMN profile_id integer NULL
    """,
    """
    ALTER TABLE api_sharelink_peers
    ADD COLUMN owner_id integer NULL
    """,
    """
    UPDATE api_remotepeer_tags
    SET profile_id = (
        SELECT peer.profile_id
        FROM api_remotepeer AS peer
        WHERE peer.id = api_remotepeer_tags.remotepeer_id
    )
    """,
    """
    UPDATE api_sharelink_peers
    SET profile_id = (
            SELECT peer.profile_id
            FROM api_remotepeer AS peer
            WHERE peer.id = api_sharelink_peers.remotepeer_id
        ),
        owner_id = (
            SELECT profile.owner_id
            FROM api_remotepeer AS peer
            JOIN api_addressbookprofile AS profile ON profile.id = peer.profile_id
            WHERE peer.id = api_sharelink_peers.remotepeer_id
        )
    """,
    "CREATE INDEX peer_tag_profile_idx ON api_remotepeer_tags (profile_id)",
    "CREATE INDEX share_peer_scope_idx ON api_sharelink_peers (profile_id, owner_id)",
    """
    CREATE TRIGGER api_peer_tag_scope_insert_guard
    BEFORE INSERT ON api_remotepeer_tags
    WHEN NOT EXISTS (
        SELECT 1
        FROM api_remotepeer AS peer
        JOIN api_remotetag AS tag ON tag.id = NEW.remotetag_id
        WHERE peer.id = NEW.remotepeer_id AND peer.profile_id = tag.profile_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'peer_tag_scope_match');
    END
    """,
    """
    CREATE TRIGGER api_peer_tag_scope_insert_fill
    AFTER INSERT ON api_remotepeer_tags
    BEGIN
        UPDATE api_remotepeer_tags
        SET profile_id = (SELECT profile_id FROM api_remotepeer WHERE id = NEW.remotepeer_id)
        WHERE id = NEW.id;
    END
    """,
    """
    CREATE TRIGGER api_peer_tag_scope_update_guard
    BEFORE UPDATE OF remotepeer_id, remotetag_id, profile_id ON api_remotepeer_tags
    WHEN NOT EXISTS (
        SELECT 1
        FROM api_remotepeer AS peer
        JOIN api_remotetag AS tag ON tag.id = NEW.remotetag_id
        WHERE peer.id = NEW.remotepeer_id
          AND peer.profile_id = tag.profile_id
          AND NEW.profile_id = peer.profile_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'peer_tag_scope_match');
    END
    """,
    """
    CREATE TRIGGER api_share_peer_scope_insert_guard
    BEFORE INSERT ON api_sharelink_peers
    WHEN NOT EXISTS (
        SELECT 1
        FROM api_sharelink AS link
        JOIN api_remotepeer AS peer ON peer.id = NEW.remotepeer_id
        JOIN api_addressbookprofile AS profile ON profile.id = peer.profile_id
        WHERE link.id = NEW.sharelink_id AND link.creator_id = profile.owner_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'share_peer_owner_scope_match');
    END
    """,
    """
    CREATE TRIGGER api_share_peer_scope_insert_fill
    AFTER INSERT ON api_sharelink_peers
    BEGIN
        UPDATE api_sharelink_peers
        SET profile_id = (
                SELECT profile_id FROM api_remotepeer WHERE id = NEW.remotepeer_id
            ),
            owner_id = (
                SELECT profile.owner_id
                FROM api_remotepeer AS peer
                JOIN api_addressbookprofile AS profile ON profile.id = peer.profile_id
                WHERE peer.id = NEW.remotepeer_id
            )
        WHERE id = NEW.id;
    END
    """,
    """
    CREATE TRIGGER api_share_peer_scope_update_guard
    BEFORE UPDATE OF sharelink_id, remotepeer_id, profile_id, owner_id ON api_sharelink_peers
    WHEN NOT EXISTS (
        SELECT 1
        FROM api_sharelink AS link
        JOIN api_remotepeer AS peer ON peer.id = NEW.remotepeer_id
        JOIN api_addressbookprofile AS profile ON profile.id = peer.profile_id
        WHERE link.id = NEW.sharelink_id
          AND link.creator_id = profile.owner_id
          AND NEW.profile_id = peer.profile_id
          AND NEW.owner_id = profile.owner_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'share_peer_owner_scope_match');
    END
    """,
    """
    CREATE TRIGGER api_remotepeer_scope_update_guard
    BEFORE UPDATE OF profile_id ON api_remotepeer
    WHEN EXISTS (
        SELECT 1
        FROM api_remotepeer_tags AS membership
        JOIN api_remotetag AS tag ON tag.id = membership.remotetag_id
        WHERE membership.remotepeer_id = OLD.id
          AND (
            tag.profile_id <> NEW.profile_id
            OR membership.profile_id <> NEW.profile_id
          )
    ) OR EXISTS (
        SELECT 1
        FROM api_sharelink_peers AS membership
        JOIN api_sharelink AS link ON link.id = membership.sharelink_id
        JOIN api_addressbookprofile AS profile ON profile.id = NEW.profile_id
        WHERE membership.remotepeer_id = OLD.id
          AND (
            link.creator_id <> profile.owner_id
            OR membership.profile_id <> NEW.profile_id
            OR membership.owner_id <> profile.owner_id
          )
    )
    BEGIN
        SELECT RAISE(ABORT, 'remote_peer_scope_change');
    END
    """,
    """
    CREATE TRIGGER api_remotetag_scope_update_guard
    BEFORE UPDATE OF profile_id ON api_remotetag
    WHEN EXISTS (
        SELECT 1
        FROM api_remotepeer_tags AS membership
        JOIN api_remotepeer AS peer ON peer.id = membership.remotepeer_id
        WHERE membership.remotetag_id = OLD.id AND peer.profile_id <> NEW.profile_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'remote_tag_scope_change');
    END
    """,
    """
    CREATE TRIGGER api_sharelink_scope_update_guard
    BEFORE UPDATE OF creator_id ON api_sharelink
    WHEN EXISTS (
        SELECT 1
        FROM api_sharelink_peers AS membership
        JOIN api_remotepeer AS peer ON peer.id = membership.remotepeer_id
        JOIN api_addressbookprofile AS profile ON profile.id = peer.profile_id
        WHERE membership.sharelink_id = OLD.id AND profile.owner_id <> NEW.creator_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'share_link_creator_scope_change');
    END
    """,
    """
    CREATE TRIGGER api_abprofile_owner_scope_update_guard
    BEFORE UPDATE OF owner_id ON api_addressbookprofile
    WHEN EXISTS (
        SELECT 1
        FROM api_sharelink_peers AS membership
        JOIN api_sharelink AS link ON link.id = membership.sharelink_id
        WHERE membership.profile_id = OLD.id AND link.creator_id <> NEW.owner_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'address_book_owner_scope_change');
    END
    """,
)


def install_scope_authority(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    if vendor not in {"postgresql", "sqlite"}:
        raise RuntimeError(f"unsupported address-book scope database backend: {vendor}")
    with schema_editor.connection.cursor() as cursor:
        _refuse_historical_scope_violations(cursor)
        statements = POSTGRESQL_INSTALL if vendor == "postgresql" else SQLITE_INSTALL
        for statement in statements:
            cursor.execute(statement)


POSTGRESQL_REMOVE = (
    "DROP TRIGGER api_share_peer_scope_fill ON api_sharelink_peers",
    "DROP FUNCTION api_fill_share_peer_scope()",
    "DROP TRIGGER api_peer_tag_scope_fill ON api_remotepeer_tags",
    "DROP FUNCTION api_fill_peer_tag_scope()",
    "ALTER TABLE api_sharelink_peers DROP CONSTRAINT share_peer_profile_owner_fk",
    "ALTER TABLE api_sharelink_peers DROP CONSTRAINT share_peer_peer_profile_fk",
    "ALTER TABLE api_sharelink_peers DROP CONSTRAINT share_peer_link_owner_fk",
    "ALTER TABLE api_remotepeer_tags DROP CONSTRAINT peer_tag_tag_profile_fk",
    "ALTER TABLE api_remotepeer_tags DROP CONSTRAINT peer_tag_peer_profile_fk",
    "DROP INDEX share_peer_scope_idx",
    "DROP INDEX peer_tag_profile_idx",
    "ALTER TABLE api_sharelink DROP CONSTRAINT sharelink_id_creator_scope_key",
    "ALTER TABLE api_addressbookprofile DROP CONSTRAINT abprofile_id_owner_scope_key",
    "ALTER TABLE api_remotetag DROP CONSTRAINT remotetag_id_profile_scope_key",
    "ALTER TABLE api_remotepeer DROP CONSTRAINT remotepeer_id_profile_scope_key",
    "ALTER TABLE api_sharelink_peers DROP COLUMN owner_id",
    "ALTER TABLE api_sharelink_peers DROP COLUMN profile_id",
    "ALTER TABLE api_remotepeer_tags DROP COLUMN profile_id",
)

SQLITE_TRIGGERS = (
    "api_abprofile_owner_scope_update_guard",
    "api_sharelink_scope_update_guard",
    "api_remotetag_scope_update_guard",
    "api_remotepeer_scope_update_guard",
    "api_share_peer_scope_update_guard",
    "api_share_peer_scope_insert_fill",
    "api_share_peer_scope_insert_guard",
    "api_peer_tag_scope_update_guard",
    "api_peer_tag_scope_insert_fill",
    "api_peer_tag_scope_insert_guard",
)


def remove_scope_authority(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    with schema_editor.connection.cursor() as cursor:
        if vendor == "postgresql":
            for statement in POSTGRESQL_REMOVE:
                cursor.execute(statement)
        elif vendor == "sqlite":
            for trigger in SQLITE_TRIGGERS:
                cursor.execute(f"DROP TRIGGER {trigger}")
            cursor.execute("DROP INDEX share_peer_scope_idx")
            cursor.execute("DROP INDEX peer_tag_profile_idx")
            cursor.execute("ALTER TABLE api_sharelink_peers DROP COLUMN owner_id")
            cursor.execute("ALTER TABLE api_sharelink_peers DROP COLUMN profile_id")
            cursor.execute("ALTER TABLE api_remotepeer_tags DROP COLUMN profile_id")
        else:
            raise RuntimeError(f"unsupported address-book scope database backend: {vendor}")


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0026_username_canonical_identity"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(install_scope_authority, remove_scope_authority),
            ],
            state_operations=[
                migrations.CreateModel(
                    name="RemotePeerTagMembership",
                    fields=[
                        (
                            "id",
                            models.AutoField(
                                auto_created=True,
                                primary_key=True,
                                serialize=False,
                                verbose_name="ID",
                            ),
                        ),
                        (
                            "peer",
                            models.ForeignKey(
                                db_column="remotepeer_id",
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="tag_memberships",
                                to="api.remotepeer",
                            ),
                        ),
                        (
                            "profile",
                            models.ForeignKey(
                                db_constraint=False,
                                db_index=False,
                                editable=False,
                                null=True,
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="peer_tag_memberships",
                                to="api.addressbookprofile",
                            ),
                        ),
                        (
                            "tag",
                            models.ForeignKey(
                                db_column="remotetag_id",
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="peer_memberships",
                                to="api.remotetag",
                            ),
                        ),
                    ],
                    options={
                        "db_table": "api_remotepeer_tags",
                        "indexes": [
                            models.Index(fields=["profile"], name="peer_tag_profile_idx"),
                        ],
                        "unique_together": {("peer", "tag")},
                    },
                ),
                migrations.AlterField(
                    model_name="remotepeer",
                    name="tags",
                    field=models.ManyToManyField(
                        blank=True,
                        related_name="peers",
                        through="api.RemotePeerTagMembership",
                        through_fields=("peer", "tag"),
                        to="api.remotetag",
                        verbose_name="标签",
                    ),
                ),
                migrations.CreateModel(
                    name="ShareLinkPeerMembership",
                    fields=[
                        (
                            "id",
                            models.AutoField(
                                auto_created=True,
                                primary_key=True,
                                serialize=False,
                                verbose_name="ID",
                            ),
                        ),
                        (
                            "owner",
                            models.ForeignKey(
                                db_constraint=False,
                                db_index=False,
                                editable=False,
                                null=True,
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="share_link_peer_memberships",
                                to=settings.AUTH_USER_MODEL,
                            ),
                        ),
                        (
                            "peer",
                            models.ForeignKey(
                                db_column="remotepeer_id",
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="share_link_memberships",
                                to="api.remotepeer",
                            ),
                        ),
                        (
                            "profile",
                            models.ForeignKey(
                                db_constraint=False,
                                db_index=False,
                                editable=False,
                                null=True,
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="share_link_peer_memberships",
                                to="api.addressbookprofile",
                            ),
                        ),
                        (
                            "share_link",
                            models.ForeignKey(
                                db_column="sharelink_id",
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="peer_memberships",
                                to="api.sharelink",
                            ),
                        ),
                    ],
                    options={
                        "db_table": "api_sharelink_peers",
                        "indexes": [
                            models.Index(
                                fields=["profile", "owner"],
                                name="share_peer_scope_idx",
                            ),
                        ],
                        "unique_together": {("share_link", "peer")},
                    },
                ),
                migrations.AlterField(
                    model_name="sharelink",
                    name="peers",
                    field=models.ManyToManyField(
                        related_name="share_links",
                        through="api.ShareLinkPeerMembership",
                        through_fields=("share_link", "peer"),
                        to="api.remotepeer",
                        verbose_name="机器列表",
                    ),
                ),
            ],
        ),
    ]
