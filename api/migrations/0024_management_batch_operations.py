import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0023_audit_evidence_receipts"),
    ]

    operations = [
        migrations.CreateModel(
            name="ManagementBatchOperation",
            fields=[
                ("generation", models.BigAutoField(primary_key=True, serialize=False)),
                ("operation_id", models.UUIDField(editable=False, unique=True)),
                ("operation", models.CharField(editable=False, max_length=64)),
                ("request_digest", models.CharField(editable=False, max_length=64)),
                ("status_code", models.PositiveSmallIntegerField(editable=False)),
                ("response", models.JSONField(editable=False)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "actor",
                    models.ForeignKey(
                        editable=False,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="management_batch_operations",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ("-generation",),
                "indexes": [
                    models.Index(
                        fields=["actor", "created_at"],
                        name="mgmt_batch_actor_created_idx",
                    )
                ],
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(status_code__gte=200, status_code__lt=500),
                        name="valid_mgmt_batch_status",
                    )
                ],
            },
        ),
    ]
