from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0024_management_batch_operations"),
    ]

    operations = [
        migrations.AddField(
            model_name="oidcpendingauth",
            name="callback_claim_expires_at",
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="oidcpendingauth",
            name="callback_claim_generation",
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name="oidcpendingauth",
            name="callback_claim_owner",
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
        migrations.RemoveConstraint(
            model_name="oidcpendingauth",
            name="valid_oidc_pending_status",
        ),
        migrations.AddConstraint(
            model_name="oidcpendingauth",
            constraint=models.CheckConstraint(
                condition=models.Q(status__in=("pending", "processing", "done", "error")),
                name="valid_oidc_pending_status",
            ),
        ),
        migrations.AddConstraint(
            model_name="oidcpendingauth",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(
                        status="processing",
                        callback_claim_owner__isnull=False,
                        callback_claim_generation__gte=1,
                        callback_claim_expires_at__isnull=False,
                    )
                    | models.Q(
                        ~models.Q(status="processing"),
                        callback_claim_owner__isnull=True,
                        callback_claim_expires_at__isnull=True,
                    )
                ),
                name="valid_oidc_callback_claim",
            ),
        ),
    ]
