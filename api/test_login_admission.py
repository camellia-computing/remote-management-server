import concurrent.futures
import datetime
import threading

from django.db import close_old_connections, connections
from django.test import TestCase, TransactionTestCase, skipUnlessDBFeature
from django.utils import timezone

from api.login_admission import (
    LOGIN_SCOPE,
    REGISTER_SCOPE,
    complete_login_success,
    reserve_login_attempt,
)
from api.models import LoginAdmissionLock, LoginAttempt


class LoginAdmissionTests(TestCase):
    def test_account_and_ip_budgets_are_atomic_and_bounded(self):
        account_admissions = [reserve_login_attempt("198.51.100.10", "alice") for _ in range(11)]
        self.assertEqual(sum(admission is not None for admission in account_admissions), 10)
        self.assertEqual(LoginAttempt.objects.filter(ip="198.51.100.10").count(), 10)

        ip_admissions = [reserve_login_attempt("198.51.100.11", f"user-{index}") for index in range(101)]
        self.assertEqual(sum(admission is not None for admission in ip_admissions), 100)
        self.assertEqual(LoginAttempt.objects.filter(ip="198.51.100.11").count(), 100)

    def test_ipv6_text_forms_share_one_canonical_budget(self):
        expanded = "2001:0db8:0000:0000:0000:0000:0000:0010"
        compressed = "2001:db8::10"
        admissions = [reserve_login_attempt(expanded, "alice") for _ in range(5)]
        admissions.extend(reserve_login_attempt(compressed, "alice") for _ in range(5))

        self.assertTrue(all(admission is not None for admission in admissions))
        self.assertIsNone(reserve_login_attempt(compressed, "alice"))
        self.assertEqual(LoginAttempt.objects.filter(ip=compressed).count(), 10)

    def test_login_and_registration_have_distinct_scopes_but_share_ip_budget(self):
        login_admissions = [reserve_login_attempt("198.51.100.12", "alice", scope=LOGIN_SCOPE) for _ in range(10)]
        register_admissions = [reserve_login_attempt("198.51.100.12", "alice", scope=REGISTER_SCOPE) for _ in range(10)]
        self.assertTrue(all(admission is not None for admission in login_admissions))
        self.assertTrue(all(admission is not None for admission in register_admissions))
        other_admissions = [reserve_login_attempt("198.51.100.12", f"other-{index}") for index in range(80)]
        self.assertTrue(all(admission is not None for admission in other_admissions))
        self.assertIsNone(reserve_login_attempt("198.51.100.12", "other"))

    def test_success_clears_only_earlier_same_scope_admissions(self):
        first = reserve_login_attempt("198.51.100.13", "alice")
        second = reserve_login_attempt("198.51.100.13", "alice")
        later = reserve_login_attempt("198.51.100.13", "alice")
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertIsNotNone(later)

        complete_login_success(second)
        remaining = list(LoginAttempt.objects.filter(ip="198.51.100.13").values_list("pk", flat=True))
        self.assertEqual(remaining, [later.attempt_id])
        complete_login_success(first)
        self.assertTrue(LoginAttempt.objects.filter(pk=later.attempt_id).exists())
        complete_login_success(later)
        self.assertFalse(LoginAttempt.objects.filter(ip="198.51.100.13").exists())

    def test_expired_attempts_are_removed_before_new_reservation(self):
        admission = reserve_login_attempt("198.51.100.14", "alice")
        old = timezone.now() - datetime.timedelta(minutes=16)
        LoginAttempt.objects.filter(pk=admission.attempt_id).update(created_at=old)
        LoginAdmissionLock.objects.filter(ip="198.51.100.14").update(updated_at=old)

        replacement = reserve_login_attempt("198.51.100.14", "alice")
        self.assertIsNotNone(replacement)
        self.assertEqual(LoginAttempt.objects.filter(ip="198.51.100.14").count(), 1)


class PostgreSQLLoginAdmissionTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_account_admission_is_serialized(self):
        workers = 32
        barrier = threading.Barrier(workers + 1)

        def reserve(_index):
            close_old_connections()
            try:
                barrier.wait(timeout=20)
                return reserve_login_attempt("198.51.100.15", "alice")
            finally:
                connections.close_all()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(reserve, index) for index in range(workers)]
            barrier.wait(timeout=20)
            admissions = [future.result(timeout=60) for future in futures]

        self.assertEqual(sum(admission is not None for admission in admissions), 10)
        self.assertEqual(LoginAttempt.objects.filter(ip="198.51.100.15").count(), 10)
