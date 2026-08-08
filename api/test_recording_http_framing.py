import datetime
import hashlib
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from io import BytesIO, StringIO
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from django.core.handlers.wsgi import WSGIRequest
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from api import ingestion_governance, views_api
from api.models import RecordingUpload, RemoteDevice, RemoteToken, UserProfile

_MISSING = object()


def _json(response):
    return json.loads(response.content)


class RecordingHttpFramingTests(TestCase):
    def setUp(self):
        self.user = UserProfile.objects.create_user(
            username="framing-owner",
            password="framing-owner-password",  # noqa: S106 - isolated test credential
        )
        self.device = RemoteDevice.objects.create(
            rid="864209753",
            cpu="-",
            hostname="framing-recorder",
            memory="-",
            os="linux",
            uuid="framing-device-uuid",
            public_key_hash=hashlib.sha256(b"framing-public-key").hexdigest(),
            username="framing-recorder",
            version="test",
            owner=self.user,
        )
        self.raw_token = "framing-device-token"  # noqa: S105 - isolated test token
        RemoteToken.objects.create(
            device=self.device,
            subject_user=self.user,
            access_token=hashlib.sha256(self.raw_token.encode()).hexdigest(),
            credential_hash=self.user.get_session_auth_hash(),
            expires_at=timezone.now() + datetime.timedelta(hours=1),
        )
        self.upload_root = tempfile.TemporaryDirectory()
        self.addCleanup(self.upload_root.cleanup)
        self.settings_override = override_settings(
            RECORD_UPLOAD_ROOT=Path(self.upload_root.name),
            RECORD_UPLOAD_MAX_CHUNK_BYTES=16,
            RECORD_UPLOAD_MAX_FILE_BYTES=64,
            RECORD_UPLOAD_REQUIRE_MOUNT=False,
            RECORD_UPLOAD_VOLUME_RESERVE_BYTES=0,
            RECORD_UPLOAD_VOLUME_RESERVE_INODES=0,
            RECORD_UPLOAD_CAPABILITY_CACHE_SECONDS=0,
            DATA_UPLOAD_MAX_MEMORY_SIZE=16,
        )
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)

    def _request(
        self,
        operation,
        *,
        body=b"",
        content_length=_MISSING,
        transfer_encoding=_MISSING,
        extra_meta=None,
        **params,
    ):
        query = {
            "version": "2",
            "type": operation,
            **{key: str(value) for key, value in params.items()},
        }
        stream = BytesIO(body)
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/api/record",
            "QUERY_STRING": urlencode(query),
            "SERVER_NAME": "testserver",
            "SERVER_PORT": "80",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "CONTENT_TYPE": "application/octet-stream",
            "HTTP_AUTHORIZATION": f"Bearer {self.raw_token}",
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "http",
            "wsgi.input": stream,
            "wsgi.errors": StringIO(),
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
        }
        if content_length is not _MISSING:
            environ["CONTENT_LENGTH"] = content_length
        if transfer_encoding is not _MISSING:
            environ["HTTP_TRANSFER_ENCODING"] = transfer_encoding
        if extra_meta:
            environ.update(extra_meta)
        return views_api.record(WSGIRequest(environ)), stream

    def _new_params(self, case):
        return {
            "file": f"framing-{case}.webm",
            "create_id": str(uuid.UUID(int=case, version=4)),
        }

    def test_missing_length_and_transfer_encoding_are_rejected_before_mutation(self):
        cases = (
            ("missing", _MISSING, _MISSING, 411, "content_length_required"),
            ("chunked", _MISSING, "chunked", 400, "unsupported_transfer_encoding"),
            ("identity", _MISSING, "identity", 400, "unsupported_transfer_encoding"),
            ("cl-and-te", "0", "chunked", 400, "unsupported_transfer_encoding"),
        )
        for index, (name, content_length, transfer_encoding, status, code) in enumerate(cases, start=1):
            with self.subTest(name=name):
                with patch.object(ingestion_governance, "check_recording_storage_capability") as storage_check:
                    response, stream = self._request(
                        "new",
                        body=b"ACTUAL-HIDDEN-BODY",
                        content_length=content_length,
                        transfer_encoding=transfer_encoding,
                        **self._new_params(index),
                    )
                self.assertEqual(response.status_code, status, response.content)
                self.assertEqual(_json(response)["code"], code)
                self.assertEqual(stream.tell(), 0)
                storage_check.assert_not_called()
                self.assertFalse(RecordingUpload.objects.filter(filename=f"framing-{index}.webm").exists())

    def test_invalid_and_oversized_content_lengths_fail_before_storage_admission(self):
        cases = (
            ("", 411, "content_length_required"),
            ("-1", 400, "invalid_content_length"),
            ("+0", 400, "invalid_content_length"),
            (" 0", 400, "invalid_content_length"),
            ("0,0", 400, "invalid_content_length"),
            ("four", 400, "invalid_content_length"),
            ("９", 400, "invalid_content_length"),
            ("9" * 100, 413, "chunk_too_large"),
            ("17", 413, "chunk_too_large"),
        )
        for index, (content_length, status, code) in enumerate(cases, start=20):
            with self.subTest(content_length=content_length):
                with patch.object(ingestion_governance, "check_recording_storage_capability") as storage_check:
                    response, stream = self._request(
                        "new",
                        body=b"untrusted",
                        content_length=content_length,
                        **self._new_params(index),
                    )
                self.assertEqual(response.status_code, status, response.content)
                self.assertEqual(_json(response)["code"], code)
                self.assertEqual(stream.tell(), 0)
                storage_check.assert_not_called()
                self.assertFalse(RecordingUpload.objects.filter(filename=f"framing-{index}.webm").exists())

    def test_nonstandard_content_length_alias_is_rejected_as_ambiguous(self):
        with patch.object(ingestion_governance, "check_recording_storage_capability") as storage_check:
            response, stream = self._request(
                "new",
                body=b"untrusted",
                content_length="0",
                extra_meta={"HTTP_CONTENT_LENGTH": "0"},
                **self._new_params(50),
            )

        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(_json(response)["code"], "invalid_content_length")
        self.assertEqual(stream.tell(), 0)
        storage_check.assert_not_called()
        self.assertFalse(RecordingUpload.objects.filter(filename="framing-50.webm").exists())

    def test_missing_length_cannot_abort_an_existing_upload(self):
        created, _stream = self._request("new", content_length="0", **self._new_params(100))
        self.assertEqual(created.status_code, 201, created.content)
        upload_id = _json(created)["upload_id"]

        rejected, stream = self._request(
            "abort",
            body=b"hidden-abort-body",
            upload_id=upload_id,
        )

        self.assertEqual(rejected.status_code, 411, rejected.content)
        self.assertEqual(_json(rejected)["code"], "content_length_required")
        self.assertEqual(stream.tell(), 0)
        self.assertEqual(RecordingUpload.objects.get(upload_id=upload_id).state, RecordingUpload.STATE_ACTIVE)

    def test_valid_fixed_length_create_and_part_remain_supported(self):
        created, create_stream = self._request("new", content_length="000", **self._new_params(200))
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(create_stream.tell(), 0)
        state = _json(created)
        body = b"framed-body"

        committed, part_stream = self._request(
            "part",
            body=body,
            content_length=str(len(body)),
            upload_id=state["upload_id"],
            chunk_id=str(uuid.UUID(int=201, version=4)),
            offset=0,
            revision=0,
            length=len(body),
            digest=hashlib.sha256(body).hexdigest(),
        )

        self.assertEqual(committed.status_code, 200, committed.content)
        self.assertEqual(_json(committed)["offset"], len(body))
        self.assertEqual(part_stream.tell(), len(body))


class RecordingGunicornFramingTests(SimpleTestCase):
    raw_token = "raw-gunicorn-framing-token"  # noqa: S105 - isolated test token

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.root = tempfile.TemporaryDirectory(prefix="camellia-recording-framing-")
        cls.addClassCleanup(cls.root.cleanup)
        root = Path(cls.root.name)
        cls.database_path = root / "framing.sqlite3"
        cls.socket_path = root / "gunicorn.sock"
        cls.log_path = root / "gunicorn.log"
        upload_root = root / "records"
        upload_root.mkdir(mode=0o700)
        cls.environment = {key: value for key, value in os.environ.items() if not key.startswith("CAMELLIA_REMOTE_")}
        cls.environment.update(
            {
                "CAMELLIA_REMOTE_DEBUG": "true",
                "CAMELLIA_REMOTE_SECRET_KEY": "raw-gunicorn-framing-secret",
                "CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN": "raw-gunicorn-device-token-00000000",
                "CAMELLIA_REMOTE_ALLOWED_HOSTS": "127.0.0.1,testserver",
                "CAMELLIA_REMOTE_SQLITE_DB_PATH": str(cls.database_path),
                "CAMELLIA_REMOTE_RECORD_UPLOAD_ROOT": str(upload_root),
                "CAMELLIA_REMOTE_RECORD_UPLOAD_MAX_CHUNK_BYTES": "65536",
                "CAMELLIA_REMOTE_RECORD_UPLOAD_MAX_FILE_BYTES": "65536",
                "CAMELLIA_REMOTE_RECORD_REQUIRE_MOUNT": "false",
                "CAMELLIA_REMOTE_RECORD_VOLUME_RESERVE_BYTES": "0",
                "CAMELLIA_REMOTE_RECORD_VOLUME_RESERVE_INODES": "0",
                "CAMELLIA_REMOTE_RECORD_CAPABILITY_CACHE_SECONDS": "0",
            }
        )
        project_root = Path(__file__).resolve().parents[1]
        subprocess.run(  # noqa: S603 - fixed interpreter and repository command
            [sys.executable, "manage.py", "migrate", "--noinput", "--verbosity", "0"],
            cwd=project_root,
            env=cls.environment,
            check=True,
            timeout=30,
        )
        seed = f"""
import datetime, hashlib
import django
django.setup()
from django.utils import timezone
from api.models import RemoteDevice, RemoteToken, UserProfile
user = UserProfile.objects.create_user(username="raw-framing-owner", password="raw-framing-password")
device = RemoteDevice.objects.create(
    rid="975310864", cpu="-", hostname="raw-framing-recorder", memory="-", os="linux",
    uuid="raw-framing-device-uuid", public_key_hash=hashlib.sha256(b"raw-framing-key").hexdigest(),
    username="raw-framing-recorder", version="test", owner=user,
)
RemoteToken.objects.create(
    device=device, subject_user=user, access_token=hashlib.sha256({cls.raw_token!r}.encode()).hexdigest(),
    credential_hash=user.get_session_auth_hash(), expires_at=timezone.now() + datetime.timedelta(hours=1),
)
"""
        subprocess.run(  # noqa: S603 - fixed interpreter and isolated seed
            [sys.executable, "-c", seed],
            cwd=project_root,
            env=cls.environment,
            check=True,
            timeout=30,
        )
        cls.log_file = cls.log_path.open("w+b")
        cls.addClassCleanup(cls.log_file.close)
        cls.process = subprocess.Popen(  # noqa: S603 - fixed interpreter and repository WSGI entry point
            [
                sys.executable,
                "-m",
                "gunicorn",
                "camellia_remote_management.wsgi:application",
                "--bind",
                f"unix:{cls.socket_path}",
                "--workers",
                "1",
                "--threads",
                "2",
                "--keep-alive",
                "2",
                "--access-logfile",
                "-",
                "--error-logfile",
                "-",
            ],
            cwd=project_root,
            env=cls.environment,
            stdout=cls.log_file,
            stderr=subprocess.STDOUT,
        )
        cls.addClassCleanup(cls._stop_gunicorn)
        deadline = time.monotonic() + 10
        while not cls.socket_path.exists() and time.monotonic() < deadline:
            if cls.process.poll() is not None:
                cls.log_file.flush()
                raise RuntimeError(cls.log_path.read_text(errors="replace"))
            time.sleep(0.05)
        if not cls.socket_path.exists():
            raise TimeoutError("Gunicorn did not create its test socket")

    @classmethod
    def _stop_gunicorn(cls):
        process = getattr(cls, "process", None)
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def _exchange(self, request):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(str(self.socket_path))
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                try:
                    chunk = connection.recv(65536)
                except TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        response = b"".join(chunks)
        self.assertTrue(response, self._gunicorn_log())
        return response

    def _gunicorn_log(self):
        self.log_file.flush()
        return self.log_path.read_text(errors="replace")

    def _recording_count(self):
        with sqlite3.connect(self.database_path) as database:
            return database.execute("SELECT COUNT(*) FROM api_recordingupload").fetchone()[0]

    def _new_path(self, case):
        return (
            "/api/record?"
            + urlencode(
                {
                    "version": "2",
                    "type": "new",
                    "file": f"raw-{case}.webm",
                    "create_id": str(uuid.UUID(int=case, version=4)),
                }
            )
        ).encode()

    def _request_head(self, path, *headers):
        lines = [
            b"POST " + path + b" HTTP/1.1",
            b"Host: testserver",
            f"Authorization: Bearer {self.raw_token}".encode(),
        ]
        lines.extend(headers)
        return b"\r\n".join(lines) + b"\r\n\r\n"

    def test_raw_gunicorn_rejects_ambiguous_framing_without_mutation(self):
        initial_count = self._recording_count()
        missing = self._exchange(self._request_head(self._new_path(300), b"Connection: close"))
        self.assertEqual(re.findall(rb"HTTP/1\.1 (\d{3})", missing)[0], b"411", self._gunicorn_log())
        self.assertEqual(self._recording_count(), initial_count)

        body = b"raw-chunked-body"
        chunked_request = (
            self._request_head(
                self._new_path(301),
                b"Transfer-Encoding: chunked",
                b"Connection: keep-alive",
            )
            + f"{len(body):X}\r\n".encode()
            + body
            + b"\r\n0\r\n\r\n"
            + b"GET /health/live HTTP/1.1\r\nHost: testserver\r\nConnection: close\r\n\r\n"
        )
        chunked = self._exchange(chunked_request)
        self.assertEqual(
            re.findall(rb"HTTP/1\.1 (\d{3})", chunked),
            [b"400", b"200"],
            self._gunicorn_log(),
        )
        self.assertNotIn(b"201 Created", chunked)
        self.assertEqual(self._recording_count(), initial_count)

        duplicate_length = self._exchange(
            self._request_head(
                self._new_path(302),
                b"Content-Length: 0",
                b"Content-Length: 0",
                b"Connection: close",
            )
        )
        self.assertEqual(re.findall(rb"HTTP/1\.1 (\d{3})", duplicate_length)[0], b"400", self._gunicorn_log())
        self.assertEqual(self._recording_count(), initial_count)

        cl_and_te = self._exchange(
            self._request_head(
                self._new_path(303),
                b"Content-Length: 0",
                b"Transfer-Encoding: chunked",
                b"Connection: close",
            )
            + b"0\r\n\r\n"
        )
        self.assertEqual(re.findall(rb"HTTP/1\.1 (\d{3})", cl_and_te)[0], b"400", self._gunicorn_log())
        self.assertEqual(self._recording_count(), initial_count)

    def test_raw_gunicorn_accepts_fixed_zero_length_and_keeps_next_request_aligned(self):
        initial_count = self._recording_count()
        valid_and_health = self._exchange(
            self._request_head(
                self._new_path(400),
                b"Content-Length: 0",
                b"Connection: keep-alive",
            )
            + b"GET /health/live HTTP/1.1\r\nHost: testserver\r\nConnection: close\r\n\r\n"
        )

        self.assertEqual(re.findall(rb"HTTP/1\.1 (\d{3})", valid_and_health), [b"201", b"200"], self._gunicorn_log())
        self.assertEqual(self._recording_count(), initial_count + 1)
