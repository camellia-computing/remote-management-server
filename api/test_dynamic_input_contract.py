"""Bounded deterministic mutation checks for Management JSON boundaries."""

from __future__ import annotations

import json
import time

from django.test import SimpleTestCase
from hypothesis import given, settings, strategies

from api.request_utils import InvalidJsonPayload, load_json_text

ITERATIONS = 512
MAX_INPUT = 4 * 1024
MAX_GENERATED_JSON_BYTES = 16 * 1024
MAX_RUNTIME_SECONDS = 60.0

_JSON_TEXT = strategies.text(
    alphabet=strategies.characters(exclude_categories=("Cs",)),
    max_size=32,
)
_JSON_KEYS = strategies.text(
    alphabet=strategies.characters(min_codepoint=0x20, max_codepoint=0x7E),
    max_size=32,
)
_JSON_VALUES = strategies.recursive(
    strategies.one_of(
        strategies.none(),
        strategies.booleans(),
        strategies.integers(min_value=-(2**63), max_value=2**63 - 1),
        strategies.floats(allow_nan=False, allow_infinity=False, width=64),
        _JSON_TEXT,
    ),
    lambda children: strategies.one_of(
        strategies.lists(children, max_size=16),
        strategies.dictionaries(_JSON_KEYS, children, max_size=16),
    ),
    max_leaves=32,
)


def _mutate(index: int) -> str:
    state = (0x63616D656C6C6961 + index) & ((1 << 64) - 1)
    length = state % (MAX_INPUT + 1)
    output = bytearray()
    for _ in range(length):
        state ^= (state << 13) & ((1 << 64) - 1)
        state ^= state >> 7
        state = (state * 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
        output.append((state >> 32) & 0xFF)
    return output.decode("latin-1")


class DynamicInputContractTests(SimpleTestCase):
    def test_mutations_are_bounded_and_fail_closed(self):
        started = time.monotonic()
        for index in range(ITERATIONS):
            payload = _mutate(index)
            try:
                value = load_json_text(payload, max_bytes=MAX_INPUT)
            except InvalidJsonPayload:
                continue
            self.assertLessEqual(len(payload.encode("utf-8")), MAX_INPUT)
            self.assertIsInstance(value, (dict, list, str, int, float, bool, type(None)))
        self.assertLessEqual(time.monotonic() - started, MAX_RUNTIME_SECONDS)

    def test_boundary_corpus_rejects_ambiguity_without_partial_result(self):
        cases = (
            '{"a":1,"a":2}',
            "[" * 65 + "0" + "]" * 65,
            '{"a":' + "9" * 129 + "}",
            '{"a":NaN}',
            '\ufeff{"a":1}',
            '{"a":1} trailing',
        )
        for payload in cases:
            with self.assertRaises(InvalidJsonPayload):
                load_json_text(payload, max_bytes=MAX_INPUT)

    def test_valid_seed_corpus_preserves_typed_values(self):
        cases = {
            "null": None,
            "true": True,
            '[-1,0,1,1.5,"text"]': [-1, 0, 1, 1.5, "text"],
            '{"nested":{"items":[1,2,3]}}': {"nested": {"items": [1, 2, 3]}},
        }
        for encoded, expected in cases.items():
            self.assertEqual(load_json_text(encoded, max_bytes=MAX_INPUT), expected)

    @settings(max_examples=100, derandomize=True, deadline=500)
    @given(_JSON_VALUES)
    def test_generated_valid_json_roundtrips_typed_values(self, value):
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        self.assertLessEqual(len(encoded.encode("utf-8")), MAX_GENERATED_JSON_BYTES)
        self.assertEqual(load_json_text(encoded, max_bytes=MAX_GENERATED_JSON_BYTES), value)
