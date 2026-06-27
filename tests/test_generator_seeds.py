"""
Unit tests for pipeline/phase2/generator.py seed management.

Verifies that:
- _TRAIN_OFFSET and _TEST_OFFSET are what the code comments promise
- The resulting seed ranges [train_start, train_end) and [test_start, test_end)
  are disjoint for any reasonable (train, test) count
- The 10 000-unit gap is preserved for realistic dataset sizes
"""

import pytest

from pipeline.phase2.generator import _TRAIN_OFFSET, _TEST_OFFSET


# ===========================================================================
# Static constant checks
# ===========================================================================

class TestSeedConstants:
    def test_train_offset_is_zero(self):
        assert _TRAIN_OFFSET == 0

    def test_test_offset_is_ten_thousand(self):
        assert _TEST_OFFSET == 10_000

    def test_gap_at_least_ten_thousand(self):
        assert (_TEST_OFFSET - _TRAIN_OFFSET) >= 10_000

    def test_train_offset_less_than_test_offset(self):
        assert _TRAIN_OFFSET < _TEST_OFFSET


# ===========================================================================
# Seed range disjointness
# ===========================================================================

def _train_seeds(n: int, extra_offset: int = 0) -> set[int]:
    return {_TRAIN_OFFSET + extra_offset + i for i in range(1, n + 1)}


def _test_seeds(n: int, extra_offset: int = 0) -> set[int]:
    return {_TEST_OFFSET + extra_offset + i for i in range(1, n + 1)}


class TestSeedDisjointness:
    def test_typical_30_train_10_test_disjoint(self):
        train = _train_seeds(30)
        test  = _test_seeds(10)
        assert train.isdisjoint(test)

    def test_max_9999_train_disjoint_from_test(self):
        # 9 999 is the largest train count that stays below _TEST_OFFSET
        train = _train_seeds(9_999)
        test  = _test_seeds(1)
        assert train.isdisjoint(test)

    def test_train_seeds_start_at_one(self):
        seeds = _train_seeds(5)
        assert min(seeds) == _TRAIN_OFFSET + 1

    def test_test_seeds_start_at_test_offset_plus_one(self):
        seeds = _test_seeds(5)
        assert min(seeds) == _TEST_OFFSET + 1

    def test_no_overlap_with_extra_offset(self):
        # extra offsets up to 5000 still stay disjoint for up to 200 scenarios
        for extra in (0, 100, 500, 5_000):
            train = _train_seeds(200, extra_offset=extra)
            test  = _test_seeds(200, extra_offset=extra)
            assert train.isdisjoint(test), f"overlap at extra_offset={extra}"

    def test_train_range_contiguous(self):
        n = 50
        seeds = sorted(_train_seeds(n))
        expected = list(range(_TRAIN_OFFSET + 1, _TRAIN_OFFSET + n + 1))
        assert seeds == expected

    def test_test_range_contiguous(self):
        n = 20
        seeds = sorted(_test_seeds(n))
        expected = list(range(_TEST_OFFSET + 1, _TEST_OFFSET + n + 1))
        assert seeds == expected

    def test_train_and_test_seeds_together_unique(self):
        train = _train_seeds(100)
        test  = _test_seeds(50)
        combined = train | test
        # No duplicates — combined size equals sum of individual sizes
        assert len(combined) == len(train) + len(test)


# ===========================================================================
# Boundary: what happens when train count approaches gap size
# ===========================================================================

class TestSeedGapBoundary:
    def test_9999_train_does_not_touch_test_at_10001(self):
        max_train_seed = _TRAIN_OFFSET + 9_999
        min_test_seed  = _TEST_OFFSET + 1
        assert max_train_seed < min_test_seed

    def test_gap_formula(self):
        """Gap = _TEST_OFFSET - _TRAIN_OFFSET = 10 000; seed 10 000 not issued by
        either range (train stops at N, test starts at 10 001)."""
        boundary = _TEST_OFFSET  # = 10 000
        # train seeds: 1 … N (N < 10 000 for normal use)
        # test seeds: 10 001 …
        assert boundary not in _train_seeds(9_999)
        assert boundary not in _test_seeds(9_999)
