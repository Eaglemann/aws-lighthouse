"""Reusable orchestration primitives for bounded, deterministic scan fan-out."""

from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor

from .scan_contract import merge_list_results
from .types import ScanResult


def collect_scan_results[ScanInput](
    inputs: Sequence[ScanInput],
    scan_one: Callable[[ScanInput], ScanResult],
    *,
    max_workers: int,
) -> ScanResult:
    """Run one scanner per input and merge envelopes in input order.

    ``ThreadPoolExecutor.map`` preserves input ordering, which keeps persisted
    snapshots deterministic even when AWS calls finish in a different order.
    Scanner exceptions intentionally propagate: individual scanner adapters
    must convert expected AWS failures into ``ScanResult`` error envelopes.
    """
    if not inputs:
        return merge_list_results([])
    worker_count = max(1, min(max_workers, len(inputs)))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        return merge_list_results(pool.map(scan_one, inputs))
