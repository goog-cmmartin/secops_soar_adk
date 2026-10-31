"""Shared page-token pagination for list primitives.

Every list endpoint used by the detection-rule workflows follows the AIP-158
``pageSize`` / ``pageToken`` / ``nextPageToken`` contract. ``collect_pages``
walks that chain so consumers get every item instead of the first page only.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Tuple, TypeVar

T = TypeVar("T")

# Hard ceiling on pages walked by one call. At page sizes of 100-1000 this is
# far beyond any tenant observed (202 rules, 2,713 rule errors, 460 curated
# deployments); hitting it returns the remaining ``next_page_token`` so the
# truncation is visible to the caller instead of silent.
DEFAULT_MAX_PAGES = 200


class PaginationError(RuntimeError):
    """The API returned a page token that would loop forever."""


def _valid_token(token: object) -> Optional[str]:
    return token if isinstance(token, str) and token else None


def collect_pages(
    fetch_page: Callable[[Optional[str]], Tuple[List[T], object]],
    page_token: Optional[str] = None,
    max_results: Optional[int] = None,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> Tuple[List[T], Optional[str], int]:
    """Fetch pages until the token chain ends, ``max_results`` or ``max_pages``.

    Args:
        fetch_page: Called with the page token (None for the first page);
            returns ``(items, next_page_token)``.
        page_token: Token to resume from.
        max_results: Stop once this many items are collected (the list is
            truncated to exactly this many). None means no item limit.
        max_pages: Safety ceiling on pages.

    Returns:
        ``(items, next_page_token, pages_fetched)``. ``next_page_token`` is
        non-None only when collection stopped before the end of the chain.

    Raises:
        PaginationError: if the API repeats a page token.
        Any exception raised by ``fetch_page`` propagates unchanged.
    """
    items: List[T] = []
    token = _valid_token(page_token)
    seen: set = set()
    pages = 0
    while True:
        page_items, next_token = fetch_page(token)
        pages += 1
        items.extend(page_items or [])
        token = _valid_token(next_token)
        if max_results is not None and len(items) >= max_results:
            return items[:max_results], token, pages
        if token is None:
            return items, None, pages
        if token in seen:
            raise PaginationError(f"API repeated page token after {pages} pages; aborting to avoid an infinite loop")
        seen.add(token)
        if pages >= max_pages:
            return items, token, pages
