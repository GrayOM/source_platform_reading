from collections import defaultdict


class SitemapBuilder:
    """Builds an adjacency-list sitemap of discovered pages."""

    def __init__(self):
        self._pages: set[str] = set()
        self._links: dict[str, set[str]] = defaultdict(set)
        self._parents: dict[str, str | None] = {}

    def add_page(self, url: str, parent: str | None = None) -> None:
        self._pages.add(url)
        self._parents[url] = parent

    def add_link(self, from_url: str, to_url: str) -> None:
        self._links[from_url].add(to_url)

    def to_dict(self) -> dict:
        return {
            "pages": list(self._pages),
            "links": {k: list(v) for k, v in self._links.items()},
            "tree": self._build_tree(),
        }

    def _build_tree(self) -> dict:
        root = {}
        for url, parent in self._parents.items():
            if parent is None:
                root[url] = {}
        return root
