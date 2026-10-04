# Watch-Dawg deterministic page checks

`sentinel.website_page_checks` analyzes the exact HTML response bytes already preserved in a verified Watch-Dawg website evidence package. It does not crawl, execute JavaScript, or make additional network requests.

## Run

```bash
python -m sentinel.website_page_checks \
  --evidence-root .sentinel/evidence \
  --package-ref sha256:<package-digest> \
  --store-result
```

`--store-result` writes the deterministic analysis back into the same content-addressed evidence store. Because the analysis contains no generated timestamp and is derived from the verified package, repeating the same detector version over the same evidence produces the same stored artifact reference.

## Current checks

The first passive adapter reports only directly observable markup conditions:

- active mixed-content references from an HTTPS page (`script`, `iframe`, `object`, `embed`);
- passive mixed-content references (`img`, `audio`, `video`, `source`, `track`, poster assets, and selected linked resources);
- HTTPS pages with forms whose resolved action uses HTTP;
- password inputs inside forms using GET;
- cross-origin form actions as an informational review signal, not a vulnerability claim;
- missing/non-empty HTML title as a low-severity page-quality observation.

Every finding is labeled `VERIFIED` only in the narrow sense that the condition exists in the captured bytes. The adapter does not infer exploitability, intent, compromise, customer impact, or root cause.

## Coverage boundary

The result explicitly records:

- source `package_ref`, capture ref, and body ref;
- the original collection coverage;
- parser identity;
- references/forms examined;
- the reference cap;
- `network_requests_added_by_analysis: 0`.

The adapter refuses non-HTML captures instead of guessing. It does not fetch referenced resources or form targets, so availability or behavior of those destinations remains unverified until a separately authorized collection step observes them.
