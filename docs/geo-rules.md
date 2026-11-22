# Sample country and ASN rules

RustIPS ships five **disabled** sample disposition rules for GeoIP/ASN data.
They exist to show the shape of country/ASN conditions and to give an operator
a safe starting point; no country rule is enabled by default (FR-138).

## The samples

| Name | Action | Match | Why it is useful |
|---|---|---|---|
| Geo alert: China | alert | country CN | Visibility without changing enforcement |
| Geo block 24h: high-risk list | block 24h | countries CN, RU, KP, IR | Explicit, short first block |
| Geo allow: partner ASNs | allow | ASN 13335, 15169 | Allow known infrastructure after a detection |
| Geo escalate: hosting ASNs | escalate 24h → 48h → permanent | ASN 16509, 14618, 8075 | Longer ladder for hosting/cloud ranges |
| Geo alert: outside expected countries | alert | not country US, GB, DE, CA, AU | Travel/expected-country review |

ASNs and countries are examples. Replace them with the networks and countries
that matter to your host; the allow rule does not bypass the implicit/allowlist
protection, it only adds a rule-level exemption.

## Loading them

**UI:** open **Rules → Sample geo rules → Load sample geo rules**. The five
rules are added disabled; enable and edit them individually.

**CLI (table):**

```sh
rustips rules samples
```

**CLI (importable document):**

```sh
rustips rules samples --json > /tmp/geo-rules.json
rustips import /tmp/geo-rules.json      # replaces the stored set
```

`rustips import` also accepts a bare JSON array. The checked-in copy is
`docs/examples/geo-rules.json`. The UI import form accepts either the document
or an array.

## Before enabling a geo rule

1. Install and load the geo indexes:

   ```sh
   sudo rustips geo update
   sudo rustips geo status
   sudo rustips geo lookup 1.0.1.5   # CN
   sudo rustips geo lookup 8.8.8.8   # US / 15169
   ```

   Geo conditions do **not** match when the index is absent; the Rules page
   shows `not configured`. Geo data is never used to create a detection.

2. Review the rule against recent traffic with **Rules → Dry-run against recent
   detections**. The page evaluates the stored rules, including country/ASN
   lookups, against the last 100 detections and shows the winner and action.

3. Start with `alert` or `dry_run`, then move to a short `block_temp` once the
   volume and false-positive rate are understood. Keep the allowlist for
   management/partner networks.

4. Enable one rule at a time. Rules are evaluated in priority order and their
   actions combine: `allow` wins, otherwise the longest block wins, then
   `alert`, then `tag`. Ties break on severity, priority and the lowest rule ID.

## Safety properties

* Geo is disposition-only (FR-137): it cannot trigger a detection or block a
  source that was not already detected.
* No country rule is enabled by default (FR-138).
* The implicit allowlist (loopback, RFC1918, link-local, host addresses) and
  the explicit allowlist always win (FR-145/FR-152).
* A rule with `countries`/`asns` cannot match without a loaded index; a failed
  geo update leaves the previous index in place.
* Country/ASN conditions are ordinary rules: they are audited, included in the
  strike ladder and reversible like any other disposition.
