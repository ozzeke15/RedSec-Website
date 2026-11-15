# RedSec security hardening V2

## Executive assessment

Review date: 2026-11-15 (Europe/Brussels). Base: `1634609`.
Scope: marketing repository `ozzeke15/RedSec-Website`, its reachable Git history,
GitHub Pages settings, owner-visible Cloudflare DNS/rule settings, and a bounded
public HTTPS check. SponsorTracker internals are outside this review.
No exploit, takeover attempt, intrusive crawl, DNS edit or production deployment
was performed. Raw live response data and dashboard captures are not stored here.
This is a reviewable hardening patch, not a production-readiness certification.

The site has no server-side application, PHP, WordPress, package manifests,
third-party scripts, remote fonts, forms or data-fetching code. The only image is
the local logo. No exploitable XSS, HTML injection, open redirect, credential leak
or successful compromise was confirmed. Automated PHP probes are not evidence of
compromise. Request IPs alone are insufficient grounds for blocking.

## Findings and evidence boundaries

Every row records title, severity, asset/category, evidence, impact,
recommendation and confidence. Confirmed configuration gaps are distinguished
from demonstrated exploitable vulnerabilities.

| Title / status | Severity | Asset / category | Evidence and confidence | Impact | Recommendation |
| --- | --- | --- | --- | --- | --- |
| Missing response hardening / confirmed gap | Low | Marketing homepage / headers | Bounded HTTPS response lacked CSP, HSTS, nosniff, Referrer-Policy, Permissions-Policy and frame protection; high confidence at review time | Reduced browser defense in depth; framing possible without a separate policy, though no sensitive action exists here | Page CSP in patch; apply scoped Cloudflare headers below |
| Domain ownership unverified / confirmed gap | Medium | redsec.be / domain lifecycle | GitHub account Pages settings explicitly showed no verified domains; high confidence | Increased future takeover risk if association is removed or publishing disabled while DNS remains | Verify apex through GitHub's owner-generated TXT challenge |
| Unexpected apex origins / confirmed misconfiguration for stated GitHub-only architecture | Medium | Apex DNS / hosting | Cloudflare record table includes four GitHub A records plus two non-GitHub A values; high confidence | Potential inconsistent routing/origin availability; current apex redirect may mask it | Owner review and removal of the two stale origins, as detailed below |
| Missing disclosure file / confirmed gap | Informational | /.well-known/security.txt / disclosure | HTTPS canonical path returned 404; high confidence | Researchers have no standard discovery endpoint | Publish file reusing existing website contact |
| Inline code without restrictive policy / confirmed hardening opportunity | Low | index.html / frontend | Inline style block, two style attributes and one script block; high confidence | Makes strict CSP harder to deploy; no attacker-controlled input-to-execution path identified | Externalize unchanged code and use restrictive CSP |
| Takeover / potential, not confirmed | Medium | Domain lifecycle | Current Pages association exists; no takeover attempted | Future orphaned custom domain could be claimable without verification | Retain association, verify domain, remove DNS before retiring hosting |
| Exposed secrets / not found in reviewed scope | Informational | Repository / disclosure | Current files and all 22 reachable commits (15 unique blobs) reviewed; limited private-key/AWS/GitHub-token pattern scan returned no matches | Does not exclude unknown token formats, deleted unreachable history, caches or external systems | Enable GitHub secret scanning/push protection where available; rotate if an actual leak is found |

No Critical or High vulnerability was confirmed. Scores from external tools and
Cloudflare recommendations are signals, not proof of exploitation.

## Repository and frontend review

At base, tracked files are `index.html`, `CNAME` and `assets/redsec-logo.png`.
The pre-existing hardening branch also supplied extracted `assets/site.css` and
`assets/site.js`; this patch wires them into the page. CSS extraction retains all
original declarations and adds two classes equivalent to the original style
attributes. JavaScript is byte-equivalent after surrounding whitespace removal.
Text, anchors, ARIA controls, logo and interactions are preserved.

The JavaScript uses fixed selectors, attributes, classes and `textContent` for
the year. No `innerHTML`, `outerHTML`, `document.write`, `eval`, dynamic Function,
untrusted URL interpolation or inline event handler is present. Links are local
anchors and the existing `mailto:info@redsec.be`; there are no external browser
targets needing `noopener`, mixed-content assets, remote dependencies or unsafe
redirect logic in the repository.

Reachable history includes an older standalone HTML file but no PHP, environment
file, database dump, private key, configuration backup or `config.php.bak` path.
`git log --all -- ...` found no history for that backup name. This is limited to
fetched reachable refs; it does not prove that a file never existed in deleted
history or external deployments. The canonical backup URL returned 404 during the
bounded check. Other logged probe paths were inspected against repository paths,
not requested from production. No history rewriting is required or performed.

No custom Actions workflow or deployment permissions existed at base. Added CI
uses read-only contents access, no deployment secrets, a commit-pinned checkout,
credential persistence disabled, Python standard-library checks and Node syntax
validation. Dependabot covers Actions; there are no npm/Python dependencies to
register. Enable repository secret scanning and push protection where available,
review Actions updates before merging, require the static checks in branch rules,
and restrict workflow write/default token permissions. These account settings
are recommendations, not changes performed by this patch.

## DNS takeover assessment and owner actions

`185.199.110.153` is an official shared GitHub Pages endpoint. Provider/ASN naming
such as Fastly does not mean a resource is abandoned. The specific warning is
unsupported as a takeover finding: repository `CNAME` and GitHub Pages custom
domain both equal `www.redsec.be`; Pages publishes `main` from `/ (root)` with
Enforce HTTPS checked; public www serves RedSec and HTTPS apex redirects to www.
There is no evidence of a currently unclaimed Pages site. Do not label the whole
zone safe: ownership verification is absent and extra origin records exist.

Cloudflare hides origin targets in public DNS when proxied. The owner-visible
record table, rather than public proxy IPs, is the basis for these exact proposed
changes. No DNS change was applied:

1. Preserve all four proxied apex A records: `185.199.108.153`,
   `185.199.109.153`, `185.199.110.153`, `185.199.111.153`.
2. Preserve proxied `www CNAME ozzeke15.github.io`.
3. Confirm that the two additional apex A origins are no longer intentionally
   used. For the stated GitHub-only hosting, delete only `@ A 76.223.105.230`
   and `@ A 13.248.243.5`. Export the existing zone first and retain the current
   TTL/proxy settings for rollback. Do not alter valid GitHub records.
4. GitHub personal Settings → Pages → Add a domain → `redsec.be`. Copy GitHub's
   actual generated TXT name/value into Cloudflare (DNS only), then Verify in
   GitHub. Expected name is `_github-pages-challenge-ozzeke15.redsec.be`; the
   value must be generated by GitHub, never invented. Keep the TXT afterward.
5. Leave `_domainconnect` and email records untouched; separately review whether
   the legacy Domain Connect alias is still wanted. No wildcard or unexpected
   website AAAA origin appeared in the ten-record table. `scouts.redsec.be` is a
   separate Worker custom domain; preserve it. Do not repoint it to Pages.
6. Confirm Cloudflare Full (strict) TLS and certificate health; never use
   Flexible TLS. Verify Pages DNS check completes; it was still in progress
   when inspected. Keep the current canonical redirect.
7. After owner changes, verify apex/www HTTPS, canonical redirect, certificates,
   Pages association and SponsorTracker health. No probe of old origins or claim
   attempt is needed. DNS rollback restores only the two exported A records if
   an unintended dependency is discovered; ownership verification should remain.

References: [GitHub DNS configuration](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site),
[domain verification](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages).

## Cloudflare response headers: manual configuration

GitHub Pages does not consume Netlify/Cloudflare Pages `_headers`. No such file
is added. The HTML meta CSP works for this document but cannot enforce
`frame-ancestors`, HSTS, Permissions-Policy or nosniff. The referrer meta provides
a page-level fallback. HTTP headers must be installed manually at the proxy.
Direct access to the Pages origin can bypass Cloudflare-only controls.

After the code patch is merged by the owner, first load the deployed page and
assets. In Cloudflare → Rules → Overview → Create rule → Response Header Transform
Rule, name it `RedSec marketing security headers`, choose custom expression:

```text
(http.host in {"redsec.be" "www.redsec.be"})
```

Use **Set static** (replace, not append) for each of these six headers:

| Header | Exact value |
| --- | --- |
| Content-Security-Policy | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests` |
| X-Content-Type-Options | `nosniff` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | `camera=(), microphone=(), geolocation=(), payment=(), usb=()` |
| X-Frame-Options | `DENY` |
| Strict-Transport-Security | `max-age=86400` |

Save/deploy only after review. Keep this hostname scope: it excludes
SponsorTracker. Check existing Transform Rules ordering; later rules may replace
headers. Confirm no duplicate/conflicting CSP is installed. Test document, assets,
redirects and errors. Consider a report-only CSP trial before enforcing the edge
policy, especially if Cloudflare HTML/script injection features are active.
Do not loosen the page policy to accommodate an unneeded injected tracker.

HSTS starts at one day for reversible rollout; after sustained verified HTTPS,
the owner may change to `max-age=31536000`. Do not add `includeSubDomains` or
`preload`; those need separate review/approval and could affect scouts. Removing
HSTS does not clear cached policies; rollback uses `max-age=0` over working HTTPS.

Transform Rules require proxied DNS and are available on Free (10 active rules).
The six operations fit in one rule. Test Cloudflare challenges: response transforms
can affect challenge/error pages, and strict policies can conflict with injected
scripts. Validate in a clean browser and Security Analytics before broad rollout.

References: [Transform availability](https://developers.cloudflare.com/rules/transform/),
[response-header rules](https://developers.cloudflare.com/rules/transform/response-header-modification/).

## Cloudflare Free WAF and bots: manual recommendations

An existing active `RedSec - Block PHP Scanners` rule was visible, scoped to these
two marketing hosts and paths ending in `.php`. It does not cover `.php.bak`.
Do not duplicate it. Edit that rule only after reviewing the expression below,
with action **Block**. It uses Free-compatible operators (no regex or bot scores):

```text
(http.host in {"redsec.be" "www.redsec.be"} and (
  ends_with(lower(http.request.uri.path), ".php") or
  ends_with(lower(http.request.uri.path), ".php.bak") or
  ends_with(lower(http.request.uri.path), ".php.old") or
  starts_with(lower(http.request.uri.path), "/wp-content/") or
  starts_with(lower(http.request.uri.path), "/wp-includes/") or
  lower(http.request.uri.path) eq "/wp-admin" or
  starts_with(lower(http.request.uri.path), "/wp-admin/") or
  lower(http.request.uri.path) in {"/.env" "/.env.local" "/.env.production" "/.git" "/.git/config" "/.git/head"} or
  starts_with(lower(http.request.uri.path), "/.git/")
))
```

This catches the listed PHP backdoor paths and config backup without touching
static assets, mail links, anchors, disclosure or scouts APIs. Do not broadly
block all JSON, dot paths, backup-looking substrings, user agents, query strings,
IP addresses or countries. Never block `/.well-known/` globally: it includes
security.txt and certificate/domain validation. Review normalized/encoded path
behavior in Cloudflare's rule tester; this is a bounded noise-reduction rule,
not comprehensive attack detection. Observe events after rollout and disable
only this rule if an unexpected legitimate marketing endpoint appears.

Free allows five custom rules; one was used when inspected. Do not add a blanket
challenge to all automated traffic or assume a documented rule is active.
For suspicious automation beyond these paths, use Security Analytics to establish
an endpoint-specific pattern before considering a Managed Challenge. Free lacks
the Log action and regex; no paid bot score fields are required here.

**Bot Fight Mode:** recommend leaving disabled until SponsorTracker has a tested
compatibility plan. Free Bot Fight Mode is zone-wide and cannot be bypassed by
ordinary WAF Skip/Page Rules. It can challenge legitimate API clients, scheduled
jobs and integrations at scouts. Prefer the host-scoped scanner rule. If the
owner later trials it, test SponsorTracker login, API requests, exports, scheduled
jobs and integrations, monitor challenges and retain an immediate disable path.
No setting was enabled and SponsorTracker compatibility was not established.

**AI Labyrinth:** optional, low priority for this small public marketing site.
It injects hidden nofollow honeypot links to consume noncompliant crawler effort
and improve bot signals. It does not prevent XSS, exposed files, takeover or PHP
probes. Cloudflare states compliant bots ignore the links and SEO is unaffected;
validate rendered HTML, indexing and analytics if enabled rather than treating
that as an independent guarantee. Legitimate AI discovery may be valuable for a
public security business; avoid blanket AI blocking without a business decision.
Combined bot controls complicate diagnosis, and injected markup must be tested
against CSP and SponsorTracker. No bot or AI feature was changed.

References: [Free custom rules](https://developers.cloudflare.com/waf/custom-rules/),
[Bot Fight Mode limitations](https://developers.cloudflare.com/bots/get-started/bot-fight-mode/),
[AI Labyrinth](https://developers.cloudflare.com/bots/additional-configurations/ai-labyrinth/).

## Validation, deployment and rollback

Completed locally:

- `python3 -m unittest discover -s tests -v`: five tests pass (strict policy,
  local resources/anchor/control IDs, disclosure expiry/contact, sensitive file
  names and Jekyll exclusions). These are regression checks, not a general
  vulnerability scanner or proof of absence of secrets.
- GitHub Actions run [43772261259](https://github.com/ozzeke15/RedSec-Website/actions/runs/43772261259): Python checks and `node --check assets/site.js` passed on implementation commit `d5095be`.
- `git diff --check`: passes. Current and reachable historical files reviewed;
  targeted credential-pattern scan found zero matches.
- Chrome loopback preview: homepage renders, both logo images decode, stylesheet
  loads, JavaScript executes, Evidence tab clicks and ArrowRight tab selection
  work. At 390×844, menu opens, Pentesting navigation changes the fragment and
  closes the menu. Local disclosure file renders as text. No page CSP error was
  observed; browser-extension warnings were unrelated to page code.
- Public pre-change bounded HTTPS check: apex canonical redirect, www homepage
  success, backup path absent, disclosure absent. Connections were pinned to
  validated public IPs, with verified hostname TLS, timeouts and no automatic
  redirect following. No live scan evidence is committed.

Outstanding: local Node syntax CLI (Node not installed), Jekyll artifact build
(Jekyll toolchain not installed), post-merge HTTPS disclosure and
asset delivery, final deployed CSP/console behavior, edge-header enforcement,
Cloudflare rule tester, Pages DNS-check completion, domain verification and
SponsorTracker compatibility. Offline tests do not assert these passed.
The mailbox exists as a published contact; owner confirmation of monitoring is
still needed. Public DNS/HTTP state and dashboard settings can change.

Owner deployment sequence:

1. Review PR and confirm disclosure mailbox ownership. Require CI checks.
2. Validate a GitHub Pages/Jekyll build: `_config.yml` includes `.well-known`
   and excludes `docs`, `tests`, `SECURITY.md` and `README.md`; inspect resulting
   artifact to ensure no tooling or sensitive file is present. Keep the existing
   branch-based Pages workflow and domain configuration. No new runtime service
   or build dependency is introduced.
3. Merge only with owner approval; the existing `main` Pages deployment then runs.
   This work does not merge or deploy the branch directly.
4. Check homepage, logo, CSS, JS, mobile navigation, keyboard tabs, mail link,
   HTTPS redirects and `/.well-known/security.txt` (200, text/plain, correct
   canonical/contact/expiry). A mailto link opens a client; delivery was not tested.
5. Apply the reviewed Cloudflare header rule, then check all six actual response
   headers and browser console. Apply the scoped scanner-rule update separately;
   test marketing paths and scouts without triggering exploit requests.
6. Perform separately reviewed DNS cleanup/ownership verification above. Keep
   Bot Fight Mode, AI Labyrinth and HSTS preload unchanged.

Rollback: revert this PR through a new reviewed commit to restore the original
HTML/assets/config; do not reset shared history. Disable only the new header
transform and restore the exported prior scanner expression if they cause a
regression. Restore prior DNS only if owner-approved cleanup caused a problem.
For HSTS send `max-age=0` over HTTPS before removing the rule and allow cache
expiry. Verify homepage, navigation, assets, redirects and SponsorTracker after
rollback. No credentials, DNS records or production settings are changed by Git
reversion alone.
