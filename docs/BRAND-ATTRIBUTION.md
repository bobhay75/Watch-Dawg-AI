# Watch-Dawg AI attribution

The shared badge identifies Watch-Dawg AI as a Bobsome1 production and links to
https://watchdawgai.com/ and https://bobsome1.com/. It is attribution, not a
security certification or a claim that a visitor's device, this site, or their
account is protected. No tracking or remote image request is added.

`assets/brand/watchdawg-bobsome1.png` is the original generated transparent PNG
(2172 × 724). `assets/css/watchdawg-attribution.css` provides a light panel, a
responsive width, and visible keyboard focus. Keep the two text links beneath
the image so image blocking does not remove the destinations.

The public Pages demo is `public-demo.html`; the full-stack runtime is
`index.html`. Pages must copy the two named assets into its artifact. The
full-stack frontend permits exactly those two new public files; no directory
or wildcard access is enabled.

## Release and rollback

This branch is review-only. Publishing the badge does not configure the custom
domain, restore Emergent hosting, or establish a deployed protection service.
Verify the destination's live landing page before a promotional launch.

After approval, publish `public-demo.html`, `watchdawg.js`, and the two named
assets through the existing Pages workflow. For the full-stack runtime,
include `index.html`, both assets, and the revised `frontend/server.mjs` in its
normal release. Do not deploy backend or unrelated code as a branding patch.
Rollback by reverting this branding commit and rerunning the applicable
existing release process.

Acceptance: both links work by keyboard, the full badge fits a 320 px viewport,
the PNG and CSS load without errors, and unrelated server paths still return
404. Mobile browser acceptance and live hosting verification are separate from
the local source checks recorded in the pull request.
