# Licensing and Contribution Governance

Status: **ACTIVE — PRIVATE DEVELOPMENT / PUBLIC LICENSE NOT YET GRANTED**

## 1. Current repository state

Cyber-Sentinel-Atlas is under controlled private development. A general public project license has not yet been adopted. The absence of a `LICENSE` file must not be interpreted as an open-source grant.

The maintainer retains control of the official repository and release process. Third-party material remains subject to its own upstream terms.

## 2. Why public licensing is deferred

Atlas combines first-party software with source-backed cybersecurity knowledge and may redistribute selected upstream-derived artifacts. Before Public Preview, the project must complete a target-by-target redistribution inventory covering copyright, license, attribution, modification and notice requirements.

A project-level license will apply only to eligible first-party material and any explicitly identified material for which the project has the right to grant those terms. It will not silently override upstream licenses.

## 3. Candidate first-party licensing model

The current preferred candidate for first-party source code is **MPL-2.0**, potentially paired with a separate commercial license where that becomes useful. This is a recommendation, not an adopted license. Final adoption requires an explicit release/legal gate after the third-party audit.

## 4. Contribution rights

External contributions are not accepted into the official public product line until a contribution-rights mechanism has been approved. Before Public Preview the project will choose and document an appropriate mechanism, such as a reviewed CLA or DCO-based process, consistent with the selected first-party license and any future dual-licensing needs.

No contributor receives merge authority merely by opening a PR. The maintainer remains the final authority for official scope, architecture and release inclusion.

## 5. Mandatory publication controls

Before a public release, CI/release review must prove:

- every redistributable third-party target has an identified source/release and license status;
- required notices/attributions are present;
- unknown/incompatible licensing fails closed;
- generated packs carry machine-readable source/license inventory;
- official first-party license text is scoped so it does not relicense upstream material;
- contributor-rights policy is active;
- branding/trademark policy distinguishes official releases from forks.

## 6. Governance against unwanted contributions

The official repository uses branch/PR review, CODEOWNERS, deterministic CI, architecture ADRs, expected-head merges and maintainer authority. Licensing controls legal permissions; these repository controls protect the official product direction and integrity.
