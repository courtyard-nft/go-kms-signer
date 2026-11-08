# Courtyard shared security threat model

## Authority and scope

Joe requested Deep security scans of nine repositories: `courtyard-nft/atlas`, `courtyard-api`, `courtyard-frontend`, `courtyard-infrastructure`, `courtyard-py`, `courtyard-solidity-dev`, `go-kms-signer`, `internal-tools`, and `rust` (all under `courtyard-nft`). The infrastructure repository is included as deployment context as well as a scan target. The intended scope is whole repositories, including experimental, legacy, development, and test code, unless Joe narrows it.

**User-confirmed policy:** Joe selected all nine whole repositories; outsiders, abusive customers, compromised staff/services, and malicious contributors; all listed assets as important; and no accepted risks. Requested finding tags are Component, Repository, Owning team, and Common Vulnerabilities and Exposures [CVE] identifier. These are user-provided facts usable for triage.

**Provenance:** The architecture and controls below are observations from repository source and documentation, not additional user-confirmed risk decisions. No dedicated root security/threat-model document was found in the nine repositories. No risk has been accepted on Joe's behalf.

This model supports triage; it is not a vulnerability report or proof that deployed controls work. Source was sampled from the available default-branch checkouts and hosted source. Deployment state, live permissions, active contract versions, and vendor settings have not been verified.

## System overview and trust boundaries

Courtyard operates a marketplace for physically vaulted collectibles represented by blockchain tokens. Customer web/mobile applications call the marketplace application programming interface [API]. Backend services coordinate identity, payments, orders, pack dispensing, buybacks, inventory, shipping/redemption, and blockchain settlement. Operations tools can change business state. Data services replicate and transform business data, provide pricing and fraud signals, and feed monitoring. Engineering tools integrate with source control, deployment, and third-party webhooks.

Principal boundaries are customer-controlled devices to public services; one customer to another customer's resources; public routes to privileged operations; vendor webhook payloads to trusted business events; backend identities to databases, storage, and signing authority; off-chain business state to on-chain assets; production to development and previews; and contributor-controlled source/build inputs to deployed workloads.

## Components and source mapping

Use these stable names for the `Component` finding tag. A shared utility inherits the component of the affected execution path; use Cloud platform for shared build/deployment configuration.

| Component | Covered code and responsibility |
| --- | --- |
| Consumer applications | `courtyard-frontend/packages/courtyard-website-v2`, `packages/mobile-app`, consumer API clients, and shared client packages: login, checkout, wallet interactions, and account views. |
| Marketplace API | `courtyard-api/internal/*-service`, `pkg`, and `database/postgres`, excluding the more specific components below: public/customer routes, identity and permission checks, payments, orders, and business persistence. |
| Privileged operations | Internal/warehouse/dealer/catalog applications in `courtyard-frontend`; `internal-tools/packages`; internal administrative, inventory, and warehouse routes in `courtyard-api`: physical inventory, metadata processing, minting artifacts, and administrative actions. |
| Contracts and signing | `courtyard-solidity-dev/contracts`, deployment tasks and manifests; `go-kms-signer/kms_signer.go`; blockchain/signing integrations in `courtyard-api`: contract execution, authorization signatures, asset ownership, and redemption authority. |
| Data and risk | `courtyard-py/packages` and applications, including analytics, fraud scoring and snapshot export; the pricing pipeline in `courtyard-api/hermes`; riskguard code in `rust`: replicated business data, scoring inputs, model bundles, pricing, and risk decisions. |
| Background processing | Jobs, indexers, and River queue execution paths in `courtyard-api`; `rust/crates/services/sentinel`: asynchronous business transitions, chain-derived state, scheduled collection, and alerts. |
| Engineering tools | `atlas` production tools, marketing services, and experimental sites; `rust/crates/services/nexus`, `engkit`, and related tools/libraries: engineering dashboards, webhooks, short links, internal sites, and integrations. |
| Cloud platform | `courtyard-infrastructure/environments`, `modules`, and shared workflows/build configuration across repositories: ingress, identities, data stores, secrets, deployment, and separation of environments. |

## Entry points and reachability

- **Public customers and unauthenticated callers:** Web/mobile application routes and public backend endpoints. Authentication does not imply authorization to other users' objects or privileged operations. Web/mobile bundles and caller-supplied identifiers, signatures, addresses, and headers are untrusted.
- **Vendor callbacks:** Payment, identity, shipping, and other callbacks appear in [`routes_webhooks.go`](https://github.com/courtyard-nft/courtyard-api/blob/main/internal/cyc-service/routes_webhooks.go). A route's existence does not establish signature verification, replay protection, or safe processing; those require tracing its handler.
- **Staff and internal clients:** Administrative routes and warehouse/intake tools cross separate permission boundaries. [`routes_internal_admin.go`](https://github.com/courtyard-nft/courtyard-api/blob/main/internal/cyc-service/routes_internal_admin.go) mounts named permission and identity middleware. The repository name `internal-tools` does not itself establish network restriction or trustworthy inputs.
- **Engineering applications:** Purview's infrastructure places the dashboard behind Identity-Aware Proxy [IAP], while exact webhook paths bypass IAP and are intended to use vendor signatures. Quick uses IAP and hosts contributor sites. See [`purview_service/main.tf`](https://github.com/courtyard-nft/courtyard-infrastructure/blob/main/modules/backend/purview_service/main.tf) and [`quick_service/main.tf`](https://github.com/courtyard-nft/courtyard-infrastructure/blob/main/modules/backend/quick_service/main.tf). Internal load-balancer ingress is not a substitute for checking an IAP assertion in applications that require one.
- **Service identities and jobs:** The fraud scoring service's Terraform specifies internal-only ingress and an explicit invoker identity list; it reads model bundles and historical snapshots. See [`fraud_scoring_service/main.tf`](https://github.com/courtyard-nft/courtyard-infrastructure/blob/main/modules/backend/fraud_scoring_service/main.tf) and [`app.py`](https://github.com/courtyard-nft/courtyard-py/blob/main/packages/fraud_scoring_api/src/fraud_scoring_api/app.py). Scheduling, queue processing, and data imports are also entry points for less-trusted events and data.
- **Blockchain participants:** Contract callers, signed orders, checkout authorizations, relayers, and public chain events cross the off-chain/on-chain boundary. Historical contract versions and test contracts are not assumed deployed.
- **Contributors and integrations:** Source changes, pull-request automation, dependency resolution, webhook receivers, image builds, and deployment credentials cross the build-to-production boundary. Experimental code is not automatically an accepted risk simply because production imports are prohibited.

## Assets and sensitivity

Joe confirmed all of the following are important, with no accepted risks and no additional ordering between them:

- Customer and company funds, payment authorizations, credits/points, refunds, and settlement correctness.
- Collectible ownership, custody records, redemption and shipping authorization, minting integrity, and correspondence between physical inventory and tokens.
- Signing capability, contract administration/upgrade authority, cloud credentials, vendor tokens, and deployment control. Non-exportable keys do not prevent abuse by a principal authorized to sign.
- Personal and identity-verification data, shipping addresses, account/wallet links, authentication material, and private operational records. Warehouse replicas, logs, exports, caches, and model features may retain sensitive information.
- Financial/risk/analytics correctness, fraud signals, pricing/model integrity, private source and integration records, service availability, and monitoring reliability.

## Attacker profiles — user confirmed

Joe explicitly included outsiders, abusive customers, compromised staff/services, and malicious contributors. Model unauthenticated internet attackers; authenticated abusive customers controlling their own accounts/wallets and request concurrency; compromised staff accounts or workload identities; and malicious contributors. Compromised dependencies and forged or compromised vendor/event sources are additional code-derived attack paths, not separately confirmed user risk priorities. Inclusion does not establish that every attacker has every privilege.

Do not assume an internet attacker already has cloud administration or a signing role. Conversely, do not discard privilege escalation or lateral movement merely because one service is internal. Preserve the scanner's demonstrated prerequisites and reachability for every finding.

## Existing controls observed in source

- Marketplace routes attach identity and named permission middleware; customer-to-resource authorization must still be evaluated per path. The backend architecture describes PostgreSQL persistence, Redis caching, and external identity/payment integrations. See [`ARCHITECTURE.md`](https://github.com/courtyard-nft/courtyard-api/blob/main/ARCHITECTURE.md).
- Cloud platform modules configure ingress, service accounts, invoker bindings, secret access, load balancing, and Cloud Armor policies. These are configuration facts, not evidence of a verified deployed perimeter. See [`cloud_run_service/main.tf`](https://github.com/courtyard-nft/courtyard-infrastructure/blob/main/modules/components/cloud_run_service/main.tf).
- Google Cloud Key Management Service [KMS] separates signing authority from key custody. Different key resources and role bindings cover checkout, forwarder, redemption, and orderbook use. The Go signer fetches public keys and delegates signing to KMS. See [`kms/main.tf`](https://github.com/courtyard-nft/courtyard-infrastructure/blob/main/modules/backend/kms/main.tf) and [`kms_signer.go`](https://github.com/courtyard-nft/go-kms-signer/blob/main/kms_signer.go).
- The smart-contract repository documents versioned upgrade tests and storage-layout constraints. This does not establish which implementation is currently deployed or who holds its roles. See [`README.md`](https://github.com/courtyard-nft/courtyard-solidity-dev/blob/main/README.md).
- Atlas documents enforced separation between experimental and production imports, review paths, and sandboxed contributor checks. This is a code/build boundary, not a blanket exemption for hosted sites. See [`AGENTS.md`](https://github.com/courtyard-nft/atlas/blob/main/AGENTS.md).

## Accepted risk, exclusions, and open questions

Joe explicitly confirmed no accepted risks and whole-repository coverage. Do not exempt staff tools, legacy code, development systems, analytics replicas, experimental sites, or dependencies. Lack of deployment evidence is an uncertainty to preserve, not proof of either exposure or safety.

No unanswered pre-launch questions remain. Deployed contract versions, live cloud permissions and vendor settings remain unverified. Tags: `Component` uses the stable names above; `Repository` is the full repository name; `Owning team` is populated only when repository ownership evidence identifies a team (do not guess from a directory or a sole contributor); `CVE` is the exact applicable identifier, omitted when none applies. No compliance scope was requested.

## Finding-priority policy

Start from the scanner's severity and its established exploitability and impact. Change priority only for user-provided facts, an explicit user-selected policy, or a user-authored security model—not for architecture assumptions drafted here. Joe included all listed attackers and assets and accepted no risks, so his current policy should preserve virtually all severities. Never raise an unverified or hard-to-exploit finding merely because a valuable asset is nearby.

For a changed finding, identify the user fact and explain both the required attacker access and the consequence to the asset. Dismiss as accepted risk only when the user actually accepted it. Source observations and component tags provide context but do not independently justify severity changes.

Security contact: security@courtyard.io.
