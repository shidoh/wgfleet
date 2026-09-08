---
hide:
  - navigation
  - toc
---

<span class="wgf-eyebrow">AmneziaWG exit fleets</span>

# Declare the fleet. wgfleet builds it and *holds it there.* { .wgf-title }

wgfleet is a controller and per-node agents that turn blank Ubuntu servers into
a small fleet of AmneziaWG exit nodes behind one master, then keep them that way:
a reconcile loop renders interfaces, routes, firewall and DNS from one manifest,
REALITY/VLESS stands in as a second transport when AmneziaWG is blocked, egress
failover moves clients off a bad exit on its own, and a web console shows the
whole fleet at a glance.
{ .wgf-lead }

<div class="wgf-pills" markdown>
<span class="wgf-pill wgf-pill--green">declarative</span>
<span class="wgf-pill wgf-pill--blue">dry-run first</span>
<span class="wgf-pill">keys stay on node</span>
<span class="wgf-pill">AmneziaWG + REALITY</span>
</div>

<figure class="wgf-shot" markdown>
![The fleet view of the web console: one master, three exits carrying traffic, three held out — one degraded, one drained, one in reserve.](docs/assets/img/console-fleet.png){ loading=lazy }
<figcaption>The fleet view. Names and addresses are from a demo fleet.</figcaption>
</figure>

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } __Quickstart__

    ---

    From two blank Ubuntu servers to a working VPN in about 30 minutes: master,
    one exit, first client.

    [:octicons-arrow-right-24: Start here](docs/QUICKSTART.md)

-   :material-server:{ .lg .middle } __System requirements__

    ---

    What a node must be, what the platform installs itself, and which
    distribution and kernel combinations are supported.

    [:octicons-arrow-right-24: Requirements](docs/requirements.md)

-   :material-radar:{ .lg .middle } __Operations__

    ---

    Day-to-day fleet work: dry-run, the dashboard, client credentials,
    break-glass access, backups, node health and module upgrades.

    [:octicons-arrow-right-24: Operations](docs/operations.md)

-   :material-file-tree:{ .lg .middle } __Configuration reference__

    ---

    Every manifest key, its default, and where the underlying tool documents
    the passthrough surface. If a key is not on this page, it is not a key.

    [:octicons-arrow-right-24: Key reference](docs/configuration.md)

-   :material-package-variant-closed:{ .lg .middle } __Support bundle__

    ---

    A read-only diagnostic archive to hand to someone without server access.
    Plain text, no secrets, printed before it leaves the machine.

    [:octicons-arrow-right-24: Support bundle](docs/support-bundle.md)

-   :material-history:{ .lg .middle } __Changelog__

    ---

    What changed for operators in each release: behaviour, manifest keys,
    CLI flags, the console, and the steps an upgrade asks of you.

    [:octicons-arrow-right-24: Changelog](docs/changelog.md)

</div>

Releases ship as an archive with these pages inside; this site is the same
material, always for the latest release. Manifest walkthrough, SOPS secrets and
the CLI live under **Configuration**; moving a client leg off wg-easy or moving
the master under **Migrations**; the RU split-tunnel setup under **Recipes**.
{ .wgf-map }
