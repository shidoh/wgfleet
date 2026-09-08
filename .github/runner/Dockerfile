# The self-hosted runner image for the sln scale set: the stock actions-runner
# plus what the wgfleet workflows call directly — a C toolchain for the race
# detector, make for the archives, gh for publishing. Built by
# .github/workflows/runner-image.yml, consumed by gitops apps/gha-runner-sln.
ARG RUNNER_VERSION=2.337.0
FROM ghcr.io/actions/actions-runner:${RUNNER_VERSION}
USER root
RUN set -eux; \
    mkdir -p -m 755 /etc/apt/keyrings; \
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list; \
    apt-get update -q; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends gcc libc6-dev make gh; \
    rm -rf /var/lib/apt/lists/*
USER runner
