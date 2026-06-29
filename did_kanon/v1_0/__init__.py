from __future__ import annotations

import logging

from acapy_agent.config.injection_context import InjectionContext

from did_kanon.v1_0.config import DidKanonConfig, KanonConfigError
from did_kanon.v1_0.contracts.pool import KanonRegistryPool
from did_kanon.v1_0.did.did_method import KANON
from did_kanon.v1_0.did.registrar import KanonDIDRegistrar
from did_kanon.v1_0.did.resolver import KanonDIDResolver

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext) -> None:
    """Plugin bootstrap — runs once during agent startup.

    Fails closed when required configuration is missing. A misconfigured
    deployment must not silently fall through to a baked-in public chain.
    """
    LOGGER.info("> did:kanon plugin setup")

    plugin_settings = (
        context.settings.get("plugin_config", {}).get("did_kanon")
        if hasattr(context, "settings")
        else None
    )
    try:
        config = (
            DidKanonConfig.from_settings(plugin_settings)
            if plugin_settings
            else DidKanonConfig.from_environment()
        )
    except KanonConfigError:
        LOGGER.exception(
            "did:kanon plugin failed to load: required configuration is missing"
        )
        raise

    if not config.networks:
        raise KanonConfigError(
            "did:kanon plugin disabled: no networks configured. Set KANON_RPC_URL "
            "+ registry addresses (KANON_DEPLOYMENT_FILE or per-registry env), or "
            "supply --plugin-config YAML."
        )

    pool = KanonRegistryPool(config)
    registrar = KanonDIDRegistrar(config, pool)
    resolver = KanonDIDResolver(pool)

    context.injector.bind_instance(DidKanonConfig, config)
    context.injector.bind_instance(KanonRegistryPool, pool)
    context.injector.bind_instance(KanonDIDRegistrar, registrar)

    from acapy_agent.wallet.did_method import DIDMethods

    did_methods = context.inject_or(DIDMethods)
    if did_methods is not None and not did_methods.registered("kanon"):
        did_methods.register(KANON)
        LOGGER.info("did:kanon: registered DIDMethod 'kanon'")

    from acapy_agent.resolver.did_resolver import DIDResolver

    did_resolver = context.inject_or(DIDResolver)
    if did_resolver is not None:
        did_resolver.register_resolver(resolver)
        LOGGER.info("did:kanon: registered DIDResolver")

    # AnonCredsRegistry may not be bound yet if the anoncreds module hasn't
    # loaded; inject_or + warning lets startup continue.
    from acapy_agent.anoncreds.registry import AnonCredsRegistry

    from did_kanon.v1_0.anoncreds.registry import KanonAnonCredsRegistry

    anoncreds_registry = context.inject_or(AnonCredsRegistry)
    kanon_anoncreds = KanonAnonCredsRegistry(pool)
    if anoncreds_registry is not None:
        anoncreds_registry.register(kanon_anoncreds)
        LOGGER.info("did:kanon: registered AnonCredsRegistry handler")
    else:
        LOGGER.warning(
            "did:kanon: AnonCredsRegistry not yet bound at setup; schema/cred-def "
            "reads for did:kanon issuers will fail until the anoncreds module loads."
        )

    # Auto-publish to AnonCredsStatusRegistry (Mode A) and/or
    # MerkleStateRegistry (Mode B) on every credential-issued event. The
    # listener reads each credDef's on-chain `policyMask` and routes writes
    # accordingly — Mode-A-only credDefs see one tx, Mode-B-only see one,
    # TIER_ALL credDefs see both. Failures are logged but don't block
    # issuance.
    from did_kanon.v1_0.anoncreds.issuance_listener import attach as attach_listener

    attach_listener(context, config, pool)

    # Bypass the AnonCreds tails-server precondition for did:kanon issuers.
    #
    # ACA-Py's AnonCredsIssuer refuses to create a credDef with
    # `support_revocation=true` unless `tails_server_base_url` is set
    # (acapy_agent/anoncreds/issuer.py:364). This is a settings check that
    # runs BEFORE any issuer-id-specific routing — once it passes, the
    # downstream rev-reg cascade is what we actually need to suppress
    # (that's where anoncreds-rs writes a tails file). The kanon-aware
    # revocation setup installed below intercepts that cascade so no
    # tails file is ever written for did:kanon credDefs; the sentinel URL
    # here just gets past the precondition.
    if not context.settings.get("tails_server_base_url"):
        context.update_settings(
            {"tails_server_base_url": "x-did-kanon://no-tails-required"}
        )
        LOGGER.info(
            "did:kanon: set tails_server_base_url sentinel (Kanon credentials "
            "use on-chain revocation, no tails)"
        )

    # Intercept the AnonCreds revocation cascade for did:kanon issuers.
    # `DefaultRevocationSetup.on_cred_def` would otherwise fire
    # `RevRegDefCreateRequestedEvent` → call
    # `RevocationRegistryDefinition.create()` in anoncreds-rs → write a
    # tails file to `~/.indy_client/tails/`. We unsubscribe the default
    # handler from `CredDefFinishedEvent` and replace it with one that
    # synthesises the minimal rev-reg meta directly in BaseStorage for
    # did:kanon issuers (so the standard /anoncreds/revocation/revoke
    # route still finds something to look up) and delegates to the
    # default for non-kanon issuers. Result: zero tails files for
    # did:kanon credDefs.
    # Suppress the AnonCreds rev-reg cascade for did:kanon issuers.
    #
    # ACA-Py's `DefaultRevocationSetup.on_cred_def` reads
    # `payload.support_revocation` and, when true, fires
    # `RevRegDefCreateRequestedEvent`. That cascade calls
    # `RevocationRegistryDefinition.create(tails_dir_path=...)` in
    # anoncreds-rs which writes a tails file to disk. Our
    # `KanonAwareRevocationSetup` swaps the default's subscriber for one
    # that returns early for `did:kanon:*` issuers — no cascade, no
    # tails file. Non-kanon issuers still go through the default.
    #
    # This works WITHOUT breaking issuance because
    # `KanonAnonCredsRegistry.get_credential_definition` strips the CL
    # `value.revocation` key from the returned CredDef for did:kanon
    # credDefs. `AnonCredsIssuer.cred_def_supports_revocation` reads
    # that field and decides whether to allocate `cred_rev_id` from a
    # rev-reg; with `value.revocation=None` the issuer treats the
    # credDef as non-revocable for its standard path and skips the
    # rev-reg lookup. anoncreds-rs never consults a rev-reg or tails
    # file. Issuance succeeds.
    #
    # Revocation still works:
    #   * `/did/kanon/revoke/{cred_def_id}` is the canonical route —
    #     translates kanonCredIds to the on-chain `policy_mask` writes
    #     (status_registry / MerkleStateRegistry leaf removal).
    #   * `/anoncreds/revocation/revoke` is supported by our registry's
    #     `update_revocation_list` reading the rev-reg meta we
    #     synthesise in BaseStorage at credef-create time.
    try:
        from did_kanon.v1_0.anoncreds.revocation_setup import install as install_kanon_revsetup

        # `install` defers the actual subscription swap to STARTUP_EVENT
        # (acapy::startup), by which point every plugin's events are
        # registered — including the default revocation setup's
        # `on_cred_def` from `acapy_agent.anoncreds.revocation.routes`.
        install_kanon_revsetup(context)
    except ImportError as err:
        LOGGER.warning(
            "did:kanon: could not import revocation setup (%s); leaving "
            "default rev-reg behavior in place", err,
        )

    networks = ", ".join(
        f"{name}({net.addresses.get('did_registry', '?')[:10]}...)"
        for name, net in config.networks.items()
    )
    LOGGER.info(
        "did:kanon plugin registered: default=%s networks=[%s]",
        config.default_network, networks,
    )
    LOGGER.info("< did:kanon plugin setup")
