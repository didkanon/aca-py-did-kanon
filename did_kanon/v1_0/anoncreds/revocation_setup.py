"""Kanon-aware AnonCreds revocation setup — replaces the default for did:kanon.

ACA-Py's `DefaultRevocationSetup` subscribes to `CredDefFinishedEvent` and,
when `support_revocation=true` is on the payload, fires
`RevRegDefCreateRequestedEvent`. That event triggers
`AnonCredsRevocation.create_and_register_revocation_registry_definition`
which in turn calls anoncreds-rs's `RevocationRegistryDefinition.create(...)`
— and THAT is where a tails file gets written to disk.

For did:kanon credDefs we don't want any of that. Revocation lives on chain
via the credDef's `policy_mask` path; there is no AnonCreds-CL
accumulator, no tails witness, no rev-reg-def to publish anywhere external.

This module subscribes its own `on_cred_def` handler in place of the
default's. For non-did:kanon issuers it delegates to the original (so a
multi-DID-method agent — did:indy and did:kanon coexisting — still gets
real rev-regs for indy). For did:kanon issuers it short-circuits:
synthesises the minimal rev-reg meta directly in BaseStorage via
`revreg_state.save_revreg_meta` and returns without firing the rest of
the cascade.

The five revocation methods on `KanonAnonCredsRegistry`
(`register_revocation_registry_definition`, `get_revocation_list`, etc.)
read off this same BaseStorage meta, so the standard
`/anoncreds/revocation/revoke` route still works end-to-end for did:kanon
credDefs — only the wasted-on-disk tails artefact is gone.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from acapy_agent.anoncreds.events import (
    CRED_DEF_FINISHED_EVENT,
    CredDefFinishedEvent,
)
from acapy_agent.core.event_bus import EventBus
from acapy_agent.core.profile import Profile

from did_kanon.v1_0.contracts.cred_def_registry import TIER_ONE_TIME


LOGGER = logging.getLogger(__name__)


def _is_kanon_issuer(issuer_id: Optional[str]) -> bool:
    return isinstance(issuer_id, str) and issuer_id.startswith("did:kanon:")


class KanonAwareRevocationSetup:
    """Wraps `DefaultRevocationSetup.on_cred_def`.

    Constructed with the default instance so non-kanon issuers can be
    delegated. The wrapper is registered as the new subscriber on
    `CredDefFinishedEvent.event_topic` after we unsubscribe the default.
    All other `RevReg*` / `RevList*` events keep the default's
    subscriptions intact — they only fire for non-kanon issuers because
    we never emit them for did:kanon.
    """

    def __init__(self, default_on_cred_def):
        self._default_on_cred_def = default_on_cred_def

    async def on_cred_def(self, profile: Profile, event: CredDefFinishedEvent) -> None:
        payload = event.payload
        issuer_id = getattr(payload, "issuer_id", None)
        if not _is_kanon_issuer(issuer_id):
            await self._default_on_cred_def(profile, event)
            return

        if not payload.support_revocation:
            # did:kanon credDef without standard AnonCreds revocation —
            # nothing to set up. Revocation can still happen through
            # /did/kanon/revoke/{cred_def_id} based on the on-chain
            # policy_mask, but ACA-Py's flow is opted out.
            LOGGER.debug(
                "did:kanon: cred-def %s finished, support_revocation=false → no AnonCreds rev-reg",
                payload.cred_def_id,
            )
            return

        try:
            await self._synthesise_kanon_rev_reg(profile, payload)
        except Exception as err:  # noqa: BLE001
            LOGGER.error(
                "did:kanon: synthesising rev-reg meta for %s failed: %s",
                payload.cred_def_id, err,
            )
            return

        LOGGER.info(
            "did:kanon: cred-def %s opted into AnonCreds revocation — "
            "synthesised rev-reg meta (no tails file, no anoncreds-rs rev-reg-def)",
            payload.cred_def_id,
        )

    async def _synthesise_kanon_rev_reg(
        self, profile: Profile, payload
    ) -> None:
        """Persist the minimal rev-reg meta KanonAnonCredsRegistry needs.

        ACA-Py's `/anoncreds/revocation/revoke` route ultimately calls our
        registry's `get_revocation_registry_definition(rev_reg_id)`. We
        write a synthesised meta keyed off the cred-def + a default
        `revoc` tag — same scheme `register_revocation_registry_definition`
        would have used if anoncreds-rs had built a real rev-reg-def.
        """
        from did_kanon.v1_0.anoncreds.revreg_state import save_revreg_meta
        from did_kanon.v1_0.contracts.pool import KanonRegistryPool

        cred_def_id = payload.cred_def_id
        tag = payload.tag or "default"
        rev_reg_id = f"{cred_def_id}/revoc/{tag}"

        # Read the credDef's on-chain policy_mask so the eventual
        # update_revocation_list dispatch knows which tier(s) to revoke
        # on. Failing this read should not abort: revoke time can re-read.
        policy_mask = TIER_ONE_TIME
        try:
            pool = profile.context.inject_or(KanonRegistryPool)
            if pool is not None:
                from web3 import Web3

                cd_bytes = Web3.keccak(text=cred_def_id)
                registries = pool.for_network()
                cd_record = await registries.cred_def.get_credential_definition(cd_bytes)
                if cd_record is not None:
                    policy_mask = int(cd_record["policy_mask"])
        except Exception as err:  # noqa: BLE001
            LOGGER.warning(
                "did:kanon: rev-reg synthesis could not read on-chain policy_mask "
                "for %s (%s); deferring to update_revocation_list",
                cred_def_id, err,
            )

        # Build a synthesised RevRegDef shaped like what ACA-Py expects
        # downstream. No anoncreds-rs call — these are dicts the
        # KanonAnonCredsRegistry's get_revocation_registry_definition will
        # deserialise back into a `RevRegDef` model.
        max_cred_num = int(payload.max_cred_num)
        rev_reg_def = {
            "issuerId": payload.issuer_id,
            "revocDefType": "CL_ACCUM",
            "credDefId": cred_def_id,
            "tag": tag,
            "value": {
                "publicKeys": {"accumKey": {"z": "x-did-kanon-synth"}},
                "maxCredNum": max_cred_num,
                # Kanon doesn't use these — they're settings ACA-Py's
                # downstream wallet code reads. We hand back the same
                # sentinel URL we set on profile.settings.
                "tailsLocation": "x-did-kanon://no-tails",
                "tailsHash": "0" * 64,
            },
        }
        rev_list = {
            "issuerId": payload.issuer_id,
            "revRegDefId": rev_reg_id,
            "revocationList": [0] * max_cred_num,
            "currentAccumulator": "1 0 0 0 0",  # placeholder
            "timestamp": 0,
        }

        await save_revreg_meta(
            profile,
            rev_reg_id=rev_reg_id,
            cred_def_id=cred_def_id,
            policy_mask=policy_mask,
            max_cred_num=max_cred_num,
            rev_reg_def_json=json.dumps(rev_reg_def),
            initial_rev_list_json=json.dumps(rev_list),
        )


def _detach_default_cred_def_subscribers(event_bus: EventBus) -> int:
    """Remove all `DefaultRevocationSetup.on_cred_def`-style subscribers from
    the `CredDefFinishedEvent` topic.

    We can't pass the exact bound-method reference to `unsubscribe` because
    ACA-Py's `acapy_agent/anoncreds/revocation/routes.py` instantiates a
    fresh `DefaultRevocationSetup()` locally — that instance isn't kept
    anywhere we can reach. Instead we introspect `topic_patterns_to_subscribers`,
    find the pattern matching `CredDefFinishedEvent.event_topic`, and drop
    any callable whose `__qualname__` belongs to `DefaultRevocationSetup`.

    Returns the count of subscribers removed (0 if the default hasn't been
    subscribed yet — caller may need to defer).
    """
    removed = 0
    for pattern, subs in list(event_bus.topic_patterns_to_subscribers.items()):
        if getattr(pattern, "pattern", "") != CRED_DEF_FINISHED_EVENT:
            continue
        for sub in list(subs):
            qual = getattr(sub, "__qualname__", "") or repr(sub)
            if "DefaultRevocationSetup.on_cred_def" in qual:
                subs.remove(sub)
                removed += 1
    return removed


def install(context, default_setup=None) -> bool:
    """Replace `DefaultRevocationSetup.on_cred_def` for did:kanon issuers.

    The default's `register_events` is fired by
    `acapy_agent/anoncreds/revocation/routes.register_events()` during
    plugin protocol-event registration. That MAY run before OR after the
    did:kanon plugin's setup depending on ACA-Py's load order, so we
    install our interception on the `STARTUP_EVENT_TOPIC` event — by
    which time every plugin's subscriptions are guaranteed to be in place.

    On startup:
      1. Drop any `DefaultRevocationSetup.on_cred_def` subscribers.
      2. Subscribe `KanonAwareRevocationSetup.on_cred_def`. The wrapper
         keeps a reference to a freshly-instantiated `DefaultRevocationSetup`
         so non-kanon issuers still get the default behaviour.

    All other subscriptions on the default (RevRegDef create / store /
    activate / RevList create / store / etc.) stay intact — they only
    fire for non-kanon issuers because we don't emit the upstream events.
    """
    event_bus = context.inject_or(EventBus)
    if event_bus is None:
        LOGGER.warning(
            "did:kanon: no EventBus in context; cannot intercept revocation setup"
        )
        return False

    from acapy_agent.anoncreds.revocation.revocation_setup import (
        DefaultRevocationSetup,
    )
    from acapy_agent.core.util import STARTUP_EVENT_PATTERN

    # Fresh default — used ONLY to delegate non-kanon issuers. Its events
    # are NEVER registered (that would double-subscribe RevReg/RevList
    # cascade handlers). We only call its `on_cred_def(profile, event)`
    # directly from our wrapper.
    delegate_default = default_setup or DefaultRevocationSetup()

    kanon_setup = KanonAwareRevocationSetup(delegate_default.on_cred_def)

    async def _on_startup(profile, event):
        # Subscribe our handler first so that even if no removal happens
        # below (default hasn't registered yet for some reason), we still
        # take the call.
        event_bus.subscribe(CRED_DEF_FINISHED_EVENT, kanon_setup.on_cred_def)
        removed = _detach_default_cred_def_subscribers(event_bus)
        LOGGER.info(
            "did:kanon: intercepted CredDefFinishedEvent at startup "
            "(removed %d default subscriber(s), installed kanon wrapper) "
            "— did:kanon credDefs now synthesise rev-reg meta directly "
            "(no tails file, no anoncreds-rs rev-reg-def)",
            removed,
        )

    event_bus.subscribe(STARTUP_EVENT_PATTERN, _on_startup)

    # Keep references alive against GC.
    try:
        context.injector.bind_instance(KanonAwareRevocationSetup, kanon_setup)
    except Exception:  # noqa: BLE001
        pass

    return True


__all__ = ["KanonAwareRevocationSetup", "install"]
