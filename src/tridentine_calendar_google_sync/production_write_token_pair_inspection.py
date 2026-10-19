"""Read-only local pair observations; never recovery approval or a credential session.

No CLI or operational caller is connected. Even matching, unexpired inputs cannot
prove a successful prior publication, provider validity, or generation freshness.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal

from tridentine_calendar_google_sync.production_write_target import (
    ProductionWriteTargetConfig,
    validate_production_write_target_config,
)
from tridentine_calendar_google_sync.production_write_token import (
    ProductionWriteTokenError,
    ProductionWriteTokenSessionLockError,
    _production_write_session_lock,
    verify_production_write_authorized_user_token,
)
from tridentine_calendar_google_sync.production_write_token_io import (
    load_production_write_authorized_user_token,
    load_production_write_token_generation_state,
    render_production_write_authorized_user_token_json,
    render_production_write_token_generation_state_json,
    validate_production_write_token_path_set,
)


class PairInspectionState(StrEnum):
    """Fixed diagnostic labels, not operation eligibility or presence assertions."""

    LOCAL_CONTENTS_CONSISTENT_NOT_APPROVED = "local_contents_consistent_not_approved"
    INPUT_UNVERIFIED = "input_unverified"
    PAIR_REJECTED = "pair_rejected"
    CONTENTS_CHANGED = "contents_changed"
    LOCK_BUSY = "lock_busy"
    LOCK_UNVERIFIED = "lock_unverified"
    INSPECTION_UNVERIFIED = "inspection_unverified"


@dataclass(frozen=True, slots=True)
class TokenPairInspection:
    """Only aggregate local observations; no paths, identifiers, secrets or digests.

    token_expired compares stored expiry with caller-supplied UTC, not provider
    validity. None is unverified, never evidence of absence. Approval is always
    false, including for consistent unexpired pairs and after a prior save error.
    """

    state: PairInspectionState
    token_expired: bool | None = None
    reuse_authorized: Literal[False] = field(default=False, init=False)


def inspect_production_write_token_pair(
    production_write_token_path: str | Path,
    generation_state_path: str | Path,
    production_read_token_path: str | Path,
    test_write_token_path: str | Path,
    target: ProductionWriteTargetConfig,
    *,
    now: datetime,
) -> TokenPairInspection:
    """Observe existing inputs twice under the shared session/bundle lock protocol.

    Linux uses existing 0700 parents and nonblocking cooperative locks. Windows
    retains existing readers/ACLs and has NO new serialization. Other non-Windows
    systems have no unlocked fallback. Reserved paths receive metadata checks
    only. Missing and unreadable inputs share INPUT_UNVERIFIED; do not infer which.

    Provider-origin labels are checked by the existing validator, not attested by
    this inspector. It invokes no authorizer/refresher/session/writer and returns
    no credentials. Reads can update access metadata; this is not forensic imaging.
    Ordinary failures are aggregate observations without exception text/context.
    BaseException unwinds locks and propagates; no recovery result is fabricated.
    """
    failure_state = PairInspectionState.INPUT_UNVERIFIED
    try:
        if not isinstance(now, datetime) or now.utcoffset() != timedelta(0):
            return TokenPairInspection(PairInspectionState.INPUT_UNVERIFIED)
        validate_production_write_target_config(target)
        validate_production_write_token_path_set(
            production_write_token_path=production_write_token_path,
            generation_state_path=generation_state_path,
            production_read_token_path=production_read_token_path,
            test_write_token_path=test_write_token_path,
            client_config_path=None,
            write_token_exists=True,
            generation_state_exists=True,
        )
        with _production_write_session_lock(
            production_write_token_path, generation_state_path
        ) as checkpoint:
            state = load_production_write_token_generation_state(generation_state_path)
            token = load_production_write_authorized_user_token(production_write_token_path)
            checkpoint()
            failure_state = PairInspectionState.INSPECTION_UNVERIFIED
            try:
                verify_production_write_authorized_user_token(token, state, target)
            except ProductionWriteTokenError:
                return TokenPairInspection(PairInspectionState.PAIR_REJECTED)
            # Compare parsed canonical content, without hashing or exposing token
            # material. This is not retained leaf identity or an atomic snapshot.
            state_bytes = render_production_write_token_generation_state_json(state).encode("utf-8")
            token_bytes = render_production_write_authorized_user_token_json(token).encode("utf-8")
            failure_state = PairInspectionState.INPUT_UNVERIFIED
            second_state = load_production_write_token_generation_state(generation_state_path)
            second_token = load_production_write_authorized_user_token(production_write_token_path)
            checkpoint()
            failure_state = PairInspectionState.INSPECTION_UNVERIFIED
            state_matches = hmac.compare_digest(
                state_bytes,
                render_production_write_token_generation_state_json(second_state).encode("utf-8"),
            )
            token_matches = hmac.compare_digest(
                token_bytes,
                render_production_write_authorized_user_token_json(second_token).encode("utf-8"),
            )
            if not state_matches or not token_matches:
                return TokenPairInspection(PairInspectionState.CONTENTS_CHANGED)
            result = TokenPairInspection(
                PairInspectionState.LOCAL_CONTENTS_CONSISTENT_NOT_APPROVED,
                token_expired=token.expiry <= now,
            )
            checkpoint()
        # Do not publish a positive local observation before normal context exit.
        return result
    except ProductionWriteTokenSessionLockError as exc:
        return TokenPairInspection(
            PairInspectionState.LOCK_BUSY
            if exc.code == "production_write_token_session_busy"
            else PairInspectionState.LOCK_UNVERIFIED
        )
    except Exception:
        return TokenPairInspection(failure_state)
