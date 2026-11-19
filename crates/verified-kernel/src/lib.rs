//! Executable security kernels checked directly by Verus.
//!
//! Cargo erases the contracts and compiles these exact function bodies.  Do
//! not replace a production call with a separately maintained model.

use vstd::prelude::*;

verus! {

/// Add an attacker-controlled amount to a bounded machine-sized counter.
/// Failure is exact: neither arithmetic overflow nor a mathematical total
/// above `limit` can be accepted.
pub fn charge_usize(current: usize, additional: usize, limit: usize) -> (out: Option<usize>)
    ensures
        out.is_some() ==> out.unwrap() as int == current as int + additional as int,
        out.is_some() ==> out.unwrap() <= limit,
        current as int + additional as int <= limit as int ==> out.is_some(),
        out.is_none() ==> current as int + additional as int > limit as int,
{
    if current > limit || additional > limit - current {
        None
    } else {
        Some(current + additional)
    }
}

/// `u64` form used by storage and byte-stream accounting.
pub fn charge_u64(current: u64, additional: u64, limit: u64) -> (out: Option<u64>)
    ensures
        out.is_some() ==> out.unwrap() as int == current as int + additional as int,
        out.is_some() ==> out.unwrap() <= limit,
        current as int + additional as int <= limit as int ==> out.is_some(),
        out.is_none() ==> current as int + additional as int > limit as int,
{
    if current > limit || additional > limit - current {
        None
    } else {
        Some(current + additional)
    }
}

/// `u32` form used by the restricted heuristic interpreter.
pub fn charge_u32(current: u32, additional: u32, limit: u32) -> (out: Option<u32>)
    ensures
        out.is_some() ==> out.unwrap() as int == current as int + additional as int,
        out.is_some() ==> out.unwrap() <= limit,
        current as int + additional as int <= limit as int ==> out.is_some(),
        out.is_none() ==> current as int + additional as int > limit as int,
{
    if current > limit || additional > limit - current {
        None
    } else {
        Some(current + additional)
    }
}

/// Select a non-empty read slice which cannot cross a caller-provided
/// sentinel.  OpenPGP uses a sentinel one byte above its plaintext limit so
/// the first excess byte is observable without permitting further expansion.
pub fn bounded_read_window(
    total: usize,
    sentinel: usize,
    buffer_len: usize,
) -> (out: Option<usize>)
    ensures
        out.is_some() ==> out.unwrap() > 0,
        out.is_some() ==> out.unwrap() <= buffer_len,
        out.is_some() ==> total as int + out.unwrap() as int <= sentinel as int,
        total < sentinel && buffer_len > 0 ==> out.is_some(),
{
    if total >= sentinel || buffer_len == 0 {
        None
    } else {
        let remaining = sentinel - total;
        if remaining < buffer_len {
            Some(remaining)
        } else {
            Some(buffer_len)
        }
    }
}

/// Multiply a structural cost by a bounded iteration count without allowing
/// overflow to turn a large program into a cheap one.
pub fn repeat_cost(unit: u32, count: u32, limit: u32) -> (out: Option<u32>)
    ensures
        out.is_some() ==> out.unwrap() as int == unit as int * count as int,
        out.is_some() ==> out.unwrap() <= limit,
{
    if count == 0 {
        return Some(0);
    }
    if unit > limit / count {
        return None;
    }
    assert(unit as int * count as int <= limit as int) by(nonlinear_arith)
        requires unit <= limit / count, count > 0;
    Some(unit * count)
}

/// Materialized bytes may consume, but never exceed, an existing reservation.
pub fn materialize_bytes(reserved: u64, materialized: u64, bytes: u64) -> (out: Option<u64>)
    ensures
        out.is_some() ==> materialized <= reserved,
        out.is_some() ==> out.unwrap() as int == materialized as int + bytes as int,
        out.is_some() ==> out.unwrap() <= reserved,
        materialized as int + bytes as int <= reserved as int ==> out.is_some(),
{
    if materialized > reserved || bytes > reserved - materialized {
        None
    } else {
        Some(materialized + bytes)
    }
}

/// A commit may publish no more bytes than were actually materialized, and
/// materialization itself must have stayed inside the reservation.
pub fn reservation_commit_allowed(reserved: u64, materialized: u64, added: u64) -> (out: bool)
    ensures
        out == (materialized as int <= reserved as int && added as int <= materialized as int),
{
    materialized <= reserved && added <= materialized
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustState {
    Known,
    Unknown,
}

/// Known correspondents may continue a formerly cold conversation, but an
/// unknown correspondent can never be admitted to a known thread.
pub fn thread_candidate_allowed(sender: TrustState, candidate: TrustState) -> (out: bool)
    ensures
        sender == TrustState::Unknown && out ==> candidate == TrustState::Unknown,
{
    match sender {
        TrustState::Known => true,
        TrustState::Unknown => match candidate {
            TrustState::Known => false,
            TrustState::Unknown => true,
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionState {
    Pending,
    InFlight,
    RetryScheduled,
    Sent,
    Failed,
    Ambiguous,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionEvent {
    Begin,
    ScheduleRetry,
    MarkSent,
    MarkFailed,
    MarkAmbiguous,
    Cancel,
    ExplicitRetry,
    RecoverInterrupted,
}

/// Authoritative SMTP outbox transition relation.
pub fn submission_transition(
    state: SubmissionState,
    event: SubmissionEvent,
) -> (out: Option<SubmissionState>)
    ensures
        state == SubmissionState::Sent ==> out.is_none(),
        state == SubmissionState::Ambiguous ==> out.is_none(),
        state == SubmissionState::Cancelled ==> out.is_none(),
{
    match (state, event) {
        (SubmissionState::Pending, SubmissionEvent::Begin)
        | (SubmissionState::RetryScheduled, SubmissionEvent::Begin) => Some(SubmissionState::InFlight),
        (SubmissionState::InFlight, SubmissionEvent::ScheduleRetry) => Some(SubmissionState::RetryScheduled),
        (SubmissionState::InFlight, SubmissionEvent::MarkSent) => Some(SubmissionState::Sent),
        (SubmissionState::InFlight, SubmissionEvent::MarkFailed) => Some(SubmissionState::Failed),
        (SubmissionState::InFlight, SubmissionEvent::MarkAmbiguous)
        | (SubmissionState::InFlight, SubmissionEvent::RecoverInterrupted) => Some(SubmissionState::Ambiguous),
        (SubmissionState::Pending, SubmissionEvent::Cancel)
        | (SubmissionState::RetryScheduled, SubmissionEvent::Cancel)
        | (SubmissionState::Failed, SubmissionEvent::Cancel) => Some(SubmissionState::Cancelled),
        (SubmissionState::Failed, SubmissionEvent::ExplicitRetry) => Some(SubmissionState::Pending),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImapMutationState {
    Pending,
    InFlight,
    Applied,
    Conflict,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImapMutationEvent {
    Begin,
    ResumeIdempotent,
    Apply,
    RecordConflict,
    Cancel,
}

/// Authoritative durable IMAP-mutation transition relation.
pub fn imap_mutation_transition(
    state: ImapMutationState,
    event: ImapMutationEvent,
) -> (out: Option<ImapMutationState>)
    ensures
        state == ImapMutationState::Applied ==> out.is_none(),
        state == ImapMutationState::Cancelled ==> out.is_none(),
{
    match (state, event) {
        (ImapMutationState::Pending, ImapMutationEvent::Begin) => Some(ImapMutationState::InFlight),
        (ImapMutationState::InFlight, ImapMutationEvent::ResumeIdempotent) => Some(ImapMutationState::InFlight),
        (ImapMutationState::InFlight, ImapMutationEvent::Apply) => Some(ImapMutationState::Applied),
        (ImapMutationState::InFlight, ImapMutationEvent::RecordConflict)
        | (ImapMutationState::Pending, ImapMutationEvent::RecordConflict) => Some(ImapMutationState::Conflict),
        (ImapMutationState::Pending, ImapMutationEvent::Cancel)
        | (ImapMutationState::Conflict, ImapMutationEvent::Cancel) => Some(ImapMutationState::Cancelled),
        _ => None,
    }
}

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_contract_examples() {
        assert_eq!(charge_usize(8, 4, 12), Some(12));
        assert_eq!(charge_usize(8, 5, 12), None);
        assert!(!thread_candidate_allowed(
            TrustState::Unknown,
            TrustState::Known
        ));
        assert_eq!(
            submission_transition(SubmissionState::Ambiguous, SubmissionEvent::Begin),
            None
        );
        assert_eq!(
            imap_mutation_transition(ImapMutationState::Pending, ImapMutationEvent::Begin),
            Some(ImapMutationState::InFlight)
        );
    }

    #[test]
    fn terminal_states_reject_every_event() {
        let submission_events = [
            SubmissionEvent::Begin,
            SubmissionEvent::ScheduleRetry,
            SubmissionEvent::MarkSent,
            SubmissionEvent::MarkFailed,
            SubmissionEvent::MarkAmbiguous,
            SubmissionEvent::Cancel,
            SubmissionEvent::ExplicitRetry,
            SubmissionEvent::RecoverInterrupted,
        ];
        for state in [
            SubmissionState::Sent,
            SubmissionState::Ambiguous,
            SubmissionState::Cancelled,
        ] {
            for event in submission_events {
                assert_eq!(submission_transition(state, event), None);
            }
        }

        let imap_events = [
            ImapMutationEvent::Begin,
            ImapMutationEvent::ResumeIdempotent,
            ImapMutationEvent::Apply,
            ImapMutationEvent::RecordConflict,
            ImapMutationEvent::Cancel,
        ];
        for state in [ImapMutationState::Applied, ImapMutationState::Cancelled] {
            for event in imap_events {
                assert_eq!(imap_mutation_transition(state, event), None);
            }
        }
    }

    #[test]
    fn accounting_rejects_boundaries_without_wrapping() {
        assert_eq!(charge_u64(u64::MAX, 1, u64::MAX), None);
        assert_eq!(charge_usize(usize::MAX, 1, usize::MAX), None);
        assert_eq!(repeat_cost(u32::MAX, 2, u32::MAX), None);
        assert_eq!(materialize_bytes(10, 8, 2), Some(10));
        assert_eq!(materialize_bytes(10, 8, 3), None);
        assert!(reservation_commit_allowed(10, 10, 10));
        assert!(!reservation_commit_allowed(10, 11, 0));
        assert!(!reservation_commit_allowed(10, 5, 6));
    }
}
