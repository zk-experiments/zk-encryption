//! The receiver's state: its long-term keys, the channels opened to it (a
//! window of chain keys each) and what it needs to recognise, open and
//! de-duplicate transfers (PROTOCOL.md §§4–5, R6–R9).
//!
//! Persist the whole `Receiver` after every scan that returns
//! [`Scan::Handshake`] or [`Scan::Ratchet`]: those consumed a chain key or
//! opened a channel, and a state restored from before them would open a
//! replayed transfer again.

use crate::emit::{Delivery, Dg1, NoteOpening};
use crate::ratchet::{Ratchet, ReceiverKeys, Session};
use crate::{Error, Fr};
use std::collections::VecDeque;

/// The result of scanning one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scan {
    /// A handshake to this receiver: a channel is now open. `note` is output
    /// 0's opening (it equals the transfer's C0 for this receiver's pk) and
    /// `dg1` the sender's DG1.
    Handshake { note: NoteOpening, dg1: Dg1 },
    /// A transfer on an open channel, at chain index `t`.
    Ratchet { t: u64, note: NoteOpening, dg1: Dg1 },
    /// Not addressed to this receiver (no held chain key and the tag isn't
    /// ours, or beyond every window: see `resync`).
    NotMine,
    /// Addressed to this receiver but not to be trusted: a reused chain
    /// index or replayed handshake (`Error::ReusedIndex`), or a transfer that
    /// doesn't open or whose note isn't ours. The state is unchanged.
    Invalid(Error),
}

/// The receiver's persisted state.
pub struct Receiver {
    pub(crate) keys: ReceiverKeys,
    /// The shielded address notes to this receiver are committed to.
    pub(crate) pk: Fr,
    pub(crate) window: u64,
    pub(crate) max_skipped: usize,
    pub(crate) sessions: Vec<Session>,
    /// Recently consumed ratchet C_t values, bounded to `consumed_limit()`.
    pub(crate) consumed: VecDeque<Fr>,
    /// C_0 of every channel opened, kept: a replayed handshake is never opened twice.
    pub(crate) channels: Vec<Fr>,
}

impl Receiver {
    /// A receiver with fresh long-term keys, holding `window` chain keys
    /// ahead and at most `window` skipped keys per channel.
    pub fn generate(pk: Fr, window: u64) -> Self {
        Self::new(
            ReceiverKeys::generate(),
            pk,
            window,
            usize::try_from(window).expect("window fits usize"),
        )
    }

    pub fn new(keys: ReceiverKeys, pk: Fr, window: u64, max_skipped: usize) -> Self {
        Self {
            keys,
            pk,
            window,
            max_skipped,
            sessions: vec![],
            consumed: VecDeque::new(),
            channels: vec![],
        }
    }

    /// The long-term keys (their public part goes into the bundle).
    pub fn keys(&self) -> &ReceiverKeys {
        &self.keys
    }

    pub fn pk(&self) -> Fr {
        self.pk
    }

    pub fn window(&self) -> u64 {
        self.window
    }

    /// Channels opened so far.
    pub fn channels(&self) -> usize {
        self.sessions.len()
    }

    /// Consumed C_t values kept: a window plus a margin per channel.
    pub fn consumed_limit(&self) -> usize {
        (usize::try_from(self.window).expect("window fits usize") + 4) * self.sessions.len().max(1)
    }

    /// Consumed C_t values remembered.
    pub fn consumed(&self) -> usize {
        self.consumed.len()
    }

    /// Chain keys held ahead and skipped, over every channel.
    pub fn held(&self) -> usize {
        self.sessions.iter().map(Session::held).sum()
    }

    /// Extends every channel's window by `n` keys (PROTOCOL.md §5 step 5),
    /// when a sender may have skipped more than `window` indices.
    pub fn resync(&mut self, n: u64) {
        for s in &mut self.sessions {
            s.resync(n);
        }
    }

    /// Opens c_note (checking it opens C0 for our pk) and c_id under chain key `s`.
    fn open(&self, d: &Delivery, s: Fr) -> Result<(NoteOpening, Dg1), Error> {
        let ctx = d.ctx();
        let e = &d.envelope;
        let note = NoteOpening::from_payload(&Ratchet::open_payload(
            Ratchet::key_note(),
            s,
            e.c_t,
            ctx,
            &e.c_note,
        )?)?;
        if note.commitment(d.cid, self.pk) != d.commitments[0].0 {
            return Err(Error::HandshakeMismatch);
        }
        Ok((note, Dg1::open(s, e.c_t, ctx, &e.c_id)?))
    }

    /// Scans one transaction (PROTOCOL.md R6): look C_t up in every window;
    /// else test the tag and, on a match, derive S_0 (checking the carried
    /// ciphertext and C_0). Open the note and DG1 and check the note against
    /// C0 first; only then consume the chain key or open the channel.
    // The one-arm match keeps the error value for `Scan::Invalid`.
    #[allow(clippy::single_match_else)]
    pub fn scan(&mut self, d: &Delivery) -> Scan {
        let e = &d.envelope;
        let held = self
            .sessions
            .iter()
            .enumerate()
            .find_map(|(i, x)| x.peek(e.c_t).map(|(t, s)| (i, t, s)));
        let (s, t, session) = if let Some((i, t, s)) = held {
            (s, t, Some(i))
        } else if self.consumed.contains(&e.c_t) || self.channels.contains(&e.c_t) {
            return Scan::Invalid(Error::ReusedIndex);
        } else {
            let k = &e.kem;
            match self
                .keys
                .handshake_root(k.ephemeral, k.tag, k.ct_commitment, e.c_t, &k.ct)
            {
                Ok(s0) => (s0, 0, None),
                Err(Error::NotForUs) => return Scan::NotMine,
                Err(err) => return Scan::Invalid(err),
            }
        };
        let (note, dg1) = match self.open(d, s) {
            Ok(x) => x,
            Err(err) => {
                return Scan::Invalid(err);
            }
        };
        match session {
            Some(i) => {
                self.sessions[i].take(e.c_t).expect("peeked");
                self.consumed.push_back(e.c_t);
                while self.consumed.len() > self.consumed_limit() {
                    self.consumed.pop_front();
                }
                Scan::Ratchet { t, note, dg1 }
            }
            None => {
                self.sessions
                    .push(Session::start_with(s, self.window, self.max_skipped));
                self.channels.push(e.c_t);
                Scan::Handshake { note, dg1 }
            }
        }
    }

    /// The sessions, for inspection (tests, diagnostics).
    pub fn sessions(&self) -> &[Session] {
        &self.sessions
    }
}
