//! The channel session as a pipeline app: the handshake KEM (real keys on a
//! handshake, a throwaway key on a ratchet transfer) and C_t, published with
//! the context the envelopes and the transfer are bound to
//! (`channel::session`).
//!

use channel::session::{Channel, session, SESSION_FIELDS};

fn main(context: Field, channel: Channel) -> return_data [Field; SESSION_FIELDS] {
    session(context, channel)
}
