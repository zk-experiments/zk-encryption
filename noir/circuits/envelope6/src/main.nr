//! The channel envelope as a pipeline app: a six-field payload (DG1's
//! plaintext, a note opening, ...) sealed on the ratchet channel under the
//! payload domain its family pins (`bind_const`), linked to the app that
//! committed to it by the payload's commitment (`channel::payload::envelope`).
//!

use channel::payload::{envelope, Payload};

fn main(
    domain: Field,
    payload: Payload<6>,
    salt: Field,
    context: Field,
    s: Field,
) -> return_data [Field; 10] {
    envelope(domain, payload, salt, context, s)
}
