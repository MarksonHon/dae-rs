//! Routing decision engine modules.
//!
//! Compiles routing rules into kernel-readable forms and decides where
//! intercepted connections go:
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`matcher`] | Routing rule matching & eBPF rule compilation |
//! | [`routing_handoff`] | Handoff of matched connections to the proxy path |
//! | [`domain_routing`] | Domain (DNS-based) routing bitmap tracking |

pub mod domain_routing;
pub mod matcher;
pub mod routing_handoff;
