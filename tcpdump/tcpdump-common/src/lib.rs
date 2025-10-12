#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(feature = "user")]
extern crate std;

#[cfg(feature = "user")]
pub mod user;

#[cfg(feature = "ebpf")]
pub mod ebpf;
