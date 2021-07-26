// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

macro_rules! div_round_up {
    ($n:expr,$d:expr) => {
        ($n + $d - 1) / $d
    };
}

pub mod vhdx;
mod vhdx_bat;
mod vhdx_header;
mod vhdx_io;
mod vhdx_metadata;
