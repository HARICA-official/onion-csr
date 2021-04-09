# SPDX-FileCopyrightText: 2021 Antonios Eleftheriadis <antoniose@harica.gr>
# SPDX-FileCopyrightText: 2021 HARICA <ca@harica.gr>
# SPDX-License-Identifier: GPL-3.0-or-later

# frozen_string_literal: true

require 'ffi'

module Ed25519
  extend FFI::Library
  ffi_lib './libed25519.so'

  attach_function :ed25519_sign, %i[buffer_inout buffer_in size_t buffer_in buffer_in], :void
end
