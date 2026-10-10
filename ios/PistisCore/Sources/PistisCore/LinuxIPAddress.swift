#if os(Linux)
  import Glibc

  /// Linux-only equivalents for the address operations used by ADR 0029.
  /// Apple builds continue to use Network's original address implementations.
  struct IPv4Address: Equatable, Sendable {
    let debugDescription: String

    init?(_ text: String) {
      guard let canonical = canonicalIPAddress(text, family: AF_INET) else { return nil }
      debugDescription = canonical
    }
  }

  struct IPv6Address: Equatable, Sendable {
    let debugDescription: String

    init?(_ text: String) {
      guard let canonical = canonicalIPAddress(text, family: AF_INET6) else { return nil }
      debugDescription = canonical
    }
  }

  private func canonicalIPAddress(_ text: String, family: Int32) -> String? {
    var address = in6_addr()
    let parsed = withUnsafeMutablePointer(to: &address) { pointer in
      text.withCString { inet_pton(family, $0, pointer) }
    }
    guard parsed == 1 else { return nil }
    var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    let formatted = withUnsafePointer(to: &address) { pointer in
      output.withUnsafeMutableBufferPointer { buffer in
        inet_ntop(family, pointer, buffer.baseAddress, socklen_t(buffer.count)) != nil
      }
    }
    guard formatted else { return nil }
    return output.withUnsafeBufferPointer { buffer in
      buffer.baseAddress.map { String(cString: $0) }
    }
  }
#endif
