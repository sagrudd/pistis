import Foundation
import Network

/// One connection to an already checked offer. This does not authenticate the
/// host: that only happens after both humans confirm the transcript-bound SAS.
final class AttendedCustodyPairingConnectionV1: @unchecked Sendable {
    private let connection: NWConnection
    private let deadline: ContinuousClock.Instant
    private let queue = DispatchQueue(label: "org.mnemosyne.pistis.custody-pairing.v1")

    init(offer: AttendedCustodyPairingOfferV1, deadline: ContinuousClock.Instant) throws {
        let host = offer.address.map { String($0) }.joined(separator: ".")
        guard let port = NWEndpoint.Port(rawValue: offer.port), ContinuousClock().now < deadline else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: .tcp)
        self.deadline = deadline
    }

    deinit { connection.cancel() }

    func cancel() { connection.cancel() }

    func start() async throws {
        let _: Void = try await bounded { finish in
            self.connection.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(.success(()))
                case .failed(_), .cancelled, .waiting(_): finish(.failure(PlatformFailure.custodyRewrapUnavailable))
                default: break
                }
            }
            self.connection.start(queue: self.queue)
        }
    }

    func send(_ data: Data) async throws {
        guard !data.isEmpty, data.count <= 32_802 else { throw PlatformFailure.custodyRewrapUnavailable }
        let _: Void = try await bounded { finish in
            self.connection.send(content: data, completion: .contentProcessed { error in
                if error != nil { finish(.failure(PlatformFailure.custodyRewrapUnavailable)) }
                else { finish(.success(())) }
            })
        }
    }

    func sendRecord(_ record: Data) async throws {
        guard record.count >= 30, record.count <= 32_798 else { throw PlatformFailure.custodyRewrapUnavailable }
        var length = UInt32(record.count).bigEndian
        var frame = Data(); withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }; frame.append(record)
        try await send(frame)
    }

    func receiveRecord() async throws -> Data {
        let header = try await receiveExactly(4)
        let size = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size >= 30, size <= 32_798 else { throw PlatformFailure.custodyRewrapUnavailable }
        return try await receiveExactly(Int(size))
    }

    private func receiveExactly(_ count: Int) async throws -> Data {
        var output = Data()
        while output.count < count {
            let remaining = count - output.count
            let chunk: Data = try await bounded { finish in
                self.connection.receive(minimumIncompleteLength: 1, maximumLength: remaining) { data, _, _, error in
                    guard error == nil, let data, !data.isEmpty else {
                        finish(.failure(PlatformFailure.custodyRewrapUnavailable)); return
                    }
                    finish(.success(data))
                }
            }
            output.append(chunk)
        }
        return output
    }

    private func bounded<T: Sendable>(_ start: @escaping @Sendable (@escaping @Sendable (Result<T, Error>) -> Void) -> Void) async throws -> T {
        guard ContinuousClock().now < deadline else { connection.cancel(); throw PlatformFailure.custodyRewrapUnavailable }
        let gate = PairingOperationV1<T>()
        let value = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard gate.install(continuation) else { return }
                let timer = Task {
                    do {
                        try await Task.sleep(until: self.deadline, clock: .continuous)
                        if gate.finish(.failure(PlatformFailure.custodyRewrapUnavailable)) { self.connection.cancel() }
                    } catch { }
                }
                gate.installTimer(timer)
                start { result in
                    if gate.finish(result), case .failure = result { self.connection.cancel() }
                }
            }
        } onCancel: {
            if gate.finish(.failure(PlatformFailure.custodyRewrapUnavailable)) { self.connection.cancel() }
        }
        guard ContinuousClock().now < deadline else { connection.cancel(); throw PlatformFailure.custodyRewrapUnavailable }
        return value
    }
}

private final class PairingOperationV1<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?
    private var timer: Task<Void, Never>?
    private var finished = false
    func install(_ continuation: CheckedContinuation<T, Error>) -> Bool {
        lock.lock()
        if finished { lock.unlock(); continuation.resume(throwing: PlatformFailure.custodyRewrapUnavailable); return false }
        self.continuation = continuation; lock.unlock(); return true
    }
    func installTimer(_ timer: Task<Void, Never>) {
        lock.lock(); if finished { lock.unlock(); timer.cancel(); return }
        self.timer = timer; lock.unlock()
    }
    @discardableResult func finish(_ result: Result<T, Error>) -> Bool {
        lock.lock()
        guard !finished else { lock.unlock(); return false }
        finished = true; let current = continuation; continuation = nil; let timer = timer; self.timer = nil
        lock.unlock(); timer?.cancel(); current?.resume(with: result); return true
    }
}
