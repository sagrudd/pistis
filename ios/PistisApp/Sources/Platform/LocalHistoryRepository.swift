import Foundation

/// Minimized, non-authoritative diagnostic history retained after local
/// credential cleanup. Prosopikon remains the authoritative audit source.
@MainActor
final class LocalHistoryRepository {
    static let shared = LocalHistoryRepository()
    static let historyDidChangeNotification = Notification.Name(
        "org.mnemosynebiosciences.pistis.local-history-changed"
    )

    private let defaults: UserDefaults
    private let key = "org.mnemosynebiosciences.pistis.local-history.v1"
    private let maximumRecords = 128
    private let maximumEncodedBytes = 65_536

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func records() throws -> [HistoryEvent] {
        guard let data = defaults.data(forKey: key) else { return [] }
        guard data.count <= maximumEncodedBytes else {
            throw PlatformFailure.invalidConfiguration
        }
        return try JSONDecoder().decode([HistoryEvent].self, from: data)
    }

    func record(_ event: HistoryEvent) throws {
        var retained = try records().filter { $0.id != event.id }
        retained.append(event)
        retained = Array(retained.suffix(maximumRecords))
        let encoded = try JSONEncoder().encode(retained)
        guard encoded.count <= maximumEncodedBytes else {
            throw PlatformFailure.invalidConfiguration
        }
        defaults.set(encoded, forKey: key)
        NotificationCenter.default.post(name: Self.historyDidChangeNotification, object: nil)
    }
}
