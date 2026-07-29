import Foundation

/// A deliberately small JSON object parser for security-sensitive provider
/// responses. It retains number lexemes and rejects duplicate members.
struct StrictJSONObject {
    enum Value: Equatable {
        case string(String)
        case number(String)
        case boolean(Bool)
        case null
        case object([String: Value])
        case array([Value])
    }

    let values: [String: Value]

    init(data: Data, maximumBytes: Int) throws {
        guard !data.isEmpty, data.count <= maximumBytes else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        var parser = Parser(bytes: Array(data))
        values = try parser.parse()
    }
}

private struct Parser {
    let bytes: [UInt8]
    var index = 0

    mutating func parse() throws -> [String: StrictJSONObject.Value] {
        let result = try parseObject(depth: 0)
        skipWhitespace()
        try requireEnd()
        return result
    }

    private mutating func parseObject(
        depth: Int
    ) throws -> [String: StrictJSONObject.Value] {
        guard depth <= 8 else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        skipWhitespace()
        try consume(0x7b)
        skipWhitespace()
        var result: [String: StrictJSONObject.Value] = [:]
        if consumeIfPresent(0x7d) {
            return result
        }

        while true {
            let key = try parseString()
            guard result[key] == nil else {
                throw GitHubDeviceFlowFailure.malformedResponse
            }
            skipWhitespace()
            try consume(0x3a)
            skipWhitespace()
            result[key] = try parseValue(depth: depth + 1)
            skipWhitespace()
            if consumeIfPresent(0x7d) {
                break
            }
            try consume(0x2c)
            skipWhitespace()
        }
        return result
    }

    private mutating func parseValue(depth: Int) throws -> StrictJSONObject.Value {
        guard let byte = current else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        switch byte {
        case 0x22:
            return .string(try parseString())
        case 0x2d, 0x30...0x39:
            return .number(try parseNumber())
        case 0x74:
            try consumeLiteral("true")
            return .boolean(true)
        case 0x66:
            try consumeLiteral("false")
            return .boolean(false)
        case 0x6e:
            try consumeLiteral("null")
            return .null
        case 0x7b:
            return .object(try parseObject(depth: depth))
        case 0x5b:
            return .array(try parseArray(depth: depth))
        default:
            throw GitHubDeviceFlowFailure.malformedResponse
        }
    }

    private mutating func parseArray(
        depth: Int
    ) throws -> [StrictJSONObject.Value] {
        guard depth <= 8 else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        try consume(0x5b)
        skipWhitespace()
        var result: [StrictJSONObject.Value] = []
        if consumeIfPresent(0x5d) {
            return result
        }
        while true {
            result.append(try parseValue(depth: depth + 1))
            skipWhitespace()
            if consumeIfPresent(0x5d) {
                return result
            }
            try consume(0x2c)
            skipWhitespace()
        }
    }

    private mutating func parseString() throws -> String {
        let start = index
        try consume(0x22)
        var escaped = false
        while let byte = current {
            guard index - start <= 4_096 else {
                throw GitHubDeviceFlowFailure.malformedResponse
            }
            if escaped {
                if byte == 0x75 {
                    advance()
                    for _ in 0..<4 {
                        guard let hex = current, isHex(hex) else {
                            throw GitHubDeviceFlowFailure.malformedResponse
                        }
                        advance()
                    }
                    escaped = false
                    continue
                }
                guard [0x22, 0x5c, 0x2f, 0x62, 0x66, 0x6e, 0x72, 0x74].contains(byte)
                else {
                    throw GitHubDeviceFlowFailure.malformedResponse
                }
                escaped = false
                advance()
            } else if byte == 0x5c {
                escaped = true
                advance()
            } else if byte == 0x22 {
                advance()
                let encoded = Data(bytes[start..<index])
                do {
                    return try JSONDecoder().decode(String.self, from: encoded)
                } catch {
                    throw GitHubDeviceFlowFailure.malformedResponse
                }
            } else {
                guard byte >= 0x20 else {
                    throw GitHubDeviceFlowFailure.malformedResponse
                }
                advance()
            }
        }
        throw GitHubDeviceFlowFailure.malformedResponse
    }

    private mutating func parseNumber() throws -> String {
        let start = index
        consumeIfPresent(0x2d)
        guard let first = current else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        if first == 0x30 {
            advance()
            if let next = current, isDigit(next) {
                throw GitHubDeviceFlowFailure.malformedResponse
            }
        } else {
            guard (0x31...0x39).contains(first) else {
                throw GitHubDeviceFlowFailure.malformedResponse
            }
            repeat { advance() } while current.map(isDigit) == true
        }
        if consumeIfPresent(0x2e) {
            guard current.map(isDigit) == true else {
                throw GitHubDeviceFlowFailure.malformedResponse
            }
            repeat { advance() } while current.map(isDigit) == true
        }
        if current == 0x65 || current == 0x45 {
            advance()
            if current == 0x2b || current == 0x2d {
                advance()
            }
            guard current.map(isDigit) == true else {
                throw GitHubDeviceFlowFailure.malformedResponse
            }
            repeat { advance() } while current.map(isDigit) == true
        }
        guard let value = String(bytes: bytes[start..<index], encoding: .utf8)
        else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        return value
    }

    private mutating func consumeLiteral(_ literal: StaticString) throws {
        for expected in String(describing: literal).utf8 {
            try consume(expected)
        }
    }

    private mutating func consume(_ expected: UInt8) throws {
        guard current == expected else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        advance()
    }

    @discardableResult
    private mutating func consumeIfPresent(_ expected: UInt8) -> Bool {
        guard current == expected else { return false }
        advance()
        return true
    }

    private mutating func skipWhitespace() {
        while let byte = current, [0x20, 0x09, 0x0a, 0x0d].contains(byte) {
            advance()
        }
    }

    private func requireEnd() throws {
        guard index == bytes.endIndex else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
    }

    private var current: UInt8? {
        index < bytes.endIndex ? bytes[index] : nil
    }

    private mutating func advance() {
        index += 1
    }

    private func isDigit(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte)
    }

    private func isHex(_ byte: UInt8) -> Bool {
        isDigit(byte) || (0x41...0x46).contains(byte) || (0x61...0x66).contains(byte)
    }
}
