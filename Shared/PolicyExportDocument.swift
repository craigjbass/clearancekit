//
//  PolicyExportDocument.swift
//  clearancekit
//

import Foundation

/// Container written to / read from a `.json` policy export file.
public struct PolicyExportDocument: Codable {
    public let schemaVersion: Int
    public let exportedAt: Date
    public let rules: [FAARule]

    public init(rules: [FAARule]) {
        self.schemaVersion = 1
        self.exportedAt = Date()
        self.rules = rules
    }

    // MARK: - Serialisation helpers

    public static func encode(_ document: PolicyExportDocument) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(document)
    }

    public static func decode(from data: Data) throws -> PolicyExportDocument {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(PolicyExportDocument.self, from: data)
    }
}
