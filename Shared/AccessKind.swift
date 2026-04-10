//
//  AccessKind.swift
//  clearancekit
//
//  Classification of a file-access request as either reading the file or
//  modifying it. Set once at the Endpoint Security boundary so the domain
//  layer never has to know about Darwin fcntl constants.
//

import Foundation

public enum AccessKind: String, Sendable, Codable, Equatable {
    case read
    case write
}
