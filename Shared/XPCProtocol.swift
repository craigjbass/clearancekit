//
//  XPCProtocol.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation

// MARK: - Constants

public enum XPCConstants {
    public static let machServiceName = "uk.craigbass.clearancekit.opfilter"
}

// MARK: - FolderOpenEvent

@objc(FolderOpenEvent)
public class FolderOpenEvent: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    @objc public let path: String
    @objc public let timestamp: Date
    @objc public let processID: Int32
    @objc public let processPath: String

    public init(path: String, timestamp: Date, processID: Int32, processPath: String) {
        self.path = path
        self.timestamp = timestamp
        self.processID = processID
        self.processPath = processPath
        super.init()
    }

    public required init?(coder: NSCoder) {
        guard let path = coder.decodeObject(of: NSString.self, forKey: "path") as String?,
              let timestamp = coder.decodeObject(of: NSDate.self, forKey: "timestamp") as Date?,
              let processPath = coder.decodeObject(of: NSString.self, forKey: "processPath") as String? else {
            return nil
        }
        self.path = path
        self.timestamp = timestamp
        self.processID = coder.decodeInt32(forKey: "processID")
        self.processPath = processPath
        super.init()
    }

    public func encode(with coder: NSCoder) {
        coder.encode(path as NSString, forKey: "path")
        coder.encode(timestamp as NSDate, forKey: "timestamp")
        coder.encode(processID, forKey: "processID")
        coder.encode(processPath as NSString, forKey: "processPath")
    }

    public override var description: String {
        "FolderOpenEvent(path: \(path), pid: \(processID), processPath: \(processPath))"
    }
}

// MARK: - Server Protocol

@objc(OpFilterServiceProtocol)
public protocol OpFilterServiceProtocol {
    func registerClient(withReply reply: @escaping (Bool) -> Void)
    func unregisterClient(withReply reply: @escaping (Bool) -> Void)
    func isMonitoringActive(withReply reply: @escaping (Bool) -> Void)
}

// MARK: - Client Protocol

@objc(OpFilterClientProtocol)
public protocol OpFilterClientProtocol {
    func folderOpened(_ event: FolderOpenEvent)
    func monitoringStatusChanged(_ isActive: Bool)
}
