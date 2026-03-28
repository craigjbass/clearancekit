//
//  FAAFilterInteractor.swift
//  opfilter
//

import Foundation
import os

// MARK: - FAAFilterInteractor

final class FAAFilterInteractor: @unchecked Sendable {
    var onEvent: ((FolderOpenEvent) -> Void)? {
        get { postRespondHandler.onEvent }
        set { postRespondHandler.onEvent = newValue }
    }

    private let rulesStorage: OSAllocatedUnfairLock<[FAARule]>
    private let allowlistState: AllowlistState
    private let processTree: ProcessTreeProtocol
    private let processTreeQueue: DispatchQueue
    private let postRespondHandler: PostRespondHandler
    let pipeline: FileAuthPipeline

    init(
        initialRules: [FAARule] = faaPolicy,
        allowlistState: AllowlistState,
        processTree: ProcessTreeProtocol,
        pipeline: FileAuthPipeline,
        processTreeQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.process-tree", qos: .userInitiated),
        postRespondHandler: PostRespondHandler
    ) {
        self.rulesStorage = OSAllocatedUnfairLock(initialState: initialRules)
        self.allowlistState = allowlistState
        self.processTree = processTree
        self.pipeline = pipeline
        self.processTreeQueue = processTreeQueue
        self.postRespondHandler = postRespondHandler
    }

    func currentRules() -> [FAARule] {
        rulesStorage.withLock { $0 }
    }

    func currentAllowlist() -> [AllowlistEntry] {
        allowlistState.currentAllowlist()
    }

    func currentAncestorAllowlist() -> [AncestorAllowlistEntry] {
        allowlistState.currentAncestorAllowlist()
    }

    func updatePolicy(_ rules: [FAARule]) {
        rulesStorage.withLock { $0 = rules }
    }

    func updateAllowlist(_ entries: [AllowlistEntry]) {
        allowlistState.updateAllowlist(entries)
    }

    func updateAncestorAllowlist(_ entries: [AncestorAllowlistEntry]) {
        allowlistState.updateAncestorAllowlist(entries)
    }

    func handleFileAuth(_ fileEvent: FileAuthEvent) {
        pipeline.submit(fileEvent)
    }

    func handleFork(child: ProcessRecord) {
        processTreeQueue.async { [self] in processTree.insert(child) }
    }

    func handleExec(newImage: ProcessRecord) {
        processTreeQueue.async { [self] in processTree.insert(newImage) }
    }

    func handleExit(identity: ProcessIdentity) {
        processTreeQueue.async { [self] in processTree.remove(identity: identity) }
    }
}
