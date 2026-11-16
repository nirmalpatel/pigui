import Darwin
import Foundation
import Security
import SystemConfiguration

private let helperVersion: String = {
    let value = Bundle.main.object(
        forInfoDictionaryKey: "CFBundleShortVersionString"
    ) as? String
    let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return trimmed.isEmpty ? "dev" : trimmed
}()
private let defaultServiceName = "com.pigui.helper"
private let pfctlPath = "/sbin/pfctl"
private let ifconfigPath = "/sbin/ifconfig"
private let tcpdumpPath = "/usr/sbin/tcpdump"
private let blockAnchor = "com.apple/000.pigui"
private let allowAnchor = "com.apple/300.pigui.allow"
private let blockAnchorSuffix = "000.pigui"
private let allowAnchorSuffix = "300.pigui.allow"
private let pflogInterface = "pflog1"
private let dynamicBlockTables = [
    "pigui_block4_in",
    "pigui_block4_out",
    "pigui_block6_in",
    "pigui_block6_out",
]
private let maxFirewallRulesBytes = 256 * 1024

private struct CommandResult {
    let status: Int32
    let stdout: String
    let stderr: String

    var combined: String {
        stdout + stderr
    }
}

private func envValue(_ key: String) -> String? {
    guard let value = ProcessInfo.processInfo.environment[key] else {
        return nil
    }
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
}

private func argumentValue(_ name: String) -> String? {
    let arguments = CommandLine.arguments
    guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else {
        return nil
    }
    return arguments[index + 1]
}

@objc protocol PiguiHelperProtocol {
    func request(_ payload: String, withReply reply: @escaping (String) -> Void)
}

private struct ConsoleUser {
    let name: String
    let uid: uid_t
    let gid: gid_t
    let home: String
    let group: String
}

final class HelperService: NSObject, PiguiHelperProtocol {
    private let queue = DispatchQueue(label: "com.pigui.helper.queue")
    private let fileManager = FileManager.default
    private var snortProcess: Process?
    private var snortLog: FileHandle?
    private var snortPid: pid_t?
    private var captureInterface: String?
    private var captureLogDir: String?
    private var captureStartedAt: Int?
    let isDevelopment: Bool
    private let stateRoot: String
    private let auditDir: String
    private let auditPath: String
    private let devSnortBinary: String?
    private let devSnortConfig: String?
    private let devLogDir: String?
    private var firewallGeneration = 0
    private var firewallAppliedAt: Int?
    private var firewallPFEnabledByPigui = false
    private var firewallPFToken: String?
    private var firewallPflogCreated = false
    private var firewallBlockLabels: [String] = []
    private var firewallAllowLabels: [String] = []
    private var firewallLastError: String?
    private var pfStatusCache: (checkedAt: Date, enabled: Bool, text: String)?
    private var anchorCache: [String: (checkedAt: Date, loaded: Bool)] = [:]
    private let helperCacheTTL: TimeInterval = 5
    private let auditMaxBytes: UInt64 = 10 * 1024 * 1024
    private var pflogProcess: Process?
    private var pflogPipe: Pipe?
    private var pflogLineBuffer = ""
    private var pflogBuffer: [[String: Any]] = []
    private var pflogReaderActive = false
    private let pflogLock = NSLock()
    private let pflogBufferLimit = 1000

    init(isDevelopment: Bool) {
        self.isDevelopment = isDevelopment
        self.stateRoot = envValue("PIGUI_HELPER_STATE_ROOT")
            ?? "/Library/Application Support/PIGUI"
        self.auditPath = envValue("PIGUI_HELPER_AUDIT")
            ?? "/Library/Logs/PIGUI/audit.log"
        self.auditDir = URL(fileURLWithPath: self.auditPath)
            .deletingLastPathComponent().path
        self.devSnortBinary = envValue("PIGUI_DEV_SNORT_BIN")
        self.devSnortConfig = envValue("PIGUI_DEV_SNORT_CONFIG")
        self.devLogDir = envValue("PIGUI_DEV_SNORT_LOG_DIR")
        super.init()
        restoreCaptureState()
        restoreFirewallState()
    }

    func request(_ payload: String, withReply reply: @escaping (String) -> Void) {
        queue.sync {
            let response = self.handle(payload)
            reply(response)
        }
    }

    private func handle(_ payload: String) -> String {
        guard payload.utf8.count <= 512 * 1024 else {
            return encode(["ok": false, "error": "request too large"])
        }
        guard let data = payload.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let request = object as? [String: Any],
              let method = request["method"] as? String
        else {
            return encode(["ok": false, "error": "invalid request"])
        }

        let params = request["params"] as? [String: Any] ?? [:]
        let result: [String: Any]
        do {
            switch method {
            case "version":
                result = ok(data: ["version": helperVersion])
            case "status":
                result = try status()
            case "enable_capture":
                result = try enableCapture(params: params)
            case "disable_capture":
                result = try disableCapture()
            case "flush_firewall":
                result = try flushFirewall()
            case "apply_block":
                result = try applyBlock(params: params)
            case "firewall_status":
                result = try firewallStatus()
            case "firewall_apply":
                result = try firewallApply(params: params)
            case "firewall_flush":
                result = try firewallFlush(params: params)
            case "firewall_block":
                result = try firewallBlock(params: params)
            case "firewall_unblock":
                result = try firewallUnblock(params: params)
            case "firewall_counters":
                result = try firewallCounters()
            case "firewall_events":
                result = try firewallEvents(params: params)
            default:
                result = encode(ok: false, error: "unknown method: \(method)")
            }
        } catch {
            let message = "\(error)"
            debugLog("method \(method) failed: \(message)")
            if method.hasPrefix("firewall_") {
                firewallLastError = message
                persistFirewallState()
            }
            result = encode(ok: false, error: message)
        }

        audit(method: method, params: redact(params: params), result: result)
        return encode(result)
    }

    private func status() throws -> [String: Any] {
        let running = snortProcess?.isRunning == true || (snortPid.map(processAlive) ?? false)
        var data: [String: Any] = [
            "version": helperVersion,
            "uid": geteuid(),
            "capture_running": running,
            "state_root": stateRoot,
            "audit_log": auditPath,
            "firewall_mode": "pf",
            "firewall_generation": firewallGeneration,
            "pf_enabled_by_pigui": firewallPFEnabledByPigui,
            "development": isDevelopment,
        ]
        if let snortPid {
            data["snort_pid"] = snortPid
        }
        if let captureInterface {
            data["interface"] = captureInterface
        }
        if let captureLogDir {
            data["log_dir"] = captureLogDir
        }
        if let captureStartedAt {
            data["started_at"] = captureStartedAt
        }
        return ok(data: data)
    }

    private func enableCapture(params: [String: Any]) throws -> [String: Any] {
        guard geteuid() == 0 else {
            throw HelperError.message("capture requires root")
        }
        guard snortProcess?.isRunning != true, !(snortPid.map(processAlive) ?? false) else {
            throw HelperError.message("capture is already running")
        }
        guard let interface = params["interface"] as? String,
              validateInterface(interface)
        else {
            throw HelperError.message("invalid or unknown interface")
        }
        guard let console = consoleUser() else {
            throw HelperError.message("no console user is logged in")
        }

        let snort: URL
        let config: URL
        let currentDirectory: URL
        let payloadPath: String
        if isDevelopment, let devSnortBinary, let devSnortConfig {
            snort = URL(fileURLWithPath: devSnortBinary)
            config = URL(fileURLWithPath: devSnortConfig)
            currentDirectory = config.deletingLastPathComponent()
            payloadPath = stateRoot
        } else {
            let payload = try stagePayload()
            snort = payload.appendingPathComponent("bin/snort")
            config = payload.appendingPathComponent("etc/snort.lua")
            currentDirectory = payload.appendingPathComponent("etc")
            payloadPath = payload.path
        }
        guard fileManager.isExecutableFile(atPath: snort.path) else {
            throw HelperError.message("Snort binary is missing or not executable")
        }
        guard fileManager.fileExists(atPath: config.path) else {
            throw HelperError.message("Snort config is missing")
        }

        let logDir = try prepareLogDirectory(
            for: console,
            override: isDevelopment ? devLogDir : nil
        )
        let logPath = logDir.appendingPathComponent("snort.log")
        if !fileManager.fileExists(atPath: logPath.path) {
            fileManager.createFile(atPath: logPath.path, contents: nil)
        }
        try setOwner(path: logPath.path, uid: console.uid, gid: console.gid, mode: 0o600)
        guard let log = FileHandle(forWritingAtPath: logPath.path) else {
            throw HelperError.message("could not open Snort log")
        }
        log.seekToEndOfFile()

        let process = Process()
        process.executableURL = snort
        process.currentDirectoryURL = currentDirectory
        process.arguments = [
            "-c", config.path,
            "-i", interface,
            "-l", logDir.path,
            "--create-pidfile", "snort.pid",
            "-q",
            "-u", console.name,
            "-g", console.group,
        ]
        if isDevelopment {
            var environment = ProcessInfo.processInfo.environment
            environment["HOME"] = console.home
            environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
            environment["TMPDIR"] = NSTemporaryDirectory()
            process.environment = environment
        } else {
            process.environment = [
                "HOME": console.home,
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "TMPDIR": NSTemporaryDirectory(),
            ]
        }
        process.standardOutput = log
        process.standardError = log

        try process.run()
        snortProcess = process
        snortLog = log
        snortPid = process.processIdentifier
        captureInterface = interface
        captureLogDir = logDir.path
        captureStartedAt = Int(Date().timeIntervalSince1970)

        let pidfile = logDir.appendingPathComponent("snort.pid")
        for _ in 0..<50 {
            if fileManager.fileExists(atPath: pidfile.path) {
                try? setOwner(path: pidfile.path, uid: console.uid, gid: console.gid, mode: 0o644)
                break
            }
            usleep(100_000)
        }

        if !process.isRunning {
            process.waitUntilExit()
            snortProcess = nil
            try? log.close()
            snortLog = nil
            snortPid = nil
            captureInterface = nil
            captureLogDir = nil
            captureStartedAt = nil
            throw HelperError.message("Snort exited during startup; see \(logDir.path)/snort.log")
        }

        persistCaptureState()
        debugLog("capture started on \(interface) pid \(process.processIdentifier)")
        return ok(data: [
            "running": true,
            "pid": process.processIdentifier,
            "interface": interface,
            "user": console.name,
            "log_dir": logDir.path,
            "payload": payloadPath,
        ])
    }

    private func disableCapture() throws -> [String: Any] {
        if let process = snortProcess {
            process.terminate()
            let deadline = Date().addingTimeInterval(5)
            while process.isRunning && Date() < deadline {
                usleep(100_000)
            }
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            process.waitUntilExit()
        } else if let snortPid, processAlive(snortPid) {
            kill(snortPid, SIGTERM)
            let deadline = Date().addingTimeInterval(5)
            while processAlive(snortPid) && Date() < deadline {
                usleep(100_000)
            }
            if processAlive(snortPid) {
                kill(snortPid, SIGKILL)
            }
        }

        snortProcess = nil
        try? snortLog?.close()
        snortLog = nil
        snortPid = nil
        captureInterface = nil
        captureLogDir = nil
        captureStartedAt = nil
        clearCaptureState()
        debugLog("capture stopped")
        return ok(data: ["running": false])
    }

    private func flushFirewall() throws -> [String: Any] {
        try firewallFlush(params: ["disable_pf": false])
    }

    private func applyBlock(params: [String: Any]) throws -> [String: Any] {
        var request = params
        if request["address"] == nil {
            request["address"] = request["ip"]
        }
        return try firewallBlock(params: request)
    }

    private func firewallStatus() throws -> [String: Any] {
        ok(data: try firewallStatusData())
    }

    private func firewallStatusData() throws -> [String: Any] {
        guard geteuid() == 0 else {
            throw HelperError.message("firewall inspection requires root")
        }
        let pf = try pfStatus()
        var data: [String: Any] = [
            "pf_enabled": pf.enabled,
            "block_anchor": blockAnchor,
            "allow_anchor": allowAnchor,
            "block_anchor_loaded": anchorHasRules(blockAnchor),
            "allow_anchor_loaded": anchorHasRules(allowAnchor),
            "generation": firewallGeneration,
            "pf_enabled_by_pigui": firewallPFEnabledByPigui,
            "pflog_interface": pflogInterface,
            "pflog_ready": pflogReady(),
            "pflog_reader_running": pflogProcess?.isRunning == true,
            "pflog_created_by_pigui": firewallPflogCreated,
            "block_rule_count": firewallBlockLabels.count,
            "allow_rule_count": firewallAllowLabels.count,
        ]
        if let firewallAppliedAt {
            data["applied_at"] = firewallAppliedAt
        }
        if let firewallLastError {
            data["last_error"] = firewallLastError
        }
        return data
    }

    private func firewallApply(params: [String: Any]) throws -> [String: Any] {
        guard geteuid() == 0 else {
            throw HelperError.message("firewall changes require root")
        }
        guard let blockRules = params["block_rules"] as? String,
              let allowRules = params["allow_rules"] as? String
        else {
            throw HelperError.message("block_rules and allow_rules are required")
        }
        let generation = params["generation"] as? Int ?? 0
        let enablePF = params["enable_pf"] as? Bool ?? true

        try validateFirewallRules(
            blockRules,
            name: "block",
            allowPass: false,
            allowTables: true
        )
        try validateFirewallRules(
            allowRules,
            name: "allow",
            allowPass: true,
            allowTables: false
        )
        _ = try ensurePFEnabled(enablePF)
        try ensurePflogInterface()

        let blockFile = try writeRulesFile(blockRules, name: "block")
        let allowFile = try writeRulesFile(allowRules, name: "allow")
        defer {
            try? fileManager.removeItem(at: blockFile)
            try? fileManager.removeItem(at: allowFile)
        }

        try applyAnchor(blockAnchor, file: blockFile)
        try applyAnchor(allowAnchor, file: allowFile)

        pflogLock.lock()
        firewallBlockLabels = ruleLabels(from: blockRules)
        firewallAllowLabels = ruleLabels(from: allowRules)
        pflogLock.unlock()
        firewallGeneration = generation
        firewallAppliedAt = Int(Date().timeIntervalSince1970)
        firewallLastError = nil
        persistFirewallState()
        return ok(data: try firewallStatusData())
    }

    private func firewallFlush(params: [String: Any]) throws -> [String: Any] {
        guard geteuid() == 0 else {
            throw HelperError.message("firewall changes require root")
        }
        let disablePF = params["disable_pf"] as? Bool ?? false

        flushAnchor(blockAnchor)
        flushAnchor(allowAnchor)
        flushDynamicTables()
        stopPflogReader()
        if firewallPflogCreated {
            _ = try? runCommand(ifconfigPath, [pflogInterface, "destroy"])
            firewallPflogCreated = false
        }

        firewallLastError = nil
        if disablePF {
            if let token = firewallPFToken {
                let result = try runCommand(pfctlPath, ["-X", token])
                if result.status != 0 {
                    throw HelperError.message(
                        "could not release PF reference: \(result.combined.trimmingCharacters(in: .whitespacesAndNewlines))"
                    )
                }
                firewallPFToken = nil
            } else if firewallPFEnabledByPigui {
                firewallLastError = "PF release token is missing"
            }
            firewallPFEnabledByPigui = false
            pfStatusCache = nil
        }

        firewallGeneration = 0
        firewallAppliedAt = Int(Date().timeIntervalSince1970)
        pflogLock.lock()
        firewallBlockLabels = []
        firewallAllowLabels = []
        pflogLock.unlock()
        persistFirewallState()
        return ok(data: try firewallStatusData())
    }

    private func firewallBlock(params: [String: Any]) throws -> [String: Any] {
        guard geteuid() == 0 else {
            throw HelperError.message("firewall changes require root")
        }
        guard let address = (params["address"] as? String) ?? (params["ip"] as? String),
              validateAddress(address)
        else {
            throw HelperError.message("invalid IP or CIDR")
        }
        guard let direction = normalizedDirection(params["direction"] as? String) else {
            throw HelperError.message("invalid block direction")
        }
        let tables = tablesFor(address: address, direction: direction)
        guard !tables.isEmpty else {
            throw HelperError.message("invalid IP or CIDR")
        }
        for table in tables {
            let result = try runCommand(
                pfctlPath,
                ["-a", blockAnchor, "-t", table, "-T", "add", address]
            )
            if result.status != 0 {
                throw HelperError.message(
                    "pfctl table add failed for \(table): \(result.combined.trimmingCharacters(in: .whitespacesAndNewlines))"
                )
            }
        }
        return ok(data: [
            "address": address,
            "direction": direction,
            "tables": tables,
            "ttl_secs": params["ttl_secs"] as? Int ?? 0,
            "pf_enabled": try pfStatus().enabled,
        ])
    }

    private func firewallUnblock(params: [String: Any]) throws -> [String: Any] {
        guard geteuid() == 0 else {
            throw HelperError.message("firewall changes require root")
        }
        guard let address = (params["address"] as? String) ?? (params["ip"] as? String),
              validateAddress(address)
        else {
            throw HelperError.message("invalid IP or CIDR")
        }
        guard let direction = normalizedDirection(params["direction"] as? String) else {
            throw HelperError.message("invalid block direction")
        }
        let tables = tablesFor(address: address, direction: direction)
        for table in tables {
            _ = try? runCommand(
                pfctlPath,
                ["-a", blockAnchor, "-t", table, "-T", "delete", address]
            )
        }
        return ok(data: [
            "address": address,
            "direction": direction,
            "tables": tables,
        ])
    }

    private func firewallCounters() throws -> [String: Any] {
        guard geteuid() == 0 else {
            throw HelperError.message("firewall inspection requires root")
        }
        return ok(data: [
            "block": try countersForAnchor(blockAnchor),
            "allow": try countersForAnchor(allowAnchor),
        ])
    }

    private func firewallEvents(params: [String: Any]) throws -> [String: Any] {
        guard geteuid() == 0 else {
            throw HelperError.message("firewall inspection requires root")
        }
        let requested = params["limit"] as? Int ?? 100
        let limit = max(1, min(requested, 500))
        let clear = params["clear"] as? Bool ?? true
        try ensurePflogInterface()

        pflogLock.lock()
        let count = min(limit, pflogBuffer.count)
        let events = Array(pflogBuffer.prefix(count))
        if clear {
            pflogBuffer.removeFirst(count)
        }
        let readerRunning = pflogProcess?.isRunning == true
        pflogLock.unlock()

        return ok(data: [
            "events": events,
            "pflog_interface": pflogInterface,
            "pflog_reader_running": readerRunning,
        ])
    }

    private func runCommand(
        _ executable: String,
        _ arguments: [String],
        stdin: String? = nil,
        timeout: TimeInterval? = nil
    ) throws -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        var inputPipe: Pipe?
        if stdin != nil {
            let pipe = Pipe()
            process.standardInput = pipe
            inputPipe = pipe
        }
        try process.run()
        if let stdin, let inputPipe {
            inputPipe.fileHandleForWriting.write(Data(stdin.utf8))
            try? inputPipe.fileHandleForWriting.close()
        }
        if let timeout {
            let deadline = Date().addingTimeInterval(timeout)
            while process.isRunning && Date() < deadline {
                usleep(20_000)
            }
            if process.isRunning {
                process.terminate()
                usleep(100_000)
                if process.isRunning {
                    kill(process.processIdentifier, SIGKILL)
                }
            }
        }
        process.waitUntilExit()
        let outData = stdout.fileHandleForReading.readDataToEndOfFile()
        let errData = stderr.fileHandleForReading.readDataToEndOfFile()
        return CommandResult(
            status: process.terminationStatus,
            stdout: String(data: outData, encoding: .utf8) ?? "",
            stderr: String(data: errData, encoding: .utf8) ?? ""
        )
    }

    private func commandStatus(_ executable: String, _ arguments: [String]) -> Int32 {
        guard let result = try? runCommand(executable, arguments) else {
            return -1
        }
        return result.status
    }

    private func writeRulesFile(_ text: String, name: String) throws -> URL {
        let directory = URL(fileURLWithPath: stateRoot).appendingPathComponent("firewall")
        do {
            try fileManager.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw HelperError.message("could not create firewall directory: \(error)")
        }
        let url = directory.appendingPathComponent("\(name)-\(UUID().uuidString).pf")
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
        } catch {
            throw HelperError.message("could not write firewall rules: \(error)")
        }
        _ = chmod(url.path, 0o600)
        return url
    }

    private func validateFirewallRules(
        _ text: String,
        name: String,
        allowPass: Bool,
        allowTables: Bool
    ) throws {
        guard !text.isEmpty, text.utf8.count <= maxFirewallRulesBytes else {
            throw HelperError.message("\(name) rules are empty or too large")
        }
        guard text.contains("# PIGUI managed") else {
            throw HelperError.message("\(name) rules are missing the PIGUI header")
        }
        let lower = text.lowercased()
        if lower.contains("include ") || lower.contains("load anchor") || text.contains("\0") {
            throw HelperError.message("\(name) rules contain a forbidden directive")
        }
        try validatePiguiRuleLines(
            text,
            name: name,
            allowPass: allowPass,
            allowTables: allowTables
        )
        let file = try writeRulesFile(text, name: name)
        defer { try? fileManager.removeItem(at: file) }
        let result = try runCommand(pfctlPath, ["-nf", file.path])
        if result.status != 0 {
            throw HelperError.message(
                "pfctl rejected \(name) rules: \(result.combined.trimmingCharacters(in: .whitespacesAndNewlines))"
            )
        }
    }

    private func validatePiguiRuleLines(
        _ text: String,
        name: String,
        allowPass: Bool,
        allowTables: Bool
    ) throws {
        let allowedTables: Set<String> = [
            "table <pigui_block4_in> persist",
            "table <pigui_block4_out> persist",
            "table <pigui_block6_in> persist",
            "table <pigui_block6_out> persist",
        ]
        let forbidden = [
            "anchor ",
            "binat",
            "dummynet",
            "dup-to",
            "include ",
            "load ",
            "nat ",
            "queue ",
            "rdr ",
            "reply-to",
            "route ",
            "scrub ",
        ]
        for rawLine in text.split(separator: "\n") {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") {
                continue
            }
            if allowedTables.contains(line) {
                guard allowTables else {
                    throw HelperError.message("\(name) rules must not declare PF tables")
                }
                continue
            }
            let isPass = line.hasPrefix("pass ")
            let isBlock = line.hasPrefix("block drop ") || line.hasPrefix("block return ")
            guard isPass || isBlock else {
                throw HelperError.message("\(name) rules contain an unsupported directive: \(line)")
            }
            guard allowPass == isPass else {
                throw HelperError.message("\(name) rules contain a rule in the wrong anchor: \(line)")
            }
            guard line.contains("label \"pigui-") else {
                throw HelperError.message("\(name) rules must use a PIGUI label: \(line)")
            }
            let lower = line.lowercased()
            if let match = forbidden.first(where: { lower.contains($0) }) {
                throw HelperError.message("\(name) rules contain a forbidden keyword \(match): \(line)")
            }
        }
    }

    private func pfStatus() throws -> (enabled: Bool, text: String) {
        if let cached = pfStatusCache,
           Date().timeIntervalSince(cached.checkedAt) < helperCacheTTL {
            return (cached.enabled, cached.text)
        }
        let result = try runCommand(pfctlPath, ["-s", "info"])
        let text = result.combined
        let enabled = text.contains("Status: Enabled")
        pfStatusCache = (Date(), enabled, text)
        return (enabled, text)
    }

    private func parsePFToken(_ text: String) -> String? {
        for line in text.split(separator: "\n") {
            let trimmed = String(line).trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("Token") else {
                continue
            }
            guard let colon = trimmed.firstIndex(of: ":") else {
                continue
            }
            let token = String(trimmed[trimmed.index(after: colon)...])
                .trimmingCharacters(in: .whitespaces)
            return token.isEmpty ? nil : token
        }
        return nil
    }

    private func ensurePFEnabled(_ enable: Bool) throws -> Bool {
        let current = try pfStatus()
        if current.enabled {
            return true
        }
        firewallPFToken = nil
        firewallPFEnabledByPigui = false
        guard enable else {
            return false
        }
        let result = try runCommand(pfctlPath, ["-E"])
        if result.status != 0 {
            throw HelperError.message(
                "could not enable PF: \(result.combined.trimmingCharacters(in: .whitespacesAndNewlines))"
            )
        }
        guard let token = parsePFToken(result.combined) else {
            _ = try? runCommand(pfctlPath, ["-d"])
            throw HelperError.message("PF enabled but no release token was returned")
        }
        firewallPFToken = token
        firewallPFEnabledByPigui = true
        pfStatusCache = nil
        return true
    }

    private func pflogReady() -> Bool {
        commandStatus(ifconfigPath, [pflogInterface]) == 0
    }

    private func ensurePflogInterface() throws {
        if !pflogReady() {
            let result = try runCommand(ifconfigPath, [pflogInterface, "create"])
            if result.status != 0 {
                throw HelperError.message(
                    "could not create \(pflogInterface): \(result.combined.trimmingCharacters(in: .whitespacesAndNewlines))"
                )
            }
            firewallPflogCreated = true
            persistFirewallState()
        }
        startPflogReader()
    }

    private func startPflogReader() {
        if let process = pflogProcess, process.isRunning {
            return
        }
        pflogPipe?.fileHandleForReading.readabilityHandler = nil
        pflogLock.lock()
        pflogReaderActive = false
        pflogLock.unlock()
        pflogProcess = nil
        pflogPipe = nil

        let process = Process()
        process.executableURL = URL(fileURLWithPath: tcpdumpPath)
        process.arguments = ["-n", "-e", "-tt", "-l", "-i", pflogInterface]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            debugLog("could not start pflog reader: \(error)")
            return
        }

        pflogProcess = process
        pflogPipe = pipe
        pflogLock.lock()
        pflogReaderActive = true
        pflogLock.unlock()
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
            self?.appendPflogData(data)
        }
    }

    private func stopPflogReader() {
        pflogPipe?.fileHandleForReading.readabilityHandler = nil
        pflogPipe = nil
        if let process = pflogProcess {
            if process.isRunning {
                process.terminate()
                let deadline = Date().addingTimeInterval(1)
                while process.isRunning && Date() < deadline {
                    usleep(20_000)
                }
                if process.isRunning {
                    kill(process.processIdentifier, SIGKILL)
                }
            }
            process.waitUntilExit()
        }
        pflogProcess = nil
        pflogLock.lock()
        pflogReaderActive = false
        pflogLineBuffer = ""
        pflogBuffer.removeAll()
        pflogLock.unlock()
    }

    private func appendPflogData(_ data: Data) {
        guard let text = String(data: data, encoding: .utf8) else {
            return
        }
        pflogLock.lock()
        guard pflogReaderActive else {
            pflogLock.unlock()
            return
        }
        pflogLineBuffer.append(text)
        while let newline = pflogLineBuffer.firstIndex(of: "\n") {
            let line = String(pflogLineBuffer[..<newline])
            pflogLineBuffer.removeSubrange(pflogLineBuffer.startIndex...newline)
            if let event = parsePflogLine(
                line,
                blockLabels: firewallBlockLabels,
                allowLabels: firewallAllowLabels
            ) {
                pflogBuffer.append(event)
                if pflogBuffer.count > pflogBufferLimit {
                    pflogBuffer.removeFirst(pflogBuffer.count - pflogBufferLimit)
                }
            }
        }
        pflogLock.unlock()
    }

    private func applyAnchor(_ anchor: String, file: URL) throws {
        let result = try runCommand(pfctlPath, ["-a", anchor, "-f", file.path])
        if result.status != 0 {
            throw HelperError.message(
                "pfctl apply failed for \(anchor): \(result.combined.trimmingCharacters(in: .whitespacesAndNewlines))"
            )
        }
        anchorCache.removeValue(forKey: anchor)
    }

    private func flushAnchor(_ anchor: String) {
        _ = try? runCommand(pfctlPath, ["-a", anchor, "-F", "all"])
        _ = try? runCommand(pfctlPath, ["-a", anchor, "-f", "/dev/null"])
        anchorCache.removeValue(forKey: anchor)
    }

    private func flushDynamicTables() {
        for table in dynamicBlockTables {
            _ = try? runCommand(
                pfctlPath,
                ["-a", blockAnchor, "-t", table, "-T", "flush"]
            )
        }
    }

    private func anchorHasRules(_ anchor: String) -> Bool {
        if let cached = anchorCache[anchor],
           Date().timeIntervalSince(cached.checkedAt) < helperCacheTTL {
            return cached.loaded
        }
        guard let result = try? runCommand(pfctlPath, ["-a", anchor, "-sr"]) else {
            return false
        }
        let loaded = result.status == 0
            && !result.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        anchorCache[anchor] = (Date(), loaded)
        return loaded
    }

    private func ruleLabels(from text: String) -> [String] {
        var labels: [String] = []
        for line in text.split(separator: "\n") {
            let trimmed = String(line).trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix("table ") {
                continue
            }
            if let label = extractLabel(trimmed) {
                labels.append(label)
            }
        }
        return labels
    }

    private func extractLabel(_ line: String) -> String? {
        guard let range = line.range(of: "label \"") else {
            return nil
        }
        let rest = line[range.upperBound...]
        guard let end = rest.firstIndex(of: "\"") else {
            return nil
        }
        return String(rest[..<end])
    }

    private func countersForAnchor(_ anchor: String) throws -> [[String: Any]] {
        let result = try runCommand(pfctlPath, ["-a", anchor, "-vs", "labels"])
        guard result.status == 0 else {
            return []
        }
        var counters: [[String: Any]] = []
        for line in result.combined.split(separator: "\n") {
            let parts = line
                .split(whereSeparator: { $0 == " " || $0 == "\t" })
                .map(String.init)
            guard parts.count >= 8, parts[0].hasPrefix("pigui-") else {
                continue
            }
            counters.append([
                "anchor": anchor,
                "label": parts[0],
                "evaluations": Int(parts[1]) ?? 0,
                "packets": Int(parts[2]) ?? 0,
                "bytes": Int(parts[3]) ?? 0,
                "packets_in": Int(parts[4]) ?? 0,
                "bytes_in": Int(parts[5]) ?? 0,
                "packets_out": Int(parts[6]) ?? 0,
                "bytes_out": Int(parts[7]) ?? 0,
            ])
        }
        return counters
    }

    private func parsePflogLine(
        _ raw: String,
        blockLabels: [String],
        allowLabels: [String]
    ) -> [String: Any]? {
        guard let matchRange = raw.range(of: "(match):") else {
            return nil
        }
        let header = String(raw[..<matchRange.lowerBound])
        let detail = String(raw[matchRange.upperBound...])
            .trimmingCharacters(in: .whitespaces)

        var timestamp = 0
        if let first = header.split(separator: " ", maxSplits: 1).first {
            timestamp = Int(Double(String(first)) ?? 0)
        }

        let anchors = [
            (blockAnchorSuffix, blockLabels),
            (allowAnchorSuffix, allowLabels),
        ]
        var anchorName = ""
        var ruleNumber = -1
        var ruleLabel: String?
        for (suffix, labels) in anchors {
            guard let range = header.range(of: suffix) else {
                continue
            }
            anchorName = suffix
            let after = String(header[range.upperBound...])
            let cleaned = after.drop(while: { $0 == "." || $0 == "/" || $0 == " " })
            let numberText = cleaned.prefix(while: { $0.isNumber })
            if let number = Int(numberText) {
                ruleNumber = number
                if number >= 0, number < labels.count {
                    ruleLabel = labels[number]
                }
            }
            break
        }
        if anchorName.isEmpty {
            return nil
        }

        let actionParts = detail
            .split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            .map(String.init)
        let action = actionParts.first ?? ""
        let direction = actionParts.count > 1 ? actionParts[1] : ""

        var interface: String?
        var src = ""
        var dst = ""
        var srcPort: Int?
        var dstPort: Int?
        var proto = ""

        if let onRange = detail.range(of: " on "),
           let arrow = detail.range(of: " > ", range: onRange.upperBound..<detail.endIndex)
        {
            let afterOn = detail[onRange.upperBound...]
            if let colon = afterOn.firstIndex(of: ":") {
                interface = String(afterOn[..<colon])
                    .trimmingCharacters(in: .whitespaces)
                let endpointStart = afterOn.index(after: colon)
                let left = String(detail[endpointStart..<arrow.lowerBound])
                    .trimmingCharacters(in: .whitespaces)
                (src, srcPort) = parseEndpoint(left)
                let right = String(detail[arrow.upperBound...])
                if let protoSplit = right.range(of: ": ") {
                    let endpoint = String(right[..<protoSplit.lowerBound])
                        .trimmingCharacters(in: .whitespaces)
                    (dst, dstPort) = parseEndpoint(endpoint)
                    let protoText = String(right[protoSplit.upperBound...])
                        .split(separator: ",")
                        .first
                        .map(String.init) ?? ""
                    proto = protoText.trimmingCharacters(in: .whitespaces)
                } else {
                    (dst, dstPort) = parseEndpoint(right)
                }
            }
        }

        var event: [String: Any] = [
            "ts": timestamp,
            "anchor": "com.apple/\(anchorName)",
            "rule_number": ruleNumber,
            "action": action,
            "direction": direction,
            "raw": raw,
        ]
        if let ruleLabel {
            event["rule_label"] = ruleLabel
        }
        if let interface, !interface.isEmpty {
            event["interface"] = interface
        }
        if !src.isEmpty {
            event["src"] = src
        }
        if !dst.isEmpty {
            event["dst"] = dst
        }
        if let srcPort {
            event["src_port"] = srcPort
        }
        if let dstPort {
            event["dst_port"] = dstPort
        }
        if !proto.isEmpty {
            event["proto"] = proto
        }
        return event
    }

    private func parseEndpoint(_ value: String) -> (String, Int?) {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        guard let dot = trimmed.lastIndex(of: ".") else {
            return (trimmed, nil)
        }
        let portText = String(trimmed[trimmed.index(after: dot)...])
        guard let port = Int(portText) else {
            return (trimmed, nil)
        }
        return (String(trimmed[..<dot]), port)
    }

    private func addressFamily(_ value: String) -> Int32? {
        let address = String(
            value.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)[0]
        )
        var v4 = in_addr()
        var v6 = in6_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            return AF_INET
        }
        if address.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            return AF_INET6
        }
        return nil
    }

    private func normalizedDirection(_ value: String?) -> String? {
        switch (value ?? "both").lowercased() {
        case "in", "inbound":
            return "in"
        case "out", "outbound":
            return "out"
        case "both":
            return "both"
        default:
            return nil
        }
    }

    private func tablesFor(address: String, direction: String) -> [String] {
        guard let family = addressFamily(address) else {
            return []
        }
        let prefix = family == AF_INET ? "pigui_block4" : "pigui_block6"
        switch direction {
        case "in":
            return ["\(prefix)_in"]
        case "out":
            return ["\(prefix)_out"]
        default:
            return ["\(prefix)_in", "\(prefix)_out"]
        }
    }

    private func firewallStatePath() -> URL {
        URL(fileURLWithPath: stateRoot).appendingPathComponent("firewall.json")
    }

    private func persistFirewallState() {
        var record: [String: Any] = [
            "generation": firewallGeneration,
            "pf_enabled_by_pigui": firewallPFEnabledByPigui,
            "pflog_created": firewallPflogCreated,
            "block_labels": firewallBlockLabels,
            "allow_labels": firewallAllowLabels,
        ]
        if let firewallAppliedAt {
            record["applied_at"] = firewallAppliedAt
        }
        if let firewallPFToken {
            record["pf_token"] = firewallPFToken
        }
        if let firewallLastError {
            record["last_error"] = firewallLastError
        }
        guard let data = try? JSONSerialization.data(withJSONObject: record) else {
            return
        }
        do {
            try fileManager.createDirectory(
                atPath: stateRoot,
                withIntermediateDirectories: true
            )
            try data.write(to: firewallStatePath())
        } catch {
            return
        }
        _ = chown(firewallStatePath().path, 0, 0)
        _ = chmod(firewallStatePath().path, 0o600)
    }

    private func restoreFirewallState() {
        let path = firewallStatePath()
        guard let data = try? Data(contentsOf: path),
              let raw = try? JSONSerialization.jsonObject(with: data),
              let object = raw as? [String: Any]
        else {
            return
        }
        firewallGeneration = object["generation"] as? Int ?? 0
        firewallPFEnabledByPigui = object["pf_enabled_by_pigui"] as? Bool ?? false
        firewallPflogCreated = object["pflog_created"] as? Bool ?? false
        firewallBlockLabels = object["block_labels"] as? [String] ?? []
        firewallAllowLabels = object["allow_labels"] as? [String] ?? []
        firewallAppliedAt = object["applied_at"] as? Int
        firewallPFToken = object["pf_token"] as? String
        firewallLastError = object["last_error"] as? String
    }

    private func stagePayload() throws -> URL {
        let app = try appBundle()
        try verifyAppBundle(app)
        let source = app.appendingPathComponent("Contents/Resources/snort")
        guard fileManager.fileExists(atPath: source.path) else {
            throw HelperError.message("bundled Snort resources are missing")
        }

        let payloadID = try readPayloadID(from: source)
        let destination = URL(fileURLWithPath: stateRoot)
            .appendingPathComponent("payload")
            .appendingPathComponent(payloadID)
        if fileManager.fileExists(atPath: destination.path) {
            return destination
        }

        let parent = destination.deletingLastPathComponent()
        try fileManager.createDirectory(at: parent, withIntermediateDirectories: true)
        let temp = parent.appendingPathComponent(".tmp-\(UUID().uuidString)")
        try fileManager.createDirectory(at: temp, withIntermediateDirectories: true)

        do {
            try fileManager.createDirectory(
                at: temp.appendingPathComponent("bin"),
                withIntermediateDirectories: true
            )
            try fileManager.copyItem(
                at: app.appendingPathComponent("Contents/MacOS/snort"),
                to: temp.appendingPathComponent("bin/snort")
            )
            try fileManager.copyItem(
                at: app.appendingPathComponent("Contents/Frameworks"),
                to: temp.appendingPathComponent("Frameworks")
            )
            for name in ["etc", "lua", "rules"] {
                let item = source.appendingPathComponent(name)
                if fileManager.fileExists(atPath: item.path) {
                    try fileManager.copyItem(
                        at: item,
                        to: temp.appendingPathComponent(name)
                    )
                }
            }
            try makeRootOwned(temp)
            try fileManager.moveItem(at: temp, to: destination)
        } catch {
            try? fileManager.removeItem(at: temp)
            throw error
        }

        return destination
    }

    private func verifyAppBundle(_ app: URL) throws {
        if isDevelopment {
            return
        }
        var code: SecStaticCode?
        let status = SecStaticCodeCreateWithPath(app as CFURL, [], &code)
        guard status == errSecSuccess, let code else {
            throw HelperError.message("could not read app code signature")
        }
        let requirement = try appRequirement()
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures)
        guard SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess else {
            throw HelperError.message("app bundle signature does not match the helper policy")
        }
    }

    private func appRequirement() throws -> SecRequirement? {
        let text = infoString("PIGUIAppRequirement") ?? "identifier \"com.pigui.app\""
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(text as CFString, [], &requirement)
        guard status == errSecSuccess else {
            throw HelperError.message("invalid PIGUIAppRequirement")
        }
        return requirement
    }

    private func readPayloadID(from source: URL) throws -> String {
        let marker = source.appendingPathComponent("payload-id.txt")
        let raw = (try? String(contentsOf: marker, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-"))
        guard !raw.isEmpty,
              raw.unicodeScalars.allSatisfy({ allowed.contains($0) })
        else {
            throw HelperError.message("missing or invalid Snort payload id")
        }
        return raw
    }

    private func appBundle() throws -> URL {
        var url = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        while url.path != "/" {
            if url.pathExtension == "app" {
                return url
            }
            url.deleteLastPathComponent()
        }
        if Bundle.main.bundleURL.pathExtension == "app" {
            return Bundle.main.bundleURL
        }
        throw HelperError.message("helper is not running from an app bundle")
    }

    private func consoleUser() -> ConsoleUser? {
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard let name = SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) as String?,
              !name.isEmpty,
              name != "loginwindow",
              uid != 0
        else {
            return nil
        }
        guard let password = name.withCString({ getpwnam($0) }) else {
            return nil
        }
        let pw = password.pointee
        guard let home = String(validatingUTF8: pw.pw_dir) else {
            return nil
        }
        let group = getgrgid(pw.pw_gid)
            .flatMap { String(validatingUTF8: $0.pointee.gr_name) } ?? "staff"
        return ConsoleUser(
            name: name,
            uid: pw.pw_uid,
            gid: pw.pw_gid,
            home: home,
            group: group
        )
    }

    private func debugLog(_ message: String) {
        guard isDevelopment else {
            return
        }
        FileHandle.standardOutput.write(Data(("[dev-helper] " + message + "\n").utf8))
    }

    private func processAlive(_ pid: pid_t) -> Bool {
        kill(pid, 0) == 0 || errno == EPERM
    }

    private func captureStatePath() -> URL {
        URL(fileURLWithPath: stateRoot).appendingPathComponent("capture.json")
    }

    private func persistCaptureState() {
        guard let snortPid, let captureInterface, let captureLogDir, let captureStartedAt else {
            return
        }
        let record: [String: Any] = [
            "interface": captureInterface,
            "pid": snortPid,
            "log_dir": captureLogDir,
            "started_at": captureStartedAt,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: record) else {
            return
        }
        let path = captureStatePath()
        try? fileManager.createDirectory(
            atPath: URL(fileURLWithPath: stateRoot).path,
            withIntermediateDirectories: true
        )
        try? data.write(to: path)
        _ = chown(path.path, 0, 0)
        _ = chmod(path.path, 0o600)
    }

    private func clearCaptureState() {
        try? fileManager.removeItem(at: captureStatePath())
    }

    private func restoreCaptureState() {
        let path = captureStatePath()
        guard let data = try? Data(contentsOf: path),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let interface = object["interface"] as? String,
              let pid = object["pid"] as? Int,
              let logDir = object["log_dir"] as? String,
              let startedAt = object["started_at"] as? Int
        else {
            return
        }
        let pidValue = pid_t(pid)
        guard processAlive(pidValue) else {
            clearCaptureState()
            return
        }
        snortPid = pidValue
        captureInterface = interface
        captureLogDir = logDir
        captureStartedAt = startedAt
        debugLog("restored capture on \(interface) pid \(pidValue)")
    }

    private func prepareLogDirectory(for user: ConsoleUser, override: String?) throws -> URL {
        let directory = override.map(URL.init(fileURLWithPath:))
            ?? URL(fileURLWithPath: user.home)
                .appendingPathComponent("Library/Application Support/PIGUI/snort")
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try setOwner(path: directory.path, uid: user.uid, gid: user.gid, mode: 0o700)
        if let entries = try? fileManager.contentsOfDirectory(atPath: directory.path) {
            for entry in entries {
                let path = directory.appendingPathComponent(entry).path
                try? setOwner(path: path, uid: user.uid, gid: user.gid, mode: 0o600)
            }
        }
        return directory
    }

    private func makeRootOwned(_ root: URL) throws {
        try setOwner(path: root.path, uid: 0, gid: 0, mode: 0o755)
        guard let enumerator = fileManager.enumerator(atPath: root.path) else {
            throw HelperError.message("could not enumerate staged payload")
        }
        for case let relative as String in enumerator {
            let path = root.appendingPathComponent(relative).path
            var isDirectory: ObjCBool = false
            fileManager.fileExists(atPath: path, isDirectory: &isDirectory)
            let mode: mode_t = isDirectory.boolValue ? 0o755 : 0o644
            try setOwner(path: path, uid: 0, gid: 0, mode: mode)
        }
        let snort = root.appendingPathComponent("bin/snort").path
        try setOwner(path: snort, uid: 0, gid: 0, mode: 0o555)
    }

    private func setOwner(path: String, uid: uid_t, gid: gid_t, mode: mode_t) throws {
        if chown(path, uid, gid) != 0 && errno != EPERM {
            throw HelperError.message("chown failed for \(path): \(String(cString: strerror(errno)))")
        }
        if chmod(path, mode) != 0 {
            throw HelperError.message("chmod failed for \(path): \(String(cString: strerror(errno)))")
        }
    }

    private func validateInterface(_ name: String) -> Bool {
        guard !name.isEmpty, name.utf8.count < IFNAMSIZ else {
            return false
        }
        return name.withCString { if_nametoindex($0) != 0 }
    }

    private func validateAddress(_ value: String) -> Bool {
        let parts = value.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let address = String(parts[0])
        var v4 = in_addr()
        var v6 = in6_addr()
        let family: Int32
        if address.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            family = AF_INET
        } else if address.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            family = AF_INET6
        } else {
            return false
        }
        guard parts.count == 2 else {
            return parts.count == 1
        }
        guard let prefix = Int(parts[1]) else {
            return false
        }
        return (family == AF_INET && (0...32).contains(prefix))
            || (family == AF_INET6 && (0...128).contains(prefix))
    }

    private func infoString(_ key: String) -> String? {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String else {
            return nil
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private func audit(method: String, params: [String: Any], result: [String: Any]) {
        let readOnlyMethods: Set<String> = [
            "version", "status", "firewall_status", "firewall_counters", "firewall_events",
        ]
        if readOnlyMethods.contains(method) {
            return
        }
        try? fileManager.createDirectory(
            atPath: auditDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
        _ = chown(auditDir, 0, 0)
        if let attributes = try? fileManager.attributesOfItem(atPath: auditPath),
           let size = attributes[.size] as? UInt64,
           size > auditMaxBytes {
            let rotated = auditPath + ".1"
            try? fileManager.removeItem(atPath: rotated)
            try? fileManager.moveItem(atPath: auditPath, toPath: rotated)
        }

        var auditResult = result
        if method == "firewall_events",
           let data = result["data"] as? [String: Any],
           let events = data["events"] as? [Any] {
            auditResult = [
                "ok": result["ok"] ?? false,
                "event_count": events.count,
            ]
        }

        let record: [String: Any] = [
            "ts": Int(Date().timeIntervalSince1970),
            "helper": helperVersion,
            "pid": getpid(),
            "method": method,
            "params": params,
            "result": auditResult,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: record),
              var line = String(data: data, encoding: .utf8)
        else {
            return
        }
        line.append("\n")

        let fd = open(auditPath, O_WRONLY | O_APPEND | O_CREAT, 0o600)
        guard fd >= 0 else {
            return
        }
        line.withCString { pointer in
            _ = write(fd, pointer, strlen(pointer))
        }
        close(fd)
        _ = chown(auditPath, 0, 0)
        _ = chmod(auditPath, 0o600)
    }

    private func redact(params: [String: Any]) -> [String: Any] {
        var redacted = params.filter { $0.key != "password" && $0.key != "token" }
        for key in ["block_rules", "allow_rules"] {
            if let value = redacted[key] as? String {
                redacted[key] = "<\(value.utf8.count) bytes>"
            }
        }
        return redacted
    }

    private func ok(data: [String: Any]) -> [String: Any] {
        ["ok": true, "data": data]
    }

    private func encode(ok: Bool, error: String) -> [String: Any] {
        ["ok": false, "error": error]
    }

    private func encode(_ object: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: object),
              let text = String(data: data, encoding: .utf8)
        else {
            return "{\"ok\":false,\"error\":\"could not encode response\"}"
        }
        return text
    }

    func shutdown() {
        queue.sync {
            self.stopPflogReader()
            _ = try? self.disableCapture()
        }
    }
}

private enum HelperError: Error, CustomStringConvertible {
    case message(String)

    var description: String {
        switch self {
        case .message(let text):
            return text
        }
    }
}

final class HelperListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let service: HelperService

    init(service: HelperService) {
        self.service = service
    }

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: PiguiHelperProtocol.self)
        connection.exportedObject = service
        connection.resume()
        return true
    }
}

@main
struct PiguiHelperMain {
    static func main() {
        if CommandLine.arguments.contains("--version") {
            print(helperVersion)
            exit(0)
        }

        let development = CommandLine.arguments.contains("--dev")
        if geteuid() != 0 && !development {
            FileHandle.standardError.write(Data("pigui-helper must run as root\n".utf8))
            exit(1)
        }

        let service = HelperService(isDevelopment: development)
        let delegate = HelperListenerDelegate(service: service)
        let serviceName = envValue("PIGUI_HELPER_SERVICE")
            ?? argumentValue("--service")
            ?? defaultServiceName
        let listener = NSXPCListener(machServiceName: serviceName)
        listener.delegate = delegate

        let requirement = Bundle.main.object(
            forInfoDictionaryKey: "PIGUIHelperClientRequirement"
        ) as? String
        let trimmed = requirement?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if !trimmed.isEmpty {
            listener.setConnectionCodeSigningRequirement(trimmed)
        }

        listener.activate()

        for signalNumber in [SIGTERM, SIGINT] {
            signal(signalNumber, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .main)
            source.setEventHandler {
                service.shutdown()
                exit(0)
            }
            source.resume()
            signalSources.append(source)
        }

        RunLoop.current.run()
    }

    private static var signalSources: [DispatchSourceSignal] = []
}
