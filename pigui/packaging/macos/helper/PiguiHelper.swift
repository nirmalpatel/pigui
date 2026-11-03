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
    }

    func request(_ payload: String, withReply reply: @escaping (String) -> Void) {
        queue.sync {
            let response = self.handle(payload)
            reply(response)
        }
    }

    private func handle(_ payload: String) -> String {
        guard payload.utf8.count <= 64 * 1024 else {
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
            default:
                result = encode(ok: false, error: "unknown method: \(method)")
            }
        } catch {
            debugLog("method \(method) failed: \(error)")
            result = encode(ok: false, error: "\(error)")
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
            "firewall_mode": "dry_run",
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
        ok(data: ["dry_run": true, "flushed": 0])
    }

    private func applyBlock(params: [String: Any]) throws -> [String: Any] {
        guard let address = params["ip"] as? String,
              validateAddress(address)
        else {
            throw HelperError.message("invalid IP or CIDR")
        }
        return ok(data: [
            "dry_run": true,
            "outcome": "would_block",
            "ip": address,
            "direction": params["direction"] as? String ?? "both",
            "ttl_secs": params["ttl_secs"] as? Int ?? 0,
        ])
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
        try? fileManager.createDirectory(
            atPath: auditDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
        _ = chown(auditDir, 0, 0)

        let record: [String: Any] = [
            "ts": Int(Date().timeIntervalSince1970),
            "helper": helperVersion,
            "pid": getpid(),
            "method": method,
            "params": params,
            "result": result,
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
        params.filter { $0.key != "password" && $0.key != "token" }
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
