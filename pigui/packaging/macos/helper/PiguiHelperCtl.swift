import Foundation

private let defaultHelperServiceName = "com.pigui.helper"

private func envValue(_ key: String) -> String? {
    guard let value = ProcessInfo.processInfo.environment[key] else {
        return nil
    }
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
}

@objc protocol PiguiHelperRemoteProtocol {
    func request(_ payload: String, withReply reply: @escaping (String) -> Void)
}

private func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

private func requestJSON(_ request: [String: Any]) -> String {
    guard let data = try? JSONSerialization.data(withJSONObject: request),
          let text = String(data: data, encoding: .utf8)
    else {
        fail("could not encode helper request")
    }
    return text
}

private func callHelper(_ request: [String: Any]) -> String {
    let helperServiceName = envValue("PIGUI_HELPER_SERVICE") ?? defaultHelperServiceName
    let connection = NSXPCConnection(
        machServiceName: helperServiceName,
        options: .privileged
    )
    connection.remoteObjectInterface = NSXPCInterface(with: PiguiHelperRemoteProtocol.self)
    if envValue("PIGUI_HELPER_DEV") != "1" {
        let configured = Bundle.main.object(forInfoDictionaryKey: "PIGUIHelperRequirement") as? String
        let requirement = configured?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        connection.setCodeSigningRequirement(
            requirement.isEmpty ? "identifier \"com.pigui.helper\"" : requirement
        )
    }
    connection.resume()
    defer { connection.invalidate() }

    let service = connection.remoteObjectProxyWithErrorHandler { error in
        fail("helper connection failed: \(error.localizedDescription)")
    } as? PiguiHelperRemoteProtocol

    guard let service else {
        fail("helper proxy is unavailable")
    }

    let semaphore = DispatchSemaphore(value: 0)
    var response = ""
    service.request(requestJSON(request)) { reply in
        response = reply
        semaphore.signal()
    }
    if semaphore.wait(timeout: .now() + 10) == .timedOut {
        fail("helper request timed out")
    }
    return response
}

private func readFile(_ path: String) -> String {
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
        fail("could not read \(path)")
    }
    return text
}

private func parseBool(_ value: String) -> Bool? {
    switch value.lowercased() {
    case "1", "true", "yes", "on":
        return true
    case "0", "false", "no", "off":
        return false
    default:
        return nil
    }
}

@main
struct PiguiHelperCtlMain {
    static func main() {
        var arguments = Array(CommandLine.arguments.dropFirst())
        let command = arguments.isEmpty ? "status" : arguments.removeFirst()

        if command == "request" {
            guard let raw = arguments.first,
                  let data = raw.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else {
                fail("usage: pigui-helperctl request '<json>'", code: 2)
            }
            let response = callHelper(object)
            print(response)
            if let responseData = response.data(using: .utf8),
               let result = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
               let ok = result["ok"] as? Bool,
               !ok {
                exit(1)
            }
            return
        }

        var params: [String: Any] = [:]
        switch command {
        case "status", "version", "disable-capture", "flush-firewall",
             "firewall-status", "firewall-counters":
            break
        case "enable-capture":
            guard let interface = arguments.first else {
                fail("usage: pigui-helperctl enable-capture <interface>", code: 2)
            }
            params["interface"] = interface
        case "apply-block", "firewall-block":
            guard let ip = arguments.first else {
                fail(
                    "usage: pigui-helperctl firewall-block <ip-or-cidr> [in|out|both] [ttl]",
                    code: 2
                )
            }
            params["address"] = ip
            if arguments.count > 1 {
                params["direction"] = arguments[1]
            }
            if arguments.count > 2, let ttl = Int(arguments[2]) {
                params["ttl_secs"] = ttl
            }
        case "firewall-unblock":
            guard let ip = arguments.first else {
                fail("usage: pigui-helperctl firewall-unblock <ip-or-cidr> [in|out|both]", code: 2)
            }
            params["address"] = ip
            if arguments.count > 1 {
                params["direction"] = arguments[1]
            }
        case "firewall-flush":
            if let value = arguments.first, let disable = parseBool(value) {
                params["disable_pf"] = disable
            }
        case "firewall-events":
            if let value = arguments.first, let limit = Int(value) {
                params["limit"] = limit
            }
        case "firewall-apply":
            guard arguments.count >= 2 else {
                fail(
                    "usage: pigui-helperctl firewall-apply <block-rules-file> <allow-rules-file> [generation] [enable-pf]",
                    code: 2
                )
            }
            params["block_rules"] = readFile(arguments[0])
            params["allow_rules"] = readFile(arguments[1])
            if arguments.count > 2, let generation = Int(arguments[2]) {
                params["generation"] = generation
            }
            if arguments.count > 3, let enable = parseBool(arguments[3]) {
                params["enable_pf"] = enable
            }
        default:
            fail(
                "usage: pigui-helperctl status|version|enable-capture <iface>|disable-capture|flush-firewall|apply-block <ip> [direction] [ttl]|firewall-status|firewall-counters|firewall-events [limit]|firewall-apply <block-file> <allow-file> [generation] [enable-pf]|firewall-block <ip> [direction] [ttl]|firewall-unblock <ip> [direction]|firewall-flush [disable-pf]",
                code: 2
            )
        }

        let method = command.replacingOccurrences(of: "-", with: "_")
        let response = callHelper(["method": method, "params": params])
        print(response)

        if let data = response.data(using: .utf8),
           let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let ok = object["ok"] as? Bool,
           !ok {
            exit(1)
        }
    }
}
