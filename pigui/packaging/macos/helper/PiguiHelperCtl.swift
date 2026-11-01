import Foundation

private let helperServiceName = "com.pigui.helper"

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
    let connection = NSXPCConnection(
        machServiceName: helperServiceName,
        options: .privileged
    )
    connection.remoteObjectInterface = NSXPCInterface(with: PiguiHelperRemoteProtocol.self)
    let configured = Bundle.main.object(forInfoDictionaryKey: "PIGUIHelperRequirement") as? String
    let requirement = configured?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    connection.setCodeSigningRequirement(
        requirement.isEmpty ? "identifier \"com.pigui.helper\"" : requirement
    )
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
        case "status", "version", "disable-capture", "flush-firewall":
            break
        case "enable-capture":
            guard let interface = arguments.first else {
                fail("usage: pigui-helperctl enable-capture <interface>", code: 2)
            }
            params["interface"] = interface
        case "apply-block":
            guard let ip = arguments.first else {
                fail("usage: pigui-helperctl apply-block <ip-or-cidr> [direction] [ttl]", code: 2)
            }
            params["ip"] = ip
            if arguments.count > 1 {
                params["direction"] = arguments[1]
            }
            if arguments.count > 2, let ttl = Int(arguments[2]) {
                params["ttl_secs"] = ttl
            }
        default:
            fail(
                "usage: pigui-helperctl status|version|enable-capture <iface>|disable-capture|flush-firewall|apply-block <ip> [direction] [ttl]",
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
