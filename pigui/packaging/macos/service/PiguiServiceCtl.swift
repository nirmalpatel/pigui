import Foundation
import ServiceManagement

private let agentPlist = "com.pigui.daemon.plist"
private let helperPlist = "com.pigui.helper.plist"

private func statusName(_ status: SMAppService.Status) -> String {
    switch status {
    case .notRegistered:
        return "not_registered"
    case .enabled:
        return "enabled"
    case .requiresApproval:
        return "requires_approval"
    case .notFound:
        return "not_found"
    @unknown default:
        return "unknown"
    }
}

private func printStatus() {
    let agent = SMAppService.agent(plistName: agentPlist)
    let helper = SMAppService.daemon(plistName: helperPlist)
    let payload: [String: Any] = [
        "agent": statusName(agent.status),
        "helper": statusName(helper.status),
        "bundle": Bundle.main.bundleURL.path,
        "bundle_id": Bundle.main.bundleIdentifier ?? "",
    ]
    if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
       let text = String(data: data, encoding: .utf8) {
        print(text)
    }
}

private func register(_ service: SMAppService, label: String) -> Int32 {
    do {
        try service.register()
        print("{\"ok\":true,\"service\":\"\(label)\",\"status\":\"\(statusName(service.status))\"}")
        if service.status == .requiresApproval {
            print("Approval is required in System Settings > General > Login Items & Extensions.")
        }
        return 0
    } catch {
        let message = error.localizedDescription.replacingOccurrences(of: "\"", with: "'")
        print("{\"ok\":false,\"service\":\"\(label)\",\"error\":\"\(message)\"}")
        return 1
    }
}

private func unregister(_ service: SMAppService, label: String) -> Int32 {
    do {
        try service.unregister()
        print("{\"ok\":true,\"service\":\"\(label)\",\"status\":\"\(statusName(service.status))\"}")
        return 0
    } catch {
        let message = error.localizedDescription.replacingOccurrences(of: "\"", with: "'")
        print("{\"ok\":false,\"service\":\"\(label)\",\"error\":\"\(message)\"}")
        return 1
    }
}

@main
struct PiguiServiceCtlMain {
    static func main() {
        let command = CommandLine.arguments.dropFirst().first ?? "status"
        let agent = SMAppService.agent(plistName: agentPlist)
        let helper = SMAppService.daemon(plistName: helperPlist)

        var code: Int32 = 0
        switch command {
        case "status":
            printStatus()
        case "register-agent":
            code = register(agent, label: "agent")
        case "unregister-agent":
            code = unregister(agent, label: "agent")
        case "register-helper":
            code = register(helper, label: "helper")
        case "unregister-helper":
            code = unregister(helper, label: "helper")
        default:
            FileHandle.standardError.write(Data(
                "usage: pigui-servicectl status|register-agent|unregister-agent|register-helper|unregister-helper\n".utf8
            ))
            code = 2
        }
        exit(code)
    }
}
