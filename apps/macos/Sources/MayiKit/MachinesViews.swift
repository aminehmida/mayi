import AppKit
import SwiftUI

/// The command to run on the other machine, with the one-time token.
public struct PairingSheet: View {
    let token: String?
    let paired: String?
    let onClose: () -> Void
    @State private var copied = false

    public init(token: String?, paired: String?, onClose: @escaping () -> Void) {
        self.token = token
        self.paired = paired
        self.onClose = onClose
    }

    private var command: String { "mayi pair \(token ?? "")" }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let paired {
                Label("\(paired) is paired", systemImage: "checkmark.circle.fill")
                    .font(.headline)
                    .symbolRenderingMode(.multicolor)
                Text("It can now ask for secrets. Its requests are marked as coming from another machine, and secrets that are normally released silently show a notice instead.")
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Pair a Machine").font(.headline)
                Text("Run this on the other machine within \(AppModel.pairingMinutes) minutes. It works once.")
                    .fixedSize(horizontal: false, vertical: true)
                CodeWell(text: command, lineLimit: 5)
                Text("Anyone who has this text before you use it can pair a machine of their own. Send it over something you trust, such as your own SSH session.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if paired == nil {
                    Button(copied ? "Copied" : "Copy Command") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(command, forType: .string)
                        copied = true
                    }
                }
                Spacer()
                if paired == nil {
                    Button("Cancel", role: .cancel, action: onClose).keyboardShortcut(.cancelAction)
                } else {
                    Button("Done", action: onClose).keyboardShortcut(.defaultAction)
                }
            }
            .padding(.top, 4)
        }
        .padding(20)
        .frame(width: 460)
    }
}

public struct MachinesView: View {
    @ObservedObject var model: AppModel
    @State private var selection: String?
    @State private var showPairing = false
    @State private var aclTarget: AclTarget?
    @State private var error: String?

    public init(model: AppModel) {
        self.model = model
    }

    /// What the ACL editor is open for.
    private enum AclTarget: Identifiable {
        /// A new machine, before its invitation exists.
        case pairing
        case machine(MachineRecord)
        /// The agents on a vault device's own machine.
        case agents(DeviceInfo)

        var id: String {
            switch self {
            case .pairing: return "pairing"
            case .machine(let machine): return machine.id
            case .agents(let device): return "agents:" + device.id
            }
        }
    }

    /// Paired machines; the machine a vault device runs on is shown as that
    /// device's agents instead.
    private var paired: [MachineRecord] { model.machines.filter { $0.runsDevice == nil } }
    /// The devices that serve agents on their own machine, this Mac first.
    private var agentDevices: [DeviceInfo] {
        model.devices.filter { $0.agentsAcl != nil && !$0.removed }.sorted { $0.thisDevice && !$1.thisDevice }
    }

    private var selectedMachine: MachineRecord? { paired.first { $0.id == selection } }
    private var selectedAgents: DeviceInfo? { agentDevices.first { "agents:" + $0.id == selection } }

    private static let date: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter
    }()

    private func pair() {
        aclTarget = .pairing
    }

    private func editSelected() {
        if let machine = selectedMachine, !machine.revoked {
            aclTarget = .machine(machine)
        } else if let device = selectedAgents {
            aclTarget = .agents(device)
        }
    }

    private static func detail(_ machine: MachineRecord) -> String {
        "Paired \(date.string(from: Date(timeIntervalSince1970: Double(machine.addedMs) / 1000))), key \(machine.id.prefix(8))"
    }

    private func row(icon: String, title: String, detail: String, acl: AclRecord?, revoked: Bool) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(.secondary)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                if let acl, !revoked {
                    Text("ACL: \(aclSummary(acl))")
                        .font(.callout)
                        .foregroundStyle(acl.all ? .secondary : .primary)
                        .lineLimit(2)
                }
            }
            Spacer()
            if revoked {
                Text("Revoked").font(.callout).foregroundStyle(.red)
            }
        }
        .padding(.vertical, 4)
    }

    public var body: some View {
        List(selection: $selection) {
            if !agentDevices.isEmpty {
                Section("Agents on Your Devices") {
                    ForEach(agentDevices, id: \.id) { device in
                        row(
                            icon: "laptopcomputer",
                            title: device.thisDevice ? "Agents on this Mac" : "Agents on \(device.name)",
                            detail: device.thisDevice
                                ? "Through Mayi here, and from here on your other devices"
                                : "Through Mayi on that Mac, and from there on your other devices",
                            acl: device.agentsAcl, revoked: false
                        )
                        .tag("agents:" + device.id)
                    }
                }
            }
            Section("Paired Machines") {
                if paired.isEmpty {
                    Text("None yet. Pair a server or a virtual machine so agents there can ask for secrets; nothing is stored on it.")
                        .foregroundStyle(.secondary)
                }
                ForEach(paired, id: \.id) { machine in
                    row(
                        icon: "server.rack", title: machine.name, detail: Self.detail(machine), acl: machine.acl,
                        revoked: machine.revoked
                    )
                    .tag(machine.id)
                }
            }
        }
        .listStyle(.inset)
        .contextMenu(forSelectionType: String.self) { _ in
            Button("Edit ACL\u{2026}", action: editSelected)
        } primaryAction: { _ in
            editSelected()
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            StatusBar(message: error ?? model.remoteError, isError: true)
        }
        .navigationTitle("Machines")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button(action: editSelected) {
                    Label("Edit ACL", systemImage: "checklist")
                }
                .disabled(selectedAgents == nil && (selectedMachine == nil || selectedMachine?.revoked == true))
                .help("Choose which secrets the selected machine may use")
                Button {
                    if let selectedMachine { error = model.revokeMachine(id: selectedMachine.id) }
                } label: {
                    Label("Revoke", systemImage: "minus.circle")
                }
                .disabled(selectedMachine == nil || selectedMachine?.revoked == true)
                .help("Stop accepting requests from the selected machine")
                Button(action: pair) {
                    Label("Pair a Machine", systemImage: "plus")
                }
                .help("Pair a machine")
            }
        }
        .alert("Revoked", isPresented: .constant(model.rotationAdvice != nil)) {
            Button("OK") { model.rotationAdvice = nil }
        } message: {
            Text(model.rotationAdvice ?? "")
        }
        .sheet(item: $aclTarget) { target in
            aclEditor(target)
        }
        .sheet(isPresented: $showPairing) {
            PairingSheet(token: model.pairingToken, paired: model.lastPaired) {
                model.cancelPairing()
                showPairing = false
            }
        }
    }

    @ViewBuilder private func aclEditor(_ target: AclTarget) -> some View {
        let close = { aclTarget = nil }
        switch target {
        case .pairing:
            AclEditor(
                title: "Pair a Machine",
                message: "Choose what the new machine may use. It is refused anything else, without asking you.",
                confirm: "Create Invitation", acl: nil, tags: model.tags, secrets: model.secrets,
                onConfirm: { acl in
                    close()
                    Task {
                        error = await model.startPairing(acl: acl)
                        showPairing = error == nil
                    }
                },
                onCancel: close)
        case .machine(let machine):
            AclEditor(
                title: "ACL for \(machine.name)",
                message: "What this machine may use. It is refused anything else, without asking you.",
                confirm: "Save", acl: machine.acl, tags: model.tags, secrets: model.secrets,
                onConfirm: { acl in
                    error = model.setMachineAcl(id: machine.id, acl: acl)
                    close()
                },
                onCancel: close)
        case .agents(let device):
            AclEditor(
                title: device.thisDevice ? "ACL for agents on this Mac" : "ACL for agents on \(device.name)",
                message: "What the agents on that Mac may use, through Mayi there and from your other devices.",
                confirm: "Save", acl: device.agentsAcl, tags: model.tags, secrets: model.secrets,
                onConfirm: { acl in
                    error = model.setAgentsAcl(deviceId: device.id, acl: acl)
                    close()
                },
                onCancel: close)
        }
    }
}
