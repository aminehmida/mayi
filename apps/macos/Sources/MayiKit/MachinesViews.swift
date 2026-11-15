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
    @State private var error: String?

    public init(model: AppModel) {
        self.model = model
    }

    private var selected: MachineRecord? { model.machines.first { $0.id == selection } }

    private static let date: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter
    }()

    private func pair() {
        Task {
            error = await model.startPairing()
            showPairing = error == nil
        }
    }

    public var body: some View {
        List(selection: $selection) {
            ForEach(model.machines, id: \.id) { machine in
                HStack(spacing: 10) {
                    Image(systemName: "server.rack")
                        .foregroundStyle(.secondary)
                        .frame(width: 22)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(machine.name)
                        Text("Paired \(Self.date.string(from: Date(timeIntervalSince1970: Double(machine.addedMs) / 1000))), key \(machine.id.prefix(8))")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if machine.revoked {
                        Text("Revoked").font(.callout).foregroundStyle(.red)
                    }
                }
                .padding(.vertical, 4)
                .tag(machine.id)
            }
        }
        .listStyle(.inset)
        .overlay {
            if model.machines.isEmpty {
                ContentUnavailableView {
                    Label("No Other Machines", systemImage: "server.rack")
                } description: {
                    Text("Pair a server or a virtual machine so agents there can ask this Mac for secrets. Nothing is stored on the other machine.")
                } actions: {
                    Button("Pair a Machine", action: pair)
                }
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            StatusBar(message: error ?? model.remoteError, isError: true)
        }
        .navigationTitle("Machines")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    if let selected { error = model.revokeMachine(id: selected.id) }
                } label: {
                    Label("Revoke", systemImage: "minus.circle")
                }
                .disabled(selected == nil || selected?.revoked == true)
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
        .sheet(isPresented: $showPairing) {
            PairingSheet(token: model.pairingToken, paired: model.lastPaired) {
                model.cancelPairing()
                showPairing = false
            }
        }
    }
}
