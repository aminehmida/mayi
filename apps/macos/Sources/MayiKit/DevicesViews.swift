import AppKit
import CoreImage.CIFilterBuiltins
import SwiftUI

/// A QR code for text that is tedious to type on a phone.
func qrCode(_ text: String) -> NSImage? {
    let filter = CIFilter.qrCodeGenerator()
    filter.message = Data(text.utf8)
    filter.correctionLevel = "M"
    guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 6, y: 6)) else { return nil }
    let rep = NSCIImageRep(ciImage: output)
    let image = NSImage(size: rep.size)
    image.addRepresentation(rep)
    return image
}

/// Adding a device: this Mac's invitation, as a QR code and as text, for a
/// new device to scan or paste; or the code a new device shows, pasted here.
public struct EnrolmentSheet: View {
    let token: String?
    let added: String?
    /// Adds the device that shows the pasted code; returns an error message.
    let onAddByCode: ((String) async -> String?)?
    let onClose: () -> Void
    @State private var copied = false
    @State private var code = ""
    @State private var adding = false
    @State private var error: String?

    public init(
        token: String?, added: String?, onAddByCode: ((String) async -> String?)? = nil,
        onClose: @escaping () -> Void
    ) {
        self.token = token
        self.added = added
        self.onAddByCode = onAddByCode
        self.onClose = onClose
    }

    private func addByCode() {
        guard let onAddByCode, !code.isEmpty else { return }
        adding = true
        error = nil
        Task {
            error = await onAddByCode(code)
            adding = false
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let added {
                Label("\(added) has joined", systemImage: "checkmark.circle.fill")
                    .font(.headline)
                    .symbolRenderingMode(.multicolor)
                Text("It now holds a copy of every secret and can answer requests. A change made on either device reaches the other the next time they can connect.")
                    .fixedSize(horizontal: false, vertical: true)
            } else if let token {
                Text("Add a Device").font(.headline)
                Text("On a new phone, choose \u{201C}Scan code from another device\u{201D} and scan this. On a new Mac, paste it as text under \u{201C}Use an Invitation\u{201D}. It works once, within \(AppModel.pairingMinutes) minutes.")
                    .fixedSize(horizontal: false, vertical: true)
                if let image = qrCode(token) {
                    // A QR code must stay black on white to scan, in either appearance.
                    Image(nsImage: image)
                        .interpolation(.none)
                        .resizable()
                        .frame(width: 200, height: 200)
                        .padding(10)
                        .background(Color.white, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(.separator, lineWidth: 0.5))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 2)
                }
                Text("The new device receives the whole vault. If you have level 4 secrets, this Mac asks you to confirm when the device connects, to share their keys with it.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if onAddByCode != nil {
                    Divider().padding(.vertical, 2)
                    Text("Is the new device showing a code? Paste it here.")
                    HStack {
                        TextField("Code", text: $code, prompt: Text("mayij1.\u{2026}"))
                            .labelsHidden()
                            .font(.system(.body, design: .monospaced))
                            .onSubmit(addByCode)
                            .disabled(adding)
                        if adding { ProgressView().controlSize(.small) }
                        Button("Add", action: addByCode)
                            .disabled(code.trimmingCharacters(in: .whitespaces).isEmpty || adding)
                    }
                    if let error {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            HStack {
                if added == nil, let token {
                    Button(copied ? "Copied" : "Copy as Text") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(token, forType: .string)
                        copied = true
                    }
                }
                Spacer()
                if added == nil {
                    Button("Cancel", role: .cancel, action: onClose).keyboardShortcut(.cancelAction)
                } else {
                    Button("Done", action: onClose).keyboardShortcut(.defaultAction)
                }
            }
            .padding(.top, 4)
        }
        .padding(20)
        .frame(width: 420)
    }
}

/// The recovery key, shown once.
public struct RecoveryKeySheet: View {
    let key: String
    let onClose: () -> Void
    @State private var copied = false

    public init(key: String, onClose: @escaping () -> Void) {
        self.key = key
        self.onClose = onClose
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Recovery Key").font(.headline)
            Text("Write it down or print it, and keep it somewhere offline. It is not stored, and it is not shown again.")
                .fixedSize(horizontal: false, vertical: true)
            CodeWell(text: key)
            Text("With this key and a copy of the vault file, anyone can read every secret, without your devices or your fingerprint. It restores this Mac if its keys are lost, for example after its fingerprints change. Making a new key stops the old one from receiving new level 4 secrets.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button(copied ? "Copied" : "Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(key, forType: .string)
                    copied = true
                }
                Spacer()
                Button("I Have Saved It", action: onClose).keyboardShortcut(.defaultAction)
            }
            .padding(.top, 4)
        }
        .padding(20)
        .frame(width: 460)
    }
}

public struct DevicesView: View {
    @ObservedObject var model: AppModel
    @State private var selection: String?
    @State private var showEnrolment = false
    @State private var confirmJoin = false
    @State private var error: String?

    public init(model: AppModel) {
        self.model = model
    }

    private var selected: DeviceInfo? { model.devices.first { $0.id == selection } }

    private func add() {
        Task {
            error = await model.startEnrolment()
            showEnrolment = error == nil
        }
    }

    private func place(_ device: DeviceInfo) -> String {
        if device.recovery { return "Kept offline by you" }
        if device.addresses.isEmpty {
            return device.thisDevice ? "Not open to other machines or devices yet" : "Has not said where it is yet"
        }
        return "At " + device.addresses.joined(separator: ", ")
    }

    public var body: some View {
        List(selection: $selection) {
            if model.vaultIsEmpty {
                Section {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: "info.circle")
                            .foregroundStyle(.secondary)
                            .frame(width: 22)
                        VStack(alignment: .leading, spacing: 6) {
                            Text("This Mac\u{2019}s vault is empty").font(.headline)
                            Text("If your secrets are on your phone or another Mac, join that vault instead. Mayi restarts and shows a code to scan.")
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            Button("Join Another Vault\u{2026}") { confirmJoin = true }
                        }
                    }
                    .padding(.vertical, 6)
                }
            }
            ForEach(model.devices, id: \.id) { device in
                HStack(spacing: 10) {
                    Image(systemName: device.recovery ? "key.horizontal" : device.thisDevice ? "laptopcomputer" : "iphone")
                        .foregroundStyle(.secondary)
                        .frame(width: 22)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(device.thisDevice ? "\(device.name) (This Mac)" : device.name)
                        Text(place(device))
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                    if device.removed {
                        Text("Removed").font(.callout).foregroundStyle(.red)
                    }
                }
                .padding(.vertical, 4)
                .tag(device.id)
            }
        }
        .listStyle(.inset)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            StatusBar(
                message: error ?? model.remoteError ?? model.syncStatus, isError: (error ?? model.remoteError) != nil)
        }
        .navigationTitle("Devices")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    if let selected { error = model.removeDevice(id: selected.id) }
                } label: {
                    Label("Remove", systemImage: "minus.circle")
                }
                .disabled(selected == nil || selected?.thisDevice == true || selected?.removed == true)
                .help("Remove the selected device from the vault")
                Button {
                    model.syncNow()
                } label: {
                    Label("Sync Now", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(model.devices.filter { !$0.removed && !$0.recovery }.count < 2)
                .help("Sync with your other devices now")
                Button {
                    Task { error = await model.createRecoveryKey() }
                } label: {
                    Label("Recovery Key", systemImage: "key.horizontal")
                }
                .help("Create an offline recovery key")
                Button(action: add) {
                    Label("Add a Device", systemImage: "plus")
                }
                .help("Add a device to the vault")
            }
        }
        .sheet(isPresented: .constant(model.recoveryKey != nil)) {
            RecoveryKeySheet(key: model.recoveryKey ?? "") { model.forgetRecoveryKey() }
        }
        .alert("Removed", isPresented: .constant(model.rotationAdvice != nil)) {
            Button("OK") { model.rotationAdvice = nil }
        } message: {
            Text(model.rotationAdvice ?? "")
        }
        .sheet(isPresented: $showEnrolment) {
            EnrolmentSheet(
                token: model.enrolmentToken, added: model.lastDeviceAdded,
                onAddByCode: { code in await model.addDevice(code: code) }
            ) {
                model.cancelEnrolment()
                showEnrolment = false
            }
        }
        .confirmationDialog("Join another vault?", isPresented: $confirmJoin) {
            Button("Restart and Join") {
                error = model.setAsideEmptyVault()
                if error == nil { model.onRestart?() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This Mac\u{2019}s empty vault is set aside, and Mayi restarts to show a code for your other device to scan.")
        }
    }
}
