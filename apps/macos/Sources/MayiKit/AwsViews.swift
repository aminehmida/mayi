import AppKit
import SwiftUI

// MARK: Shared pieces

extension LevelInfo {
    /// What a level means for one role of an AWS sign-in. Level 4 is a
    /// fingerprint for every use: the sign-in is shared by all its roles, so
    /// it cannot be encrypted to the fingerprint for one of them.
    static func awsDetail(_ level: UInt8) -> String {
        switch level {
        case 1: return "Used without asking, and recorded in Activity."
        case 2: return "Used at once. You are notified and can stop the command."
        case 3: return "Each command waits for your approval."
        default: return "Touch ID, your Apple Watch or your password for every use."
        }
    }
}

/// A role of an AWS sign-in, being chosen or edited.
struct AwsProfileDraft: Identifiable, Equatable {
    var id: String { accountId + "/" + role }
    var enabled: Bool
    var name: String
    var accountId: String
    var accountName: String
    var role: String
    var level: UInt8

    init(_ p: AwsProfileRecord, enabled: Bool = true) {
        self.enabled = enabled
        name = p.name
        accountId = p.accountId
        accountName = p.accountName
        role = p.role
        level = p.level
    }

    var record: AwsProfileRecord {
        AwsProfileRecord(name: name, accountId: accountId, accountName: accountName, role: role, level: level)
    }
}

/// A name for a sign-in from its portal: `mawaqit` for
/// https://mawaqit.awsapps.com/start.
func awsName(fromStartUrl url: String) -> String {
    guard let host = URL(string: url.trimmingCharacters(in: .whitespaces))?.host else { return "" }
    let first = host.split(separator: ".").first.map(String.init) ?? ""
    let name = first.hasPrefix("d-") ? "aws" : first
    return String(name.lowercased().map { $0.isLetter || $0.isNumber || $0 == "-" ? $0 : "-" })
}

/// The roles of a sign-in, by account: a switch, the profile name agents
/// use, and its level.
struct AwsProfileList: View {
    @Binding var profiles: [AwsProfileDraft]
    let signInName: String

    private var accounts: [(name: String, id: String)] {
        var seen = Set<String>()
        return profiles.compactMap { p in
            seen.insert(p.accountId).inserted ? (p.accountName, p.accountId) : nil
        }
    }

    var body: some View {
        List {
            ForEach(accounts, id: \.id) { account in
                Section {
                    ForEach($profiles) { $p in
                        if p.accountId == account.id { row($p) }
                    }
                } header: {
                    HStack(spacing: 6) {
                        Text(account.name.isEmpty ? account.id : account.name)
                        if !account.name.isEmpty {
                            Text(account.id).foregroundStyle(.tertiary).font(.caption.monospacedDigit())
                        }
                    }
                }
            }
        }
        .listStyle(.inset(alternatesRowBackgrounds: false))
    }

    private func row(_ p: Binding<AwsProfileDraft>) -> some View {
        HStack(spacing: 10) {
            Toggle(isOn: p.enabled) { EmptyView() }
                .toggleStyle(.checkbox)
                .labelsHidden()
                .help(p.wrappedValue.enabled ? "Agents may use this role" : "Not offered to agents")
            VStack(alignment: .leading, spacing: 2) {
                Text(p.wrappedValue.role).font(.body.weight(.medium))
                HStack(spacing: 2) {
                    Text("\(signInName)/").foregroundStyle(.tertiary)
                    TextField("profile", text: p.name)
                        .textFieldStyle(.plain)
                        .foregroundStyle(.secondary)
                }
                .font(.system(size: 11.5, design: .monospaced))
            }
            .opacity(p.wrappedValue.enabled ? 1 : 0.45)
            Spacer()
            Picker("Level", selection: p.level) {
                ForEach(UInt8(1)...UInt8(4), id: \.self) { level in
                    LevelLabel(level: level).tag(level)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .fixedSize()
            .disabled(!p.wrappedValue.enabled)
            .help(LevelInfo.awsDetail(p.wrappedValue.level))
        }
        .padding(.vertical, 2)
    }
}

/// While the owner approves in the browser: the code to compare, and what
/// to check.
struct AwsWaitingView: View {
    let flow: AwsSignInFlow
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Finish in your browser")
                .font(.system(size: 15, weight: .semibold))
            Text("AWS\u{2019}s page is open. Sign in as you usually do, check it shows this code, then allow Mayi.")
                .fixedSize(horizontal: false, vertical: true)
            Text(flow.userCode())
                .font(.system(size: 26, weight: .semibold, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            Label(
                "The page names the app asking. If a page like it ever names another app, an agent may have started it: don\u{2019}t allow it.",
                systemImage: "checkmark.shield"
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            HStack {
                ProgressView().controlSize(.small)
                Text("Waiting for AWS\u{2026}").foregroundStyle(.secondary)
                Spacer()
                Button("Open the Page Again") { openPage(flow) }
                Button("Cancel", role: .cancel, action: onCancel)
            }
        }
    }
}

@MainActor
func openPage(_ flow: AwsSignInFlow) {
    if let url = URL(string: flow.verificationUrl()) { NSWorkspace.shared.open(url) }
}

// MARK: Adding a sign-in

/// Adds an AWS sign-in: the portal, AWS's own sign-in in the browser, then
/// which roles agents may use and at which level.
public struct AwsSignInSheet: View {
    @ObservedObject var model: AppModel
    /// The tag being looked at, which a new sign-in starts with.
    let tag: String?
    /// Inside the Add dialog: another type was picked.
    let onPickKind: ((AddKind) -> Void)?
    let onDone: () -> Void

    private enum Step {
        case portal
        case waiting(AwsSignInFlow)
        case choosing(AwsSession)
    }

    @State private var step: Step = .portal
    @State private var portals: [AwsPortalRecord] = []
    @State private var startUrl = ""
    @State private var region = ""
    @State private var name = ""
    @State private var nameEdited = false
    @State private var profiles: [AwsProfileDraft] = []
    @State private var forgetCli = true
    @State private var cliProfiles = true
    @State private var busy = false
    @State private var error: String?

    public init(
        model: AppModel, tag: String? = nil, onPickKind: ((AddKind) -> Void)? = nil, onDone: @escaping () -> Void
    ) {
        self.model = model
        self.tag = tag
        self.onPickKind = onPickKind
        self.onDone = onDone
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Group {
                switch step {
                case .portal: portalStep
                case .waiting(let flow):
                    AwsWaitingView(flow: flow) { flow.cancel() }
                        .task { await wait(flow) }
                case .choosing(let session): choosingStep(session)
                }
            }
            .padding(20)
        }
        .frame(width: 560)
        .onAppear {
            portals = model.knownAwsPortals()
            cliProfiles = model.awsCliProfiles
            if let first = portals.first { pick(first) }
        }
    }

    private func pick(_ portal: AwsPortalRecord) {
        startUrl = portal.startUrl
        region = portal.region
        if !nameEdited { name = awsName(fromStartUrl: portal.startUrl) }
    }

    private var portalStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let onPickKind {
                Form {
                    AddKindPicker(kind: Binding(get: { .aws }, set: { kind in if kind != .aws { onPickKind(kind) } }))
                }
                .formStyle(.columns)
            }
            HStack(alignment: .top, spacing: 14) {
                AwsLogo().frame(width: 44)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Add an AWS Sign-In").font(.system(size: 15, weight: .semibold))
                    Text(
                        "Mayi signs in to your AWS access portal itself and keeps the session on this Mac. Agents never see it: they get one role\u{2019}s temporary keys, at the level you choose for that role."
                    )
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
            if !portals.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Found in your AWS CLI settings").font(.caption.weight(.medium)).foregroundStyle(.secondary)
                    ForEach(portals, id: \.startUrl) { portal in
                        Button {
                            pick(portal)
                        } label: {
                            HStack {
                                Image(systemName: startUrl == portal.startUrl ? "largecircle.fill.circle" : "circle")
                                    .foregroundStyle(startUrl == portal.startUrl ? Color.accentColor : .secondary)
                                Text(portal.startUrl).font(.system(.body, design: .monospaced))
                                Spacer()
                                Text(portal.region).foregroundStyle(.secondary)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            Form {
                TextField("Start URL", text: $startUrl, prompt: Text("https://example.awsapps.com/start"))
                    .onChange(of: startUrl) { _, url in if !nameEdited { name = awsName(fromStartUrl: url) } }
                TextField("Region", text: $region, prompt: Text("eu-west-1"))
                TextField("Name", text: $name, prompt: Text("work"))
                    .onChange(of: name) { _, new in if new != awsName(fromStartUrl: startUrl) { nameEdited = true } }
            }
            .formStyle(.columns)
            Text("Agents ask for a role as \(name.isEmpty ? "NAME" : name)/PROFILE. Your AWS sign-in stays the strong step: your usual login and two-factor, when AWS asks.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            footer {
                Button("Cancel", role: .cancel, action: onDone).keyboardShortcut(.cancelAction)
                Button("Sign In with AWS") { Task { await begin() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy || startUrl.isEmpty || region.isEmpty || name.isEmpty)
            }
        }
    }

    private func choosingStep(_ session: AwsSession) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Choose what agents may use").font(.system(size: 15, weight: .semibold))
            Text("Each role is a profile with its own level. Suggested: read-only roles at 1, roles that can change production at 4, the rest at 3.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            AwsProfileList(profiles: $profiles, signInName: name)
                .frame(height: min(CGFloat(profiles.count) * 46 + 60, 320))
            VStack(alignment: .leading, spacing: 6) {
                Toggle(isOn: $cliProfiles) {
                    Text("Add these profiles to ~/.aws/config, so `aws --profile \(name)-PROFILE`, Terraform and SDKs ask Mayi")
                }
                Toggle(isOn: $forgetCli) {
                    Text("Remove the AWS CLI\u{2019}s own saved sign-in to this portal: any program, agents included, can read it")
                }
            }
            .toggleStyle(.checkbox)
            .fixedSize(horizontal: false, vertical: true)
            footer {
                Button("Cancel", role: .cancel, action: onDone).keyboardShortcut(.cancelAction)
                Button("Add Sign-In") { Task { await save(session) } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy || !profiles.contains(where: \.enabled))
            }
        }
    }

    private func footer<Buttons: View>(@ViewBuilder _ buttons: () -> Buttons) -> some View {
        HStack(spacing: 10) {
            if let error {
                Text(error).font(.callout).foregroundStyle(.red).lineLimit(3)
                    .fixedSize(horizontal: false, vertical: true)
            } else if busy {
                ProgressView().controlSize(.small)
            }
            Spacer()
            buttons()
        }
        .controlSize(.large)
        .padding(.top, 4)
    }

    private func begin() async {
        busy = true
        error = nil
        defer { busy = false }
        switch await model.beginAwsSignIn(startUrl: startUrl, region: region) {
        case .success(let flow):
            openPage(flow)
            step = .waiting(flow)
        case .failure(let problem):
            error = problem.message
        }
    }

    private func wait(_ flow: AwsSignInFlow) async {
        switch await model.finishAwsSignIn(flow) {
        case .success(let session):
            NSApp.activate(ignoringOtherApps: true)
            switch await model.awsAccounts(session) {
            case .success(let accounts):
                profiles = awsSuggestProfiles(accounts: accounts).map { AwsProfileDraft($0) }
                step = .choosing(session)
            case .failure(let problem):
                error = problem.message
                step = .portal
            }
        case .failure(let problem):
            error = problem.message == "the sign-in was cancelled" ? nil : problem.message
            step = .portal
        }
    }

    private func save(_ session: AwsSession) async {
        busy = true
        error = nil
        defer { busy = false }
        if cliProfiles != model.awsCliProfiles { model.setAwsCliProfiles(cliProfiles) }
        let chosen = profiles.filter(\.enabled).map(\.record)
        if let problem = await model.saveAwsSignIn(
            name: name, session: session, profiles: chosen, tags: tag.map { [$0] } ?? [], forgetCliSignIns: forgetCli)
        {
            error = problem
        } else {
            onDone()
        }
    }
}

// MARK: Editing a sign-in

/// A saved AWS sign-in: its roles and their levels, more roles, signing in
/// again. Asking less of a role, or adding one, needs Touch ID.
public struct AwsSignInEditor: View {
    @ObservedObject var model: AppModel
    let secret: SecretRecord
    let onDone: () -> Void

    @State private var profiles: [AwsProfileDraft]
    @State private var original: [AwsProfileDraft]
    @State private var signingIn: AwsSignInFlow?
    @State private var busy = false
    @State private var message: String?
    @State private var error: String?

    public init(model: AppModel, secret: SecretRecord, onDone: @escaping () -> Void) {
        self.model = model
        self.secret = secret
        self.onDone = onDone
        let drafts = (secret.aws?.profiles ?? []).map { AwsProfileDraft($0) }
        _profiles = State(initialValue: drafts)
        _original = State(initialValue: drafts)
    }

    private var aws: AwsSignInRecord? { model.secrets.first { $0.name == secret.name }?.aws ?? secret.aws }

    public var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 14) {
                AwsLogo().frame(width: 44)
                VStack(alignment: .leading, spacing: 3) {
                    Text(secret.name).font(.system(size: 15, weight: .semibold, design: .monospaced))
                    if let aws {
                        Text("\(aws.startUrl)  \u{00B7}  \(aws.region)").foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
            }
            if let aws, aws.cliHasSignIn {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.multicolor)
                    Text("The AWS CLI saved a sign-in to this portal again (someone ran aws sso login). Any program, agents included, can read it.")
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Remove") { error = model.forgetAwsCliSignIns(startUrl: aws.startUrl) }
                }
                .padding(10)
                .background(.yellow.opacity(0.12), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
            if let flow = signingIn {
                AwsWaitingView(flow: flow) { flow.cancel() }
                    .task { await signInAgain(flow) }
            } else {
                AwsProfileList(profiles: $profiles, signInName: secret.name)
                    .frame(height: min(CGFloat(profiles.count) * 46 + 60, 340))
                HStack {
                    Button("Find More Roles") { Task { await findRoles() } }
                        .help("Look for accounts and roles you got since adding this sign-in")
                    Button("Sign In Again") { Task { await beginSignIn() } }
                        .help("Sign in to the portal again, keeping these profiles")
                    Spacer()
                    Toggle(
                        "Keep them in ~/.aws/config",
                        isOn: Binding(get: { model.awsCliProfiles }, set: { model.setAwsCliProfiles($0) })
                    )
                    .toggleStyle(.checkbox)
                    .help("aws --profile \(secret.name)-PROFILE, Terraform and SDKs then ask Mayi")
                }
                HStack(spacing: 10) {
                    if let error {
                        Text(error).font(.callout).foregroundStyle(.red).lineLimit(3)
                            .fixedSize(horizontal: false, vertical: true)
                    } else if let message {
                        Text(message).font(.callout).foregroundStyle(.secondary)
                    } else if busy {
                        ProgressView().controlSize(.small)
                    }
                    Spacer()
                    Button("Cancel", role: .cancel, action: onDone).keyboardShortcut(.cancelAction)
                    Button("Save") { Task { await save() } }
                        .keyboardShortcut(.defaultAction)
                        .disabled(busy || profiles == original)
                }
                .controlSize(.large)
            }
        }
        .padding(20)
        .frame(width: 560)
    }

    private func save() async {
        busy = true
        error = nil
        defer { busy = false }
        let chosen = profiles.filter(\.enabled).map(\.record)
        if let problem = await model.updateAwsProfiles(name: secret.name, profiles: chosen) {
            error = problem
        } else {
            onDone()
        }
    }

    private func findRoles() async {
        busy = true
        error = nil
        defer { busy = false }
        switch await model.awsAccounts(name: secret.name) {
        case .success(let accounts):
            let known = Set(profiles.map(\.id))
            let found = awsSuggestProfiles(accounts: accounts)
                .map { AwsProfileDraft($0, enabled: false) }
                .filter { !known.contains($0.id) }
            profiles += found
            message = found.isEmpty ? "No new roles." : "Found \(found.count) new role(s): check the ones agents may use."
        case .failure(let problem):
            error = problem.message
        }
    }

    private func beginSignIn() async {
        guard let aws else { return }
        busy = true
        defer { busy = false }
        switch await model.beginAwsSignIn(startUrl: aws.startUrl, region: aws.region) {
        case .success(let flow):
            openPage(flow)
            signingIn = flow
        case .failure(let problem):
            error = problem.message
        }
    }

    private func signInAgain(_ flow: AwsSignInFlow) async {
        defer { signingIn = nil }
        switch await model.finishAwsSignIn(flow) {
        case .success(let session):
            NSApp.activate(ignoringOtherApps: true)
            if let problem = await model.renewAwsSignIn(name: secret.name, session: session) {
                error = problem
            } else {
                message = "Signed in again."
            }
        case .failure(let problem):
            if problem.message != "the sign-in was cancelled" { error = problem.message }
        }
    }
}

// MARK: Signing in again while a request waits

/// An AWS session ended while a command needed it. Signing in again here
/// lets the waiting command carry on.
public struct AwsSignInAgainView: View {
    @ObservedObject var model: AppModel
    let pending: AppModel.PendingSignIn
    let waiting: Int

    @State private var flow: AwsSignInFlow?
    @State private var busy = false
    @State private var error: String?

    public init(model: AppModel, pending: AppModel.PendingSignIn, waiting: Int = 0) {
        self.model = model
        self.pending = pending
        self.waiting = waiting
    }

    private var needed: AwsSignInNeededInfo { pending.needed }

    public var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 14) {
                AppIconView(size: 48)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Sign in to \(needed.name) again?")
                        .font(.system(size: 15, weight: .semibold))
                    Text("Your AWS session ended: AWS ends it after a set time. A command is waiting for it.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    RequesterBadge(request: needed.request).padding(.top, 4)
                }
            }
            CodeWell(text: needed.request.command, lineLimit: 4)
            if let flow {
                AwsWaitingView(flow: flow) { flow.cancel() }
                    .task { await finish(flow) }
            } else {
                HStack(spacing: 10) {
                    Button("Not Now") { model.answerSignIn(pending.id, signedIn: false) }
                        .keyboardShortcut(.cancelAction)
                    if waiting > 0 {
                        Text("\(waiting) more waiting").font(.callout).foregroundStyle(.secondary)
                    }
                    if let error {
                        Text(error).font(.callout).foregroundStyle(.red).lineLimit(2)
                    }
                    Spacer()
                    Button("Sign In with AWS") { Task { await begin() } }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy)
                }
                .controlSize(.large)
            }
        }
        .padding(20)
        .frame(width: 500)
    }

    private func begin() async {
        busy = true
        error = nil
        defer { busy = false }
        switch await model.beginAwsSignIn(startUrl: needed.startUrl, region: needed.region) {
        case .success(let started):
            openPage(started)
            flow = started
        case .failure(let problem):
            error = problem.message
        }
    }

    private func finish(_ started: AwsSignInFlow) async {
        switch await model.finishAwsSignIn(started) {
        case .success(let session):
            if let problem = await model.renewAwsSignIn(name: needed.name, session: session) {
                error = problem
                flow = nil
            } else {
                model.answerSignIn(pending.id, signedIn: true)
            }
        case .failure(let problem):
            error = problem.message == "the sign-in was cancelled" ? nil : problem.message
            flow = nil
        }
    }
}
