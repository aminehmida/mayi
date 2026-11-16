import SwiftUI

/// Asks whether a command may use level 3 secrets, or a login may be typed
/// into a website, laid out like a system permission prompt: icon and
/// question, the command or website, then the details.
///
/// "Allow Once" is prominent but is not the default button: an approval
/// must be a click, not a stray Return. Escape denies.
public struct ApprovalView: View {
    let prompt: PromptInfo
    let waiting: Int
    let onChoice: (ApprovalChoice) -> Void

    public init(prompt: PromptInfo, waiting: Int = 0, onChoice: @escaping (ApprovalChoice) -> Void) {
        self.prompt = prompt
        self.waiting = waiting
        self.onChoice = onChoice
    }

    private var needed: [PromptSecret] { prompt.secrets.filter(\.needsApproval) }

    private var site: String? { prompt.request.site }

    private var title: String {
        if let site { return "Allow signing in to \(host(site))?" }
        return needed.count == 1
            ? "Allow this command to use \(needed[0].name)?"
            : "Allow this command to use \(needed.count) secrets?"
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 14) {
                AppIconView(size: 48)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .font(.system(size: 15, weight: .semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    RequesterBadge(request: prompt.request)
                        .padding(.top, 4)
                }
            }

            ScrollView {
                CodeWell(text: site ?? prompt.request.command)
            }
            .frame(maxHeight: 130)
            .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 6) {
                ForEach(prompt.secrets, id: \.name) { secret in
                    HStack(spacing: 8) {
                        if site != nil {
                            Image(systemName: "globe").foregroundStyle(.secondary)
                        }
                        Text(secret.name).font(.system(size: 12.5, design: .monospaced))
                        Spacer()
                        if !secret.needsApproval {
                            Text("no approval needed").foregroundStyle(.tertiary)
                        }
                        LevelLabel(level: secret.level).foregroundStyle(.secondary)
                    }
                    .font(.callout)
                }
                if site != nil {
                    Text("Types \(fieldWords(prompt.request.fields)) into the page.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }

            // What the requester says about itself. None of it is checked,
            // so it is boxed, labelled, and kept below the command.
            VStack(alignment: .leading, spacing: 8) {
                Text("Stated by the requester, not verified")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 4) {
                    detail("Reason", prompt.request.reason)
                    detail("Agent", prompt.request.agent)
                    detail("Session", prompt.request.session)
                    detail("Folder", prompt.request.cwd)
                }
                .font(.callout)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(10)
            .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 6, style: .continuous))

            Text(
                site == nil
                    ? "Once allowed, the command can do anything with the secret, including sending it elsewhere."
                    : "Once signed in, the agent can act as you on this site.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Divider()

            HStack(spacing: 10) {
                Button("Deny") { onChoice(.deny) }
                    .keyboardShortcut(.cancelAction)
                if waiting > 0 {
                    Text(waiting == 1 ? "1 more waiting" : "\(waiting) more waiting")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if site != nil {
                    Button("Allow for This Session") { onChoice(.sessionCommand) }
                } else {
                    Menu("Allow for This Session") {
                        Button("This Command Only") { onChoice(.sessionCommand) }
                        Button("Any Command") { onChoice(.sessionAny) }
                    }
                    .fixedSize()
                }
                Button("Allow Once") { onChoice(.once) }
                    .buttonStyle(.borderedProminent)
            }
            .controlSize(.large)
        }
        .padding(20)
        .frame(width: 500)
    }

    private func detail(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value.isEmpty ? "not given" : value)
                .lineLimit(3)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
    }
}

/// Tells the user secrets were released without asking, with a way to stop.
/// Shaped like a notification banner.
public struct NoticeView: View {
    let active: AppModel.ActiveNotice
    let onStop: () -> Void
    let onDismiss: () -> Void

    public init(active: AppModel.ActiveNotice, onStop: @escaping () -> Void, onDismiss: @escaping () -> Void) {
        self.active = active
        self.onStop = onStop
        self.onDismiss = onDismiss
    }

    private var title: String {
        let names = active.notice.secrets
        if let site = active.notice.request.site {
            return "\(names.joined(separator: ", ")) was typed into \(host(site))"
        }
        return names.joined(separator: ", ") + (names.count == 1 ? " was used" : " were used")
    }

    private var status: String {
        if active.stopped { return "Stopped, and its session revoked" }
        if active.ended { return active.notice.request.site == nil ? "Command finished" : "Sign-in done" }
        return origin(active.notice.request)
    }

    public var body: some View {
        HStack(alignment: .top, spacing: 12) {
            AppIconView(size: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .lineLimit(2)
                Text(active.notice.request.site ?? active.notice.request.command)
                    .font(.system(size: 11.5, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                if active.ended || active.stopped {
                    Text(status)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    RequesterBadge(request: active.notice.request, compact: true)
                        .padding(.top, 2)
                }
            }
            Spacer(minLength: 8)
            if active.ended || active.stopped {
                Button("Dismiss", action: onDismiss)
            } else {
                // The label is coloured by hand: this panel is never the key
                // window, where the system would draw a destructive button grey.
                Button(role: .destructive, action: onStop) {
                    Text("Stop").foregroundStyle(.red)
                }
            }
        }
        .padding(12)
        .frame(width: 380)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(.separator, lineWidth: 0.5))
    }
}

public struct NoticeStack: View {
    @ObservedObject var model: AppModel

    public init(model: AppModel) {
        self.model = model
    }

    public var body: some View {
        VStack(spacing: 8) {
            ForEach(model.notices) { active in
                NoticeView(
                    active: active,
                    onStop: { model.stop(runId: active.id) },
                    onDismiss: { model.dismissNotice(runId: active.id) })
            }
        }
        .padding(8)
    }
}

/// Who is asking, large enough to notice: this Mac, or the other machine by
/// name, with its key's short id. Another machine is tinted, as a request
/// from elsewhere deserves a second look.
struct RequesterBadge: View {
    let request: RequestInfo
    var compact = false

    /// "build-vm (3f9a1c2e)" as the name and the id.
    private var parts: (name: String, key: String?) {
        let label = request.requester
        guard request.remote, label.hasSuffix(")"), let open = label.range(of: " (", options: .backwards) else {
            return (request.remote ? label : "This Mac", nil)
        }
        return (String(label[..<open.lowerBound]), String(label[open.upperBound...].dropLast()))
    }

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: request.remote ? "server.rack" : "laptopcomputer")
            Text(request.remote ? "From \(parts.name)" : "From this Mac")
                .font(.system(size: compact ? 12 : 13.5, weight: .semibold))
                .lineLimit(1)
            if let key = parts.key, !compact {
                Text(key).font(.caption.monospaced()).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, compact ? 7 : 9)
        .padding(.vertical, compact ? 2 : 4)
        .background(
            (request.remote ? Color.orange.opacity(0.16) : Color.secondary.opacity(0.12)),
            in: Capsule())
        .accessibilityElement(children: .combine)
    }
}
