import AppKit
import SwiftUI

// What little the app defines for itself. Everything else is the system's:
// its fonts, its controls, its colours, its light and dark appearance.
// See docs/design-language.md.

enum Brand {
    /// The logo's blue. Controls use the system accent colour, not this.
    static let blue = Color(.sRGB, red: 0x1F / 255.0, green: 0x4F / 255.0, blue: 0xD8 / 255.0)
}

/// The logo: a speech bubble with a keyhole. A request, for access.
/// The geometry is `assets/logo/mayi-glyph.svg`, on its 24-unit grid.
struct MayiGlyph: Shape {
    func path(in rect: CGRect) -> Path {
        let side = min(rect.width, rect.height)
        let scale = side / 24
        let origin = CGPoint(x: rect.midX - side / 2, y: rect.midY - side / 2)
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: origin.x + x * scale, y: origin.y + y * scale)
        }
        func arc(_ path: inout Path, _ cx: CGFloat, _ cy: CGFloat, from: Double, to: Double, radius: CGFloat = 4.5) {
            path.addArc(
                center: p(cx, cy), radius: radius * scale, startAngle: .degrees(from), endAngle: .degrees(to),
                clockwise: false)
        }

        var path = Path()
        // The bubble, clockwise from its top edge, with the tail at bottom left.
        path.move(to: p(7, 3.5))
        path.addLine(to: p(17, 3.5))
        arc(&path, 17, 8, from: -90, to: 0)
        path.addLine(to: p(21.5, 13))
        arc(&path, 17, 13, from: 0, to: 90)
        path.addLine(to: p(11.6, 17.5))
        path.addQuadCurve(to: p(6.3, 21.6), control: p(9.8, 20.3))
        path.addQuadCurve(to: p(7, 17.5), control: p(7.3, 19.7))
        arc(&path, 7, 13, from: 90, to: 180)
        path.addLine(to: p(2.5, 8))
        arc(&path, 7, 8, from: 180, to: 270)
        path.closeSubpath()
        // The keyhole, cut out with the even-odd rule.
        path.move(to: p(13.2, 10.8))
        path.addLine(to: p(13.85, 14.3))
        path.addLine(to: p(10.15, 14.3))
        path.addLine(to: p(10.8, 10.8))
        arc(&path, 12, 8.9, from: 122.2, to: 417.8, radius: 2.25)
        path.closeSubpath()
        return path
    }

    /// The logo as a template image, for the menu bar.
    static func templateImage(side: CGFloat = 18) -> NSImage {
        let image = NSImage(size: NSSize(width: side, height: side), flipped: true) { bounds in
            guard let context = NSGraphicsContext.current?.cgContext else { return false }
            context.addPath(MayiGlyph().path(in: bounds).cgPath)
            context.setFillColor(NSColor.black.cgColor)
            context.fillPath(using: .evenOdd)
            return true
        }
        image.isTemplate = true
        return image
    }
}

/// The app icon, drawn small: the logo on its white plate.
struct AppIconView: View {
    var size: CGFloat = 48

    var body: some View {
        let plate = RoundedRectangle(cornerRadius: size * 0.225, style: .continuous)
        ZStack {
            plate.fill(LinearGradient(colors: [.white, Color(white: 0.93)], startPoint: .top, endPoint: .bottom))
            MayiGlyph()
                .fill(Brand.blue, style: FillStyle(eoFill: true))
                .padding(size * 0.2)
                .offset(y: -size * 0.012)
        }
        .frame(width: size, height: size)
        .overlay(plate.strokeBorder(Color.black.opacity(0.12), lineWidth: 0.5))
        .shadow(color: .black.opacity(0.18), radius: size * 0.04, y: size * 0.02)
        .accessibilityHidden(true)
    }
}

enum LevelInfo {
    static func name(_ level: UInt8) -> String {
        switch level {
        case 1: return "Log"
        case 2: return "Notify"
        case 3: return "Approve"
        case 4: return "Biometric"
        default: return "Level \(level)"
        }
    }

    static func detail(_ level: UInt8, login: Bool = false) -> String {
        switch (level, login) {
        case (1, false): return "Released silently and recorded in Activity."
        case (2, false): return "Released at once. You are notified and can stop the command."
        case (3, false): return "Held until you approve the command."
        case (4, false): return "Locked to this Mac\u{2019}s Secure Enclave. Every unlock needs Touch ID, your Apple Watch or your password."
        case (1, true): return "Typed in without asking, and recorded in Activity."
        case (2, true): return "Typed in at once. You are notified and can stop the session."
        case (3, true): return "Typed in once you approve the sign-in."
        case (4, true): return "Locked to this Mac\u{2019}s Secure Enclave. Every sign-in needs Touch ID, your Apple Watch or your password."
        default: return ""
        }
    }

    static func symbol(_ level: UInt8) -> String {
        switch level {
        case 1: return "list.bullet.rectangle"
        case 2: return "bell"
        case 3: return "hand.raised"
        default: return "touchid"
        }
    }
}

/// A level as the system would show it: its symbol and its name.
struct LevelLabel: View {
    let level: UInt8

    var body: some View {
        Label(LevelInfo.name(level), systemImage: LevelInfo.symbol(level))
            .labelStyle(.titleAndIcon)
            .accessibilityLabel("Level \(level), \(LevelInfo.name(level))")
    }
}

/// A command, a token or a key: literal, selectable, monospaced.
struct CodeWell: View {
    let text: String
    var lineLimit: Int? = nil

    var body: some View {
        Text(text)
            .font(.system(size: 12.5, design: .monospaced))
            .lineSpacing(2)
            .lineLimit(lineLimit)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(.separator, lineWidth: 0.5))
    }
}

func origin(_ request: RequestInfo) -> String {
    request.remote ? "From another machine, \(request.requester)" : "From this Mac"
}

/// The host of an origin such as `https://github.com`, with its port if it
/// has one, for a sentence.
func host(_ site: String) -> String {
    guard let url = URL(string: site), let host = url.host else { return site }
    return url.port.map { "\(host):\($0)" } ?? host
}

/// The fields of a sign-in, as words: "the username, password and two-factor code".
func fieldWords(_ fields: [String]) -> String {
    let words = fields.map { $0 == "totp" ? "two-factor code" : $0 }
    switch words.count {
    case 0: return "nothing"
    case 1: return "the \(words[0])"
    default: return "the " + words.dropLast().joined(separator: ", ") + " and \(words.last!)"
    }
}

/// A line of status under a list, like Finder's status bar. Hidden when empty.
struct StatusBar: View {
    let message: String?
    var isError = false

    var body: some View {
        if let message {
            VStack(spacing: 0) {
                Divider()
                Text(message)
                    .font(.callout)
                    .foregroundStyle(isError ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                    .lineLimit(2)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
            }
            .background(.bar)
        }
    }
}
