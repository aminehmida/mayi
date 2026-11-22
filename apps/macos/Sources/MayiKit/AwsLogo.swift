import AppKit
import SwiftUI

/// The AWS logo, marking AWS sign-ins: the wordmark in the text colour, so
/// it reads in dark mode too, and the smile in AWS orange. Drawn from the
/// logo's vector outline (304 by 182), so it is sharp at any size.
struct AwsLogo: View {
    var body: some View {
        ZStack {
            AwsLogoPart.wordmark.fill(.primary, style: FillStyle(eoFill: true))
            AwsLogoPart.smile.fill(Color(red: 1, green: 0.6, blue: 0), style: FillStyle(eoFill: true))
        }
        .aspectRatio(304.0 / 182.0, contentMode: .fit)
        .accessibilityElement()
        .accessibilityLabel("AWS")
    }
}

/// What the Add dialog adds.
public enum AddKind: Hashable {
    case secret, login, aws
}

/// The logo as a template image, for menus, which show only images: it
/// takes the menu's text colour.
@MainActor
enum AwsLogoImage {
    static let template: NSImage = {
        let renderer = ImageRenderer(content: AwsLogo().foregroundStyle(.black).frame(width: 23, height: 14))
        renderer.scale = 2
        let image = renderer.nsImage ?? NSImage()
        image.isTemplate = true
        return image
    }()
}

/// The Type choice of the Add dialog.
struct AddKindPicker: View {
    @Binding var kind: AddKind
    /// Whether AWS Sign-In is offered (only when adding).
    var offersAws = true

    var body: some View {
        Picker("Type", selection: $kind) {
            Label("Secret", systemImage: "key").tag(AddKind.secret)
            Label("Website Login", systemImage: "globe").tag(AddKind.login)
            if offersAws {
                Label { Text("AWS Sign-In") } icon: { Image(nsImage: AwsLogoImage.template) }.tag(AddKind.aws)
            }
        }
    }
}

private enum AwsLogoPart: Shape {
    case wordmark, smile

    func path(in rect: CGRect) -> Path {
        var p = Path()
        switch self {
        case .wordmark: Self.wordmark(&p)
        case .smile: Self.smile(&p)
        }
        let scale = min(rect.width / 304, rect.height / 182)
        let move = CGAffineTransform(translationX: rect.midX - 152 * scale, y: rect.midY - 91 * scale)
        return p.applying(move.scaledBy(x: scale, y: scale))
    }

    private static func wordmark(_ p: inout Path) {
        p.move(to: CGPoint(x: 86.4, y: 66.4))
        p.addCurve(to: CGPoint(x: 87.5, y: 75.3), control1: CGPoint(x: 86.4, y: 70.1), control2: CGPoint(x: 86.8, y: 73.1))
        p.addCurve(to: CGPoint(x: 90.7, y: 82.5), control1: CGPoint(x: 88.3, y: 77.5), control2: CGPoint(x: 89.3, y: 79.9))
        p.addCurve(to: CGPoint(x: 91.4, y: 84.8), control1: CGPoint(x: 91.2, y: 83.3), control2: CGPoint(x: 91.4, y: 84.1))
        p.addCurve(to: CGPoint(x: 89.5, y: 87.8), control1: CGPoint(x: 91.4, y: 85.8), control2: CGPoint(x: 90.8, y: 86.8))
        p.addLine(to: CGPoint(x: 83.2, y: 92))
        p.addCurve(to: CGPoint(x: 80.6, y: 92.9), control1: CGPoint(x: 82.3, y: 92.6), control2: CGPoint(x: 81.4, y: 92.9))
        p.addCurve(to: CGPoint(x: 77.6, y: 91.5), control1: CGPoint(x: 79.6, y: 92.9), control2: CGPoint(x: 78.6, y: 92.4))
        p.addCurve(to: CGPoint(x: 74, y: 86.8), control1: CGPoint(x: 76.2, y: 90), control2: CGPoint(x: 75, y: 88.4))
        p.addCurve(to: CGPoint(x: 70.9, y: 80.9), control1: CGPoint(x: 73, y: 85.1), control2: CGPoint(x: 72, y: 83.2))
        p.addCurve(to: CGPoint(x: 41.5, y: 94.7), control1: CGPoint(x: 63.1, y: 90.1), control2: CGPoint(x: 53.3, y: 94.7))
        p.addCurve(to: CGPoint(x: 21.5, y: 87.5), control1: CGPoint(x: 33.1, y: 94.7), control2: CGPoint(x: 26.4, y: 92.3))
        p.addCurve(to: CGPoint(x: 14.1, y: 68.3), control1: CGPoint(x: 16.6, y: 82.7), control2: CGPoint(x: 14.1, y: 76.3))
        p.addCurve(to: CGPoint(x: 23.2, y: 47.7), control1: CGPoint(x: 14.1, y: 59.8), control2: CGPoint(x: 17.1, y: 52.9))
        p.addCurve(to: CGPoint(x: 47.7, y: 39.9), control1: CGPoint(x: 29.3, y: 42.5), control2: CGPoint(x: 37.4, y: 39.9))
        p.addCurve(to: CGPoint(x: 58.3, y: 40.7), control1: CGPoint(x: 51.1, y: 39.9), control2: CGPoint(x: 54.6, y: 40.2))
        p.addCurve(to: CGPoint(x: 69.8, y: 42.9), control1: CGPoint(x: 62, y: 41.2), control2: CGPoint(x: 65.8, y: 42))
        p.addLine(to: CGPoint(x: 69.8, y: 35.6))
        p.addCurve(to: CGPoint(x: 65.1, y: 19.6), control1: CGPoint(x: 69.8, y: 28), control2: CGPoint(x: 68.2, y: 22.7))
        p.addCurve(to: CGPoint(x: 48.8, y: 15), control1: CGPoint(x: 61.9, y: 16.5), control2: CGPoint(x: 56.5, y: 15))
        p.addCurve(to: CGPoint(x: 38, y: 16.3), control1: CGPoint(x: 45.3, y: 15), control2: CGPoint(x: 41.7, y: 15.4))
        p.addCurve(to: CGPoint(x: 27.2, y: 19.7), control1: CGPoint(x: 34.3, y: 17.2), control2: CGPoint(x: 30.7, y: 18.3))
        p.addCurve(to: CGPoint(x: 23.7, y: 21), control1: CGPoint(x: 25.6, y: 20.4), control2: CGPoint(x: 24.4, y: 20.8))
        p.addCurve(to: CGPoint(x: 22.1, y: 21.3), control1: CGPoint(x: 23, y: 21.2), control2: CGPoint(x: 22.5, y: 21.3))
        p.addCurve(to: CGPoint(x: 20, y: 18.2), control1: CGPoint(x: 20.7, y: 21.3), control2: CGPoint(x: 20, y: 20.3))
        p.addLine(to: CGPoint(x: 20, y: 13.3))
        p.addCurve(to: CGPoint(x: 20.7, y: 9.8), control1: CGPoint(x: 20, y: 11.7), control2: CGPoint(x: 20.2, y: 10.5))
        p.addCurve(to: CGPoint(x: 23.5, y: 7.7), control1: CGPoint(x: 21.2, y: 9.1), control2: CGPoint(x: 22.1, y: 8.4))
        p.addCurve(to: CGPoint(x: 36.1, y: 3.2), control1: CGPoint(x: 27, y: 5.9), control2: CGPoint(x: 31.2, y: 4.4))
        p.addCurve(to: CGPoint(x: 51.7, y: 1.3), control1: CGPoint(x: 41, y: 1.9), control2: CGPoint(x: 46.2, y: 1.3))
        p.addCurve(to: CGPoint(x: 77.9, y: 9.4), control1: CGPoint(x: 63.6, y: 1.3), control2: CGPoint(x: 72.3, y: 4))
        p.addCurve(to: CGPoint(x: 86.2, y: 34), control1: CGPoint(x: 83.4, y: 14.8), control2: CGPoint(x: 86.2, y: 23))
        p.addLine(to: CGPoint(x: 86.2, y: 66.4))
        p.closeSubpath()
        p.move(to: CGPoint(x: 45.8, y: 81.6))
        p.addCurve(to: CGPoint(x: 56.1, y: 79.8), control1: CGPoint(x: 49.1, y: 81.6), control2: CGPoint(x: 52.5, y: 81))
        p.addCurve(to: CGPoint(x: 65.6, y: 73.4), control1: CGPoint(x: 59.7, y: 78.6), control2: CGPoint(x: 62.9, y: 76.4))
        p.addCurve(to: CGPoint(x: 69, y: 67), control1: CGPoint(x: 67.2, y: 71.5), control2: CGPoint(x: 68.4, y: 69.4))
        p.addCurve(to: CGPoint(x: 70, y: 58.3), control1: CGPoint(x: 69.6, y: 64.6), control2: CGPoint(x: 70, y: 61.7))
        p.addLine(to: CGPoint(x: 70, y: 54.1))
        p.addCurve(to: CGPoint(x: 60.8, y: 52.4), control1: CGPoint(x: 67.1, y: 53.4), control2: CGPoint(x: 64, y: 52.8))
        p.addCurve(to: CGPoint(x: 51.4, y: 51.8), control1: CGPoint(x: 57.6, y: 52), control2: CGPoint(x: 54.5, y: 51.8))
        p.addCurve(to: CGPoint(x: 36.5, y: 55.8), control1: CGPoint(x: 44.7, y: 51.8), control2: CGPoint(x: 39.8, y: 53.1))
        p.addCurve(to: CGPoint(x: 31.6, y: 67.3), control1: CGPoint(x: 33.2, y: 58.5), control2: CGPoint(x: 31.6, y: 62.3))
        p.addCurve(to: CGPoint(x: 35.3, y: 77.9), control1: CGPoint(x: 31.6, y: 72), control2: CGPoint(x: 32.8, y: 75.5))
        p.addCurve(to: CGPoint(x: 45.8, y: 81.6), control1: CGPoint(x: 37.7, y: 80.4), control2: CGPoint(x: 41.2, y: 81.6))
        p.closeSubpath()
        p.move(to: CGPoint(x: 126.1, y: 92.4))
        p.addCurve(to: CGPoint(x: 122.3, y: 91.4), control1: CGPoint(x: 124.3, y: 92.4), control2: CGPoint(x: 123.1, y: 92.1))
        p.addCurve(to: CGPoint(x: 120.2, y: 87.5), control1: CGPoint(x: 121.5, y: 90.8), control2: CGPoint(x: 120.8, y: 89.4))
        p.addLine(to: CGPoint(x: 96.7, y: 10.2))
        p.addCurve(to: CGPoint(x: 95.8, y: 6.2), control1: CGPoint(x: 96.1, y: 8.2), control2: CGPoint(x: 95.8, y: 6.9))
        p.addCurve(to: CGPoint(x: 98.2, y: 3.7), control1: CGPoint(x: 95.8, y: 4.6), control2: CGPoint(x: 96.6, y: 3.7))
        p.addLine(to: CGPoint(x: 108, y: 3.7))
        p.addCurve(to: CGPoint(x: 111.9, y: 4.7), control1: CGPoint(x: 109.9, y: 3.7), control2: CGPoint(x: 111.2, y: 4))
        p.addCurve(to: CGPoint(x: 113.9, y: 8.6), control1: CGPoint(x: 112.7, y: 5.3), control2: CGPoint(x: 113.3, y: 6.7))
        p.addLine(to: CGPoint(x: 130.7, y: 74.8))
        p.addLine(to: CGPoint(x: 146.3, y: 8.6))
        p.addCurve(to: CGPoint(x: 148.2, y: 4.7), control1: CGPoint(x: 146.8, y: 6.6), control2: CGPoint(x: 147.4, y: 5.3))
        p.addCurve(to: CGPoint(x: 152.2, y: 3.7), control1: CGPoint(x: 149, y: 4.1), control2: CGPoint(x: 150.4, y: 3.7))
        p.addLine(to: CGPoint(x: 160.2, y: 3.7))
        p.addCurve(to: CGPoint(x: 164.2, y: 4.7), control1: CGPoint(x: 162.1, y: 3.7), control2: CGPoint(x: 163.4, y: 4))
        p.addCurve(to: CGPoint(x: 166.1, y: 8.6), control1: CGPoint(x: 165, y: 5.3), control2: CGPoint(x: 165.7, y: 6.7))
        p.addLine(to: CGPoint(x: 181.9, y: 75.6))
        p.addLine(to: CGPoint(x: 199.2, y: 8.6))
        p.addCurve(to: CGPoint(x: 201.2, y: 4.7), control1: CGPoint(x: 199.8, y: 6.6), control2: CGPoint(x: 200.5, y: 5.3))
        p.addCurve(to: CGPoint(x: 205.1, y: 3.7), control1: CGPoint(x: 202, y: 4.1), control2: CGPoint(x: 203.3, y: 3.7))
        p.addLine(to: CGPoint(x: 214.4, y: 3.7))
        p.addCurve(to: CGPoint(x: 216.9, y: 6.2), control1: CGPoint(x: 216, y: 3.7), control2: CGPoint(x: 216.9, y: 4.5))
        p.addCurve(to: CGPoint(x: 216.7, y: 7.8), control1: CGPoint(x: 216.9, y: 6.7), control2: CGPoint(x: 216.8, y: 7.2))
        p.addCurve(to: CGPoint(x: 216, y: 10.3), control1: CGPoint(x: 216.6, y: 8.4), control2: CGPoint(x: 216.4, y: 9.2))
        p.addLine(to: CGPoint(x: 191.9, y: 87.6))
        p.addCurve(to: CGPoint(x: 189.8, y: 91.5), control1: CGPoint(x: 191.3, y: 89.6), control2: CGPoint(x: 190.6, y: 90.9))
        p.addCurve(to: CGPoint(x: 186, y: 92.5), control1: CGPoint(x: 189, y: 92.1), control2: CGPoint(x: 187.7, y: 92.5))
        p.addLine(to: CGPoint(x: 177.4, y: 92.5))
        p.addCurve(to: CGPoint(x: 173.4, y: 91.5), control1: CGPoint(x: 175.5, y: 92.5), control2: CGPoint(x: 174.2, y: 92.2))
        p.addCurve(to: CGPoint(x: 171.5, y: 87.5), control1: CGPoint(x: 172.6, y: 90.8), control2: CGPoint(x: 171.9, y: 89.5))
        p.addLine(to: CGPoint(x: 156, y: 23))
        p.addLine(to: CGPoint(x: 140.6, y: 87.4))
        p.addCurve(to: CGPoint(x: 138.7, y: 91.4), control1: CGPoint(x: 140.1, y: 89.4), control2: CGPoint(x: 139.5, y: 90.7))
        p.addCurve(to: CGPoint(x: 134.7, y: 92.4), control1: CGPoint(x: 137.9, y: 92.1), control2: CGPoint(x: 136.5, y: 92.4))
        p.addLine(to: CGPoint(x: 126.1, y: 92.4))
        p.closeSubpath()
        p.move(to: CGPoint(x: 254.6, y: 95.1))
        p.addCurve(to: CGPoint(x: 239.2, y: 93.3), control1: CGPoint(x: 249.4, y: 95.1), control2: CGPoint(x: 244.2, y: 94.5))
        p.addCurve(to: CGPoint(x: 227.7, y: 89.3), control1: CGPoint(x: 234.2, y: 92.1), control2: CGPoint(x: 230.3, y: 90.8))
        p.addCurve(to: CGPoint(x: 224.6, y: 86.5), control1: CGPoint(x: 226.1, y: 88.4), control2: CGPoint(x: 225, y: 87.4))
        p.addCurve(to: CGPoint(x: 224, y: 83.7), control1: CGPoint(x: 224.2, y: 85.6), control2: CGPoint(x: 224, y: 84.6))
        p.addLine(to: CGPoint(x: 224, y: 78.6))
        p.addCurve(to: CGPoint(x: 226.3, y: 75.5), control1: CGPoint(x: 224, y: 76.5), control2: CGPoint(x: 224.8, y: 75.5))
        p.addCurve(to: CGPoint(x: 228.1, y: 75.8), control1: CGPoint(x: 226.9, y: 75.5), control2: CGPoint(x: 227.5, y: 75.6))
        p.addCurve(to: CGPoint(x: 230.6, y: 76.8), control1: CGPoint(x: 228.7, y: 76), control2: CGPoint(x: 229.6, y: 76.4))
        p.addCurve(to: CGPoint(x: 241.6, y: 80.3), control1: CGPoint(x: 234, y: 78.3), control2: CGPoint(x: 237.7, y: 79.5))
        p.addCurve(to: CGPoint(x: 253.5, y: 81.5), control1: CGPoint(x: 245.6, y: 81.1), control2: CGPoint(x: 249.5, y: 81.5))
        p.addCurve(to: CGPoint(x: 268.1, y: 78.2), control1: CGPoint(x: 259.8, y: 81.5), control2: CGPoint(x: 264.7, y: 80.4))
        p.addCurve(to: CGPoint(x: 273.3, y: 68.7), control1: CGPoint(x: 271.5, y: 76), control2: CGPoint(x: 273.3, y: 72.8))
        p.addCurve(to: CGPoint(x: 270.6, y: 61.7), control1: CGPoint(x: 273.3, y: 65.9), control2: CGPoint(x: 272.4, y: 63.6))
        p.addCurve(to: CGPoint(x: 260.5, y: 56.5), control1: CGPoint(x: 268.8, y: 59.8), control2: CGPoint(x: 265.4, y: 58.1))
        p.addLine(to: CGPoint(x: 246, y: 52))
        p.addCurve(to: CGPoint(x: 230, y: 41.8), control1: CGPoint(x: 238.7, y: 49.7), control2: CGPoint(x: 233.3, y: 46.3))
        p.addCurve(to: CGPoint(x: 225, y: 27.3), control1: CGPoint(x: 226.7, y: 37.4), control2: CGPoint(x: 225, y: 32.5))
        p.addCurve(to: CGPoint(x: 227.7, y: 16.2), control1: CGPoint(x: 225, y: 23.1), control2: CGPoint(x: 225.9, y: 19.4))
        p.addCurve(to: CGPoint(x: 234.9, y: 8), control1: CGPoint(x: 229.5, y: 13), control2: CGPoint(x: 231.9, y: 10.2))
        p.addCurve(to: CGPoint(x: 245.3, y: 2.8), control1: CGPoint(x: 237.9, y: 5.7), control2: CGPoint(x: 241.3, y: 4))
        p.addCurve(to: CGPoint(x: 257.9, y: 1.1), control1: CGPoint(x: 249.3, y: 1.6), control2: CGPoint(x: 253.5, y: 1.1))
        p.addCurve(to: CGPoint(x: 264.6, y: 1.5), control1: CGPoint(x: 260.1, y: 1.1), control2: CGPoint(x: 262.4, y: 1.2))
        p.addCurve(to: CGPoint(x: 271.1, y: 2.6), control1: CGPoint(x: 266.9, y: 1.8), control2: CGPoint(x: 269, y: 2.2))
        p.addCurve(to: CGPoint(x: 276.8, y: 4.2), control1: CGPoint(x: 273.1, y: 3.1), control2: CGPoint(x: 275, y: 3.6))
        p.addCurve(to: CGPoint(x: 281, y: 6), control1: CGPoint(x: 278.6, y: 4.8), control2: CGPoint(x: 280, y: 5.4))
        p.addCurve(to: CGPoint(x: 284, y: 8.5), control1: CGPoint(x: 282.4, y: 6.8), control2: CGPoint(x: 283.4, y: 7.6))
        p.addCurve(to: CGPoint(x: 284.9, y: 11.8), control1: CGPoint(x: 284.6, y: 9.3), control2: CGPoint(x: 284.9, y: 10.4))
        p.addLine(to: CGPoint(x: 284.9, y: 16.5))
        p.addCurve(to: CGPoint(x: 282.6, y: 19.7), control1: CGPoint(x: 284.9, y: 18.6), control2: CGPoint(x: 284.1, y: 19.7))
        p.addCurve(to: CGPoint(x: 278.8, y: 18.5), control1: CGPoint(x: 281.8, y: 19.7), control2: CGPoint(x: 280.5, y: 19.3))
        p.addCurve(to: CGPoint(x: 259.6, y: 14.6), control1: CGPoint(x: 273.1, y: 15.9), control2: CGPoint(x: 266.7, y: 14.6))
        p.addCurve(to: CGPoint(x: 246.3, y: 17.4), control1: CGPoint(x: 253.9, y: 14.6), control2: CGPoint(x: 249.4, y: 15.5))
        p.addCurve(to: CGPoint(x: 241.6, y: 26.3), control1: CGPoint(x: 243.2, y: 19.3), control2: CGPoint(x: 241.6, y: 22.2))
        p.addCurve(to: CGPoint(x: 244.6, y: 33.4), control1: CGPoint(x: 241.6, y: 29.1), control2: CGPoint(x: 242.6, y: 31.5))
        p.addCurve(to: CGPoint(x: 255.6, y: 38.9), control1: CGPoint(x: 246.6, y: 35.3), control2: CGPoint(x: 250.3, y: 37.2))
        p.addLine(to: CGPoint(x: 269.8, y: 43.4))
        p.addCurve(to: CGPoint(x: 285.3, y: 53), control1: CGPoint(x: 277, y: 45.7), control2: CGPoint(x: 282.2, y: 48.9))
        p.addCurve(to: CGPoint(x: 289.9, y: 67), control1: CGPoint(x: 288.4, y: 57.1), control2: CGPoint(x: 289.9, y: 61.8))
        p.addCurve(to: CGPoint(x: 287.3, y: 78.6), control1: CGPoint(x: 289.9, y: 71.3), control2: CGPoint(x: 289, y: 75.2))
        p.addCurve(to: CGPoint(x: 280, y: 87.4), control1: CGPoint(x: 285.5, y: 82), control2: CGPoint(x: 283.1, y: 85))
        p.addCurve(to: CGPoint(x: 268.9, y: 93), control1: CGPoint(x: 276.9, y: 89.9), control2: CGPoint(x: 273.2, y: 91.7))
        p.addCurve(to: CGPoint(x: 254.6, y: 95.1), control1: CGPoint(x: 264.4, y: 94.4), control2: CGPoint(x: 259.7, y: 95.1))
        p.closeSubpath()
    }

    private static func smile(_ p: inout Path) {
        p.move(to: CGPoint(x: 273.5, y: 143.7))
        p.addCurve(to: CGPoint(x: 151.7, y: 180.9), control1: CGPoint(x: 240.6, y: 168), control2: CGPoint(x: 192.8, y: 180.9))
        p.addCurve(to: CGPoint(x: 3, y: 124.2), control1: CGPoint(x: 94.1, y: 180.9), control2: CGPoint(x: 42.2, y: 159.6))
        p.addCurve(to: CGPoint(x: 6.4, y: 119.8), control1: CGPoint(x: -0.1, y: 121.4), control2: CGPoint(x: 2.7, y: 117.6))
        p.addCurve(to: CGPoint(x: 155.2, y: 159.3), control1: CGPoint(x: 48.8, y: 144.4), control2: CGPoint(x: 101.1, y: 159.3))
        p.addCurve(to: CGPoint(x: 268.7, y: 136.1), control1: CGPoint(x: 191.7, y: 159.3), control2: CGPoint(x: 231.8, y: 151.7))
        p.addCurve(to: CGPoint(x: 273.5, y: 143.7), control1: CGPoint(x: 274.2, y: 133.6), control2: CGPoint(x: 278.9, y: 139.7))
        p.closeSubpath()
        p.move(to: CGPoint(x: 287.2, y: 128.1))
        p.addCurve(to: CGPoint(x: 248.7, y: 126.8), control1: CGPoint(x: 283, y: 122.7), control2: CGPoint(x: 259.4, y: 125.5))
        p.addCurve(to: CGPoint(x: 247.9, y: 122.3), control1: CGPoint(x: 245.5, y: 127.2), control2: CGPoint(x: 245, y: 124.4))
        p.addCurve(to: CGPoint(x: 301.2, y: 117.3), control1: CGPoint(x: 266.7, y: 109.1), control2: CGPoint(x: 297.6, y: 112.9))
        p.addCurve(to: CGPoint(x: 282.6, y: 167.5), control1: CGPoint(x: 304.8, y: 121.8), control2: CGPoint(x: 300.2, y: 152.7))
        p.addCurve(to: CGPoint(x: 278.5, y: 165.6), control1: CGPoint(x: 279.9, y: 169.8), control2: CGPoint(x: 277.3, y: 168.6))
        p.addCurve(to: CGPoint(x: 287.2, y: 128.1), control1: CGPoint(x: 282.5, y: 155.7), control2: CGPoint(x: 291.4, y: 133.4))
        p.closeSubpath()
    }
}
