// Draws the app icon and writes Mayi.icns next to this file.
//   swift make-icon.swift
// The icon is the logo (assets/logo/mayi-glyph.svg) on a white plate.
import AppKit

let size: CGFloat = 1024
let here = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let glyphURL = here.appendingPathComponent("../../assets/logo/mayi-glyph.svg").standardizedFileURL
guard let glyph = NSImage(contentsOf: glyphURL) else {
    fatalError("cannot read \(glyphURL.path)")
}

let bitmap = NSBitmapImageRep(
    bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size), bitsPerSample: 8, samplesPerPixel: 4,
    hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)

// The plate, on Apple's icon grid: 824 points square with a soft shadow.
let plate = NSRect(x: 100, y: 100, width: 824, height: 824)
let shape = NSBezierPath(roundedRect: plate, xRadius: 185, yRadius: 185)
let shadow = NSShadow()
shadow.shadowColor = NSColor.black.withAlphaComponent(0.28)
shadow.shadowOffset = NSSize(width: 0, height: -10)
shadow.shadowBlurRadius = 22
NSGraphicsContext.saveGraphicsState()
shadow.set()
NSColor.white.setFill()
shape.fill()
NSGraphicsContext.restoreGraphicsState()
// White at the top easing to a cool light grey, as paper catches light.
NSGradient(starting: NSColor.white, ending: NSColor(srgbRed: 0.92, green: 0.93, blue: 0.96, alpha: 1))!
    .draw(in: shape, angle: -90)
let edge = NSBezierPath(roundedRect: plate.insetBy(dx: 1, dy: 1), xRadius: 184, yRadius: 184)
edge.lineWidth = 2
NSColor.black.withAlphaComponent(0.08).setStroke()
edge.stroke()

// The glyph is not centred on its own grid (the tail hangs below), so it is
// placed by its outline: 19 units wide from x 2.5, 18.1 tall from y 3.5.
let unit: CGFloat = 560 / 24
let outline = NSRect(x: 2.5 * unit, y: (24 - 21.6) * unit, width: 19 * unit, height: 18.1 * unit)
let origin = NSPoint(x: size / 2 - outline.midX, y: size / 2 - outline.midY - 6)
glyph.draw(in: NSRect(x: origin.x, y: origin.y, width: 24 * unit, height: 24 * unit))

NSGraphicsContext.current = nil
let iconset = FileManager.default.temporaryDirectory.appendingPathComponent("Mayi.iconset")
try? FileManager.default.removeItem(at: iconset)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
let master = iconset.appendingPathComponent("master.png")
try bitmap.representation(using: .png, properties: [:])!.write(to: master)

func run(_ tool: String, _ arguments: [String]) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: tool)
    process.arguments = arguments
    process.standardOutput = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
}

for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = scale == 1 ? "icon_\(points)x\(points).png" : "icon_\(points)x\(points)@2x.png"
        try run("/usr/bin/sips", ["-z", "\(points * scale)", "\(points * scale)", master.path, "--out", iconset.appendingPathComponent(name).path])
    }
}
if CommandLine.arguments.count > 1 {
    try? FileManager.default.removeItem(atPath: CommandLine.arguments[1])
    try FileManager.default.copyItem(at: master, to: URL(fileURLWithPath: CommandLine.arguments[1]))
}
try FileManager.default.removeItem(at: master)
try run("/usr/bin/iconutil", ["-c", "icns", iconset.path, "-o", here.appendingPathComponent("Mayi.icns").path])
print("wrote Mayi.icns")
