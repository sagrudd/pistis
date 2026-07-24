import SwiftUI

/// The reviewed Mnemosyne semantic colour contract for the Pistis iOS client.
///
/// Views consume these roles rather than introducing palette literals. The
/// first release deliberately supports only the reviewed light appearance.
enum MnColor {
    static let textPrimary = Color(red: 17 / 255, green: 17 / 255, blue: 17 / 255)
    static let canvas = Color(red: 246 / 255, green: 247 / 255, blue: 245 / 255)
    static let raised = Color.white
    static let provenance = Color(red: 28 / 255, green: 43 / 255, blue: 11 / 255)
    static let markLight = Color(red: 199 / 255, green: 191 / 255, blue: 168 / 255)
    static let markDark = Color(red: 79 / 255, green: 92 / 255, blue: 41 / 255)
    static let action = Color(red: 15 / 255, green: 107 / 255, blue: 120 / 255)
    static let actionPressed = Color(red: 11 / 255, green: 89 / 255, blue: 100 / 255)
    static let border = Color(red: 217 / 255, green: 224 / 255, blue: 227 / 255)
    static let success = Color(red: 40 / 255, green: 98 / 255, blue: 43 / 255)
    static let warning = Color(red: 111 / 255, green: 84 / 255, blue: 16 / 255)
    static let danger = Color(red: 138 / 255, green: 60 / 255, blue: 37 / 255)
    static let onBrand = Color.white
}

enum MnSpacing {
    static let x1: CGFloat = 4
    static let x2: CGFloat = 8
    static let x3: CGFloat = 12
    static let x4: CGFloat = 16
    static let x6: CGFloat = 24
    static let x8: CGFloat = 32
}

enum MnRadius {
    static let small: CGFloat = 4
    static let medium: CGFloat = 8
    static let large: CGFloat = 12
}

enum MnMetrics {
    static let minimumTarget: CGFloat = 44
    static let screenGutter: CGFloat = MnSpacing.x4
}

struct MnScreenBackground: ViewModifier {
    func body(content: Content) -> some View {
        content
            .foregroundStyle(MnColor.textPrimary)
            .background(MnColor.canvas.ignoresSafeArea())
    }
}

extension View {
    func mnScreenBackground() -> some View {
        modifier(MnScreenBackground())
    }
}
