import SwiftUI

enum MnStatusKind {
    case success
    case warning
    case danger
    case neutral

    var color: Color {
        switch self {
        case .success: MnColor.success
        case .warning: MnColor.warning
        case .danger: MnColor.danger
        case .neutral: MnColor.textPrimary
        }
    }

    var symbol: String {
        switch self {
        case .success: "checkmark.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .danger: "xmark.octagon.fill"
        case .neutral: "circle.fill"
        }
    }
}

/// A words-first state treatment. Colour and symbol remain supplementary.
struct MnStatusLabel: View {
    let text: String
    let kind: MnStatusKind

    var body: some View {
        Label(text, systemImage: kind.symbol)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(kind.color)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Status: \(text)")
    }
}

struct MnPanel<Content: View>: View {
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .padding(MnSpacing.x4)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(MnColor.raised)
            .clipShape(RoundedRectangle(cornerRadius: MnRadius.large))
            .overlay {
                RoundedRectangle(cornerRadius: MnRadius.large)
                    .stroke(MnColor.border, lineWidth: 1)
            }
    }
}

struct MnSectionHeading: View {
    let title: String
    let orientation: String?

    init(_ title: String, orientation: String? = nil) {
        self.title = title
        self.orientation = orientation
    }

    var body: some View {
        VStack(alignment: .leading, spacing: MnSpacing.x2) {
            Text(title)
                .font(.title2.weight(.semibold))
            if let orientation {
                Text(orientation)
                    .font(.body)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

struct MnEvidenceRow: View {
    let label: String
    let value: String
    var monospaced = false

    var body: some View {
        VStack(alignment: .leading, spacing: MnSpacing.x1) {
            Text(label)
                .font(.caption)
                .foregroundStyle(MnColor.textPrimary)
            Text(value)
                .font(monospaced ? .system(.body, design: .monospaced) : .body)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }
}

struct MnPrimaryButton: View {
    let title: String
    let systemImage: String?
    let action: () -> Void

    init(_ title: String, systemImage: String? = nil, action: @escaping () -> Void) {
        self.title = title
        self.systemImage = systemImage
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Group {
                if let systemImage {
                    Label(title, systemImage: systemImage)
                } else {
                    Text(title)
                }
            }
            .font(.headline)
            .frame(maxWidth: .infinity, minHeight: MnMetrics.minimumTarget)
            .padding(.horizontal, MnSpacing.x4)
        }
        .buttonStyle(MnPrimaryButtonStyle())
        .accessibilityLabel(title)
    }
}

private struct MnPrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(MnColor.onBrand)
            .background(configuration.isPressed ? MnColor.actionPressed : MnColor.action)
            .clipShape(RoundedRectangle(cornerRadius: MnRadius.medium))
    }
}

struct MnEmptyState: View {
    let title: String
    let explanation: String
    let actionTitle: String?
    var action: (() -> Void)?

    var body: some View {
        MnPanel {
            VStack(alignment: .leading, spacing: MnSpacing.x3) {
                Text(title)
                    .font(.headline)
                    .fixedSize(horizontal: false, vertical: true)
                Text(explanation)
                    .font(.body)
                    .fixedSize(horizontal: false, vertical: true)
                if let actionTitle, let action {
                    Button(actionTitle, action: action)
                        .font(.headline)
                        .foregroundStyle(MnColor.action)
                        .frame(maxWidth: .infinity, minHeight: MnMetrics.minimumTarget)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

/// Restrained maker provenance for About/onboarding contexts only.
struct MnProvenance: View {
    var body: some View {
        VStack(alignment: .leading, spacing: MnSpacing.x2) {
            Image("MnemosyneBiosciencesLogo")
                .resizable()
                .scaledToFit()
                .frame(maxWidth: 216, maxHeight: 96, alignment: .leading)
                // The approved monochrome lock-up is reversed at render time
                // for the Mnemosyne provenance surface; its source asset stays
                // byte-for-byte identical to the branding authority.
                .colorInvert()
                .accessibilityHidden(true)
            Text("Pistis")
                .font(.title2.weight(.semibold))
        }
        .foregroundStyle(MnColor.onBrand)
        .padding(MnSpacing.x4)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(MnColor.provenance)
        .clipShape(RoundedRectangle(cornerRadius: MnRadius.large))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Pistis, by Mnemosyne Biosciences")
    }
}
