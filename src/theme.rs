use ratatui::style::{Color, Modifier, Style};

// ─── Orange palette ──────────────────────────────────────────────

pub const ORANGE: Color = Color::Rgb(255, 140, 0);
pub const ORANGE_LIGHT: Color = Color::Rgb(255, 180, 80);
pub const ORANGE_DARK: Color = Color::Rgb(204, 85, 0);
pub const AMBER: Color = Color::Rgb(255, 191, 0);

// ─── Severity colours ────────────────────────────────────────────

pub const CRITICAL: Color = Color::Rgb(255, 69, 58);
pub const WARNING: Color = Color::Rgb(255, 214, 10);
pub const SAFE: Color = Color::Rgb(48, 209, 88);
pub const INFO: Color = Color::Rgb(100, 210, 255);

// ─── UI base ─────────────────────────────────────────────────────

pub const BG_DARK: Color = Color::Rgb(18, 18, 22);
pub const BG_PANEL: Color = Color::Rgb(28, 28, 34);
pub const TEXT: Color = Color::Rgb(230, 230, 230);
pub const TEXT_DIM: Color = Color::Rgb(120, 120, 135);
pub const BORDER: Color = Color::Rgb(55, 55, 65);

// ─── Style helpers ───────────────────────────────────────────────

pub fn title() -> Style {
    Style::default()
        .fg(ORANGE)
        .add_modifier(Modifier::BOLD)
}

pub fn header() -> Style {
    Style::default()
        .fg(ORANGE_LIGHT)
        .add_modifier(Modifier::BOLD)
}

pub fn label() -> Style {
    Style::default().fg(TEXT_DIM)
}

pub fn value() -> Style {
    Style::default().fg(TEXT)
}

pub fn risk_color(level: &crate::models::RiskLevel) -> Color {
    use crate::models::RiskLevel;
    match level {
        RiskLevel::Clean => SAFE,
        RiskLevel::Low => Color::Rgb(130, 200, 100),
        RiskLevel::Medium => WARNING,
        RiskLevel::High => ORANGE,
        RiskLevel::Critical => CRITICAL,
    }
}

pub fn api_risk_color(risk: &crate::models::ApiRisk) -> Color {
    use crate::models::ApiRisk;
    match risk {
        ApiRisk::Critical => CRITICAL,
        ApiRisk::High => ORANGE,
        ApiRisk::Medium => WARNING,
        ApiRisk::Low => INFO,
        ApiRisk::None => TEXT_DIM,
    }
}

pub fn severity_color(sev: &crate::models::AnomalySeverity) -> Color {
    use crate::models::AnomalySeverity;
    match sev {
        AnomalySeverity::Critical => CRITICAL,
        AnomalySeverity::Warning => WARNING,
        AnomalySeverity::Info => INFO,
    }
}
