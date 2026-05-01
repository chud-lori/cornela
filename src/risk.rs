use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    #[allow(dead_code)]
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskFinding {
    pub level: RiskLevel,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    pub findings: Vec<RiskFinding>,
}

impl RiskAssessment {
    pub fn new() -> Self {
        Self {
            level: RiskLevel::Low,
            findings: Vec::new(),
        }
    }

    pub fn add(&mut self, level: RiskLevel, message: impl Into<String>) {
        self.level = self.level.max(level);
        self.findings.push(RiskFinding {
            level,
            message: message.into(),
        });
    }

    pub fn add_info(&mut self, message: impl Into<String>) {
        self.findings.push(RiskFinding {
            level: RiskLevel::Low,
            message: message.into(),
        });
    }

    pub fn reasons(&self) -> Vec<String> {
        self.findings
            .iter()
            .map(|finding| finding.message.clone())
            .collect()
    }
}

impl Default for RiskAssessment {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assessment_escalates_to_highest_finding() {
        let mut assessment = RiskAssessment::new();

        assessment.add(RiskLevel::Medium, "medium finding");
        assessment.add(RiskLevel::High, "high finding");
        assessment.add_info("informational reason");

        assert_eq!(assessment.level, RiskLevel::High);
        assert_eq!(
            assessment.reasons(),
            vec![
                "medium finding".to_string(),
                "high finding".to_string(),
                "informational reason".to_string()
            ]
        );
    }
}
