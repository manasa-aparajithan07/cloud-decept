/**
 * Truthful Threat Assessment & Skill Level utility for CloudDecept Dashboard.
 * Maps backend skill_level (1-10) and severity strings to authentic SOC labels.
 * NEVER fabricates fake random scores or confusing 0/100 percentages.
 */

export interface ThreatAssessment {
  level: 'Critical' | 'High' | 'Medium' | 'Low' | 'Unclassified';
  label: string;
  badgeClass: string;
  badgeBg: string;
  badgeColor: string;
  description: string;
  skillLevelText: string;
  isHighRisk: boolean;
}

/**
 * Evaluates session threat level based on backend skill_level (1-10) or explicit severity string.
 * Mapping conforms to backend API:
 * 8-10: Critical
 * 5-7: High
 * 3-4: Medium
 * 1-2: Low
 * 0 / null: Unclassified
 */
export function evaluateThreat(skillLevel?: number | null, explicitSeverity?: string | null): ThreatAssessment {
  if (explicitSeverity && explicitSeverity.trim() !== '') {
    const sev = explicitSeverity.toLowerCase().trim();
    if (sev === 'critical') {
      return {
        level: 'Critical',
        label: 'Critical',
        badgeClass: 'bg-red-100 text-red-800 border-red-300',
        badgeBg: 'bg-red-100',
        badgeColor: 'text-red-800',
        description: 'Critical adversary capability with active privilege escalation or data tampering',
        skillLevelText: skillLevel ? `Skill ${skillLevel}/10` : 'Critical Severity',
        isHighRisk: true,
      };
    }
    if (sev === 'high') {
      return {
        level: 'High',
        label: 'High',
        badgeClass: 'bg-orange-100 text-orange-800 border-orange-300',
        badgeBg: 'bg-orange-100',
        badgeColor: 'text-orange-800',
        description: 'High threat session executing multi-stage reconnaissance or credential access',
        skillLevelText: skillLevel ? `Skill ${skillLevel}/10` : 'High Severity',
        isHighRisk: true,
      };
    }
    if (sev === 'medium') {
      return {
        level: 'Medium',
        label: 'Medium',
        badgeClass: 'bg-amber-100 text-amber-800 border-amber-300',
        badgeBg: 'bg-amber-100',
        badgeColor: 'text-amber-800',
        description: 'Moderate adversary probing system enumeration and environment discovery',
        skillLevelText: skillLevel ? `Skill ${skillLevel}/10` : 'Medium Severity',
        isHighRisk: false,
      };
    }
    if (sev === 'low') {
      return {
        level: 'Low',
        label: 'Low',
        badgeClass: 'bg-emerald-100 text-emerald-800 border-emerald-300',
        badgeBg: 'bg-emerald-100',
        badgeColor: 'text-emerald-800',
        description: 'Low threat automated scanning or basic command probing',
        skillLevelText: skillLevel ? `Skill ${skillLevel}/10` : 'Low Severity',
        isHighRisk: false,
      };
    }
  }

  // Evaluate via numeric skill_level
  const score = typeof skillLevel === 'number' && !isNaN(skillLevel) ? skillLevel : 0;

  if (score >= 8) {
    return {
      level: 'Critical',
      label: 'Critical',
      badgeClass: 'bg-red-100 text-red-800 border-red-300',
      badgeBg: 'bg-red-100',
      badgeColor: 'text-red-800',
      description: `Skill rating ${score}/10: Advanced targeted threat sequences detected`,
      skillLevelText: `Skill ${score}/10`,
      isHighRisk: true,
    };
  }

  if (score >= 5) {
    return {
      level: 'High',
      label: 'High',
      badgeClass: 'bg-orange-100 text-orange-800 border-orange-300',
      badgeBg: 'bg-orange-100',
      badgeColor: 'text-orange-800',
      description: `Skill rating ${score}/10: Focused adversary reconnaissance or credential harvesting`,
      skillLevelText: `Skill ${score}/10`,
      isHighRisk: true,
    };
  }

  if (score >= 3) {
    return {
      level: 'Medium',
      label: 'Medium',
      badgeClass: 'bg-amber-100 text-amber-800 border-amber-300',
      badgeBg: 'bg-amber-100',
      badgeColor: 'text-amber-800',
      description: `Skill rating ${score}/10: Semi-automated probing or basic discovery commands`,
      skillLevelText: `Skill ${score}/10`,
      isHighRisk: false,
    };
  }

  if (score >= 1) {
    return {
      level: 'Low',
      label: 'Low',
      badgeClass: 'bg-emerald-100 text-emerald-800 border-emerald-300',
      badgeBg: 'bg-emerald-100',
      badgeColor: 'text-emerald-800',
      description: `Skill rating ${score}/10: Automated botnet scanner or scripted worm activity`,
      skillLevelText: `Skill ${score}/10`,
      isHighRisk: false,
    };
  }

  return {
    level: 'Unclassified',
    label: 'Unclassified',
    badgeClass: 'bg-gray-100 text-gray-700 border-gray-200',
    badgeBg: 'bg-gray-100',
    badgeColor: 'text-gray-700',
    description: 'No threat skill assessment available for this session',
    skillLevelText: 'Not Assessed',
    isHighRisk: false,
  };
}
