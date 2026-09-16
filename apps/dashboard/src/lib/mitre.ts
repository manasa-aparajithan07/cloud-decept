/**
 * MITRE ATT&CK and CloudDecept Research Taxonomy Registry
 * Separates official ATT&CK Enterprise techniques from custom research extensions.
 */

export interface TaxonomyTechnique {
  id: string;
  name: string;
  tactic: string;
  isCustom: boolean;
  closestOfficial?: string;
  description: string;
  commonCommands?: string[];
}

export const TAXONOMY_REGISTRY: Record<string, TaxonomyTechnique> = {
  // Official MITRE ATT&CK Techniques
  'T1082': {
    id: 'T1082',
    name: 'System Information Discovery',
    tactic: 'Discovery',
    isCustom: false,
    description: 'Adversaries may attempt to get detailed information about the operating system and hardware, including version, patches, architecture, and configuration.',
    commonCommands: ['uname -a', 'cat /etc/os-release', 'cat /proc/version', 'lscpu', 'hostname', 'uptime'],
  },
  'T1033': {
    id: 'T1033',
    name: 'System Owner/User Discovery',
    tactic: 'Discovery',
    isCustom: false,
    description: 'Adversaries may attempt to identify the primary user, currently logged in user, prior users, or system privileges.',
    commonCommands: ['whoami', 'id', 'w', 'who', 'users', 'last'],
  },
  'T1087.001': {
    id: 'T1087.001',
    name: 'Account Discovery: Local Account',
    tactic: 'Discovery',
    isCustom: false,
    description: 'Adversaries may attempt to get a list of local system accounts.',
    commonCommands: ['id', 'cat /etc/passwd', 'cat /etc/group'],
  },
  'T1083': {
    id: 'T1083',
    name: 'File and Directory Discovery',
    tactic: 'Discovery',
    isCustom: false,
    description: 'Adversaries may enumerate files and directories or search specific locations of host systems.',
    commonCommands: ['ls -la', 'pwd', 'find /etc -maxdepth 1 -type f'],
  },
  'T1526': {
    id: 'T1526',
    name: 'Cloud Service Discovery',
    tactic: 'Discovery',
    isCustom: false,
    description: 'Adversaries may attempt to discover cloud services and infrastructure resources like compute instances.',
    commonCommands: ['aws ec2 describe-instances', 'describe-instances'],
  },
  'T1059': {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    isCustom: false,
    description: 'Adversaries may abuse Unix shell commands and scripting interpreters to execute malicious commands or scripts.',
    commonCommands: ['sh', 'bash', 'dash', '/bin/sh', 'python', 'perl'],
  },
  'T1110': {
    id: 'T1110',
    name: 'Brute Force / Password Guessing',
    tactic: 'Credential Access',
    isCustom: false,
    description: 'Adversaries may use brute force techniques to attempt authentication with common usernames and passwords.',
    commonCommands: ['SSH login attempts (root, admin, user, test, ubuntu)'],
  },
  'T1016': {
    id: 'T1016',
    name: 'System Network Configuration Discovery',
    tactic: 'Discovery',
    isCustom: false,
    description: 'Adversaries may look for details about the network configuration and interfaces to understand neighboring systems.',
    commonCommands: ['ifconfig', 'ip addr', 'ip route', 'netstat -rn', 'arp -a', 'route -n'],
  },
  'T1046': {
    id: 'T1046',
    name: 'Network Service Discovery',
    tactic: 'Discovery',
    isCustom: false,
    description: 'Adversaries may attempt to gather information about active network services using listening ports and scanners.',
    commonCommands: ['netstat -tuln', 'ss -tuln', 'nmap', 'nc -zv'],
  },
  'T1005': {
    id: 'T1005',
    name: 'Data from Local System',
    tactic: 'Collection',
    isCustom: false,
    description: 'Adversaries may search for and collect sensitive data, configuration files, and keys from the local system.',
    commonCommands: ['cat ~/.bash_history', 'cat ~/.ssh/id_rsa', 'find / -name "*.conf"'],
  },
  'T1053': {
    id: 'T1053',
    name: 'Scheduled Task/Job',
    tactic: 'Persistence',
    isCustom: false,
    description: 'Adversaries may abuse task scheduling systems like crontab to facilitate recurring malicious execution.',
    commonCommands: ['crontab -l', 'cat /etc/crontab', 'ls -la /etc/cron.*'],
  },
  'T1105': {
    id: 'T1105',
    name: 'Ingress Tool Transfer',
    tactic: 'Command and Control',
    isCustom: false,
    description: 'Adversaries may transfer tools or other files from an external system into a compromised environment.',
    commonCommands: ['wget http://...', 'curl -O http://...', 'tftp', 'ftp', 'scp'],
  },

  // Official MITRE ATT&CK Standard Mappings for Cloud API & Token Access
  'T1550.001': {
    id: 'T1550.001',
    name: 'Use Alternate Authentication Material: Application Access Token',
    tactic: 'Lateral Movement',
    isCustom: false,
    description: 'Adversaries may use application access tokens to bypass standard authentication processes and access resources.',
    commonCommands: ['aws sts get-caller-identity', 'assume-role'],
  },
  'T1059.009': {
    id: 'T1059.009',
    name: 'Command and Scripting Interpreter: Cloud API',
    tactic: 'Execution',
    isCustom: false,
    description: 'Adversaries may execute commands directly against cloud APIs or through cloud CLI tools.',
    commonCommands: ['aws ...', 'az ...', 'gcloud ...'],
  },
};

/**
 * Normalizes legacy/non-standard technique IDs to official MITRE ATT&CK standards.
 * Suppresses invalid IDs like T1550.007 and non-standard T1059.008.
 */
export function normalizeMitreId(id: string): string {
  if (!id) return '';
  const trimmed = id.trim();
  if (trimmed === 'T1550.007') return 'T1550.001';
  if (trimmed === 'T1059.008') return 'T1059.009';
  return trimmed;
}

export function getTechniqueInfo(id: string): TaxonomyTechnique {
  const normId = normalizeMitreId(id);
  if (TAXONOMY_REGISTRY[normId]) {
    return TAXONOMY_REGISTRY[normId];
  }
  // Fallback heuristic detection
  const isCustom = normId.startsWith('CUSTOM-');
  return {
    id: normId,
    name: normId,
    tactic: 'Discovery',
    isCustom,
    closestOfficial: isCustom ? 'T1059 (Execution) / T1082 (Discovery)' : undefined,
    description: isCustom
      ? 'Custom CloudDecept behavioral taxonomy identifier recorded by the research telemetry pipeline.'
      : 'Technique classified under MITRE ATT&CK framework.',
  };
}
