/**
 * Virus Scan Pro - Internal Rule Engine
 * Suspicious pattern detection rules
 */

export const SECURITY_RULES = [
    {
        id: 'RULE-001',
        name: 'Extension Signature Mismatch',
        severity: 'HIGH',
        description: 'File extension does not match detected file format',
        category: 'spoofing'
    },
    {
        id: 'RULE-002',
        name: 'High Entropy Detected',
        severity: 'MEDIUM',
        description: 'File contains high entropy data, possibly compressed, encrypted, or packed',
        category: 'entropy'
    },
    {
        id: 'RULE-003',
        name: 'Suspicious PowerShell Command',
        severity: 'HIGH',
        description: 'File contains suspicious PowerShell command patterns',
        category: 'script'
    },
    {
        id: 'RULE-004',
        name: 'Suspicious Command Shell',
        severity: 'HIGH',
        description: 'File contains suspicious cmd.exe or shell command patterns',
        category: 'script'
    },
    {
        id: 'RULE-005',
        name: 'Encoded Command Pattern',
        severity: 'MEDIUM',
        description: 'File contains encoded command strings (base64, hex encoding)',
        category: 'encoding'
    },
    {
        id: 'RULE-006',
        name: 'Executable in Non-Executable File',
        severity: 'HIGH',
        description: 'Executable content found in non-executable file type',
        category: 'structure'
    },
    {
        id: 'RULE-007',
        name: 'Suspicious URL Detected',
        severity: 'MEDIUM',
        description: 'File contains suspicious or known malicious URL patterns',
        category: 'network'
    },
    {
        id: 'RULE-008',
        name: 'Autorun Reference',
        severity: 'MEDIUM',
        description: 'File contains autorun or persistence mechanism references',
        category: 'persistence'
    },
    {
        id: 'RULE-009',
        name: 'Registry Modification Reference',
        severity: 'MEDIUM',
        description: 'File contains registry key modification references',
        category: 'persistence'
    },
    {
        id: 'RULE-010',
        name: 'Suspicious PE Characteristics',
        severity: 'HIGH',
        description: 'PE file has suspicious section characteristics or imports',
        category: 'pe'
    },
    {
        id: 'RULE-011',
        name: 'High-Risk Extension',
        severity: 'LOW',
        description: 'File has a high-risk extension (exe, dll, bat, ps1, etc.)',
        category: 'extension'
    },
    {
        id: 'RULE-012',
        name: 'Archive with Executable',
        severity: 'MEDIUM',
        description: 'Archive contains executable files',
        category: 'archive'
    },
    {
        id: 'RULE-013',
        name: 'Nested Archive',
        severity: 'MEDIUM',
        description: 'Archive contains another archive (potential archive bomb)',
        category: 'archive'
    },
    {
        id: 'RULE-014',
        name: 'Suspicious Process Injection',
        severity: 'HIGH',
        description: 'File contains process injection API references',
        category: 'api'
    },
    {
        id: 'RULE-015',
        name: 'Anti-Debugging Techniques',
        severity: 'HIGH',
        description: 'File contains anti-debugging or evasion techniques',
        category: 'evasion'
    }
];

/**
 * Run rule-based analysis on file data
 */
export function runRuleEngine(fileData, analysisResults) {
    const triggeredRules = [];
    
    const {
        filename,
        extension,
        detectedType,
        isSpoofed,
        entropy,
        strings,
        iocs,
        peData
    } = analysisResults;
    
    // Rule 001: Extension Signature Mismatch
    if (isSpoofed) {
        triggeredRules.push({
            ...SECURITY_RULES[0],
            details: `Extension: .${extension}, Detected: ${detectedType}`
        });
    }
    
    // Rule 002: High Entropy
    if (entropy > 7.5) {
        triggeredRules.push({
            ...SECURITY_RULES[1],
            details: `Entropy: ${entropy.toFixed(2)}`
        });
    }
    
    // Rule 003: Suspicious PowerShell
    const powerShellPatterns = [
        /powershell\s+-[eE][cC]/i,
        /powershell\s+-[eE][nN][cC]/i,
        /invoke-expression/i,
        /iex\s+\$/i
    ];
    const hasPowerShell = strings.some(s => powerShellPatterns.some(p => p.test(s)));
    if (hasPowerShell) {
        triggeredRules.push({
            ...SECURITY_RULES[2],
            details: 'Suspicious PowerShell command patterns found'
        });
    }
    
    // Rule 004: Suspicious Command Shell
    const shellPatterns = [
        /cmd\.exe\s+\/c/i,
        /cmd\.exe\s+\/k/i,
        /\/bin\/sh\s+-c/i,
        /bash\s+-c/i
    ];
    const hasShellCmd = strings.some(s => shellPatterns.some(p => p.test(s)));
    if (hasShellCmd) {
        triggeredRules.push({
            ...SECURITY_RULES[3],
            details: 'Suspicious shell command patterns found'
        });
    }
    
    // Rule 005: Encoded Command
    const encodedPatterns = [
        /FromBase64String/i,
        /System\.Convert\.FromBase64String/i,
        /\\x[0-9a-fA-F]{2}/g
    ];
    const hasEncoded = strings.some(s => encodedPatterns.some(p => p.test(s)));
    if (hasEncoded) {
        triggeredRules.push({
            ...SECURITY_RULES[4],
            details: 'Encoded command patterns found'
        });
    }
    
    // Rule 006: Executable in Non-Executable
    const nonExecExtensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt', 'doc', 'docx'];
    const isNonExecExtension = nonExecExtensions.includes(extension.toLowerCase());
    const isExecutableType = detectedType.toLowerCase().includes('executable') || 
                            detectedType.toLowerCase().includes('pe') ||
                            detectedType.toLowerCase().includes('msi');
    if (isNonExecExtension && isExecutableType) {
        triggeredRules.push({
            ...SECURITY_RULES[5],
            details: `Extension: .${extension}, Type: ${detectedType}`
        });
    }
    
    // Rule 007: Suspicious URL
    const suspiciousTlds = ['.xyz', '.top', '.zip', '.tk', '.gq', '.ml'];
    const hasSuspiciousUrl = iocs.urls.some(url => suspiciousTlds.some(tld => url.includes(tld)));
    if (hasSuspiciousUrl) {
        triggeredRules.push({
            ...SECURITY_RULES[6],
            details: 'Suspicious TLD detected in URLs'
        });
    }
    
    // Rule 008: Autorun Reference
    const autorunPatterns = [
        /autorun\.inf/i,
        /run\s*=/i,
        /open\s*=/i,
        /shell\\open\\command/i
    ];
    const hasAutorun = strings.some(s => autorunPatterns.some(p => p.test(s)));
    if (hasAutorun) {
        triggeredRules.push({
            ...SECURITY_RULES[7],
            details: 'Autorun/persistence mechanism references found'
        });
    }
    
    // Rule 009: Registry Modification
    const registryPatterns = [
        /HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i,
        /HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i,
        /RegAdd/i,
        /RegWrite/i
    ];
    const hasRegistry = strings.some(s => registryPatterns.some(p => p.test(s)));
    if (hasRegistry) {
        triggeredRules.push({
            ...SECURITY_RULES[8],
            details: 'Registry modification references found'
        });
    }
    
    // Rule 010: Suspicious PE Characteristics
    if (peData) {
        if (peData.suspiciousSections || peData.suspiciousImports) {
            triggeredRules.push({
                ...SECURITY_RULES[9],
                details: 'Suspicious PE characteristics detected'
            });
        }
    }
    
    // Rule 011: High-Risk Extension
    const highRiskExtensions = ['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jar', 'msi', 'scr'];
    if (highRiskExtensions.includes(extension.toLowerCase())) {
        triggeredRules.push({
            ...SECURITY_RULES[10],
            details: `Extension: .${extension}`
        });
    }
    
    // Rule 012: Archive with Executable (simplified check)
    if (extension.toLowerCase() === 'zip' && strings.some(s => /\.exe$/i.test(s))) {
        triggeredRules.push({
            ...SECURITY_RULES[11],
            details: 'Archive contains executable files'
        });
    }
    
    // Rule 013: Nested Archive (simplified check)
    if (extension.toLowerCase() === 'zip' && strings.some(s => /\.zip$/i.test(s))) {
        triggeredRules.push({
            ...SECURITY_RULES[12],
            details: 'Archive contains nested archives'
        });
    }
    
    // Rule 014: Process Injection
    const injectionAPIs = [
        /VirtualAlloc/i,
        /WriteProcessMemory/i,
        /CreateRemoteThread/i,
        /SetWindowsHookEx/i
    ];
    const hasInjection = strings.some(s => injectionAPIs.some(p => p.test(s)));
    if (hasInjection) {
        triggeredRules.push({
            ...SECURITY_RULES[13],
            details: 'Process injection API references found'
        });
    }
    
    // Rule 015: Anti-Debugging
    const antiDebugPatterns = [
        /IsDebuggerPresent/i,
        /CheckRemoteDebuggerPresent/i,
        /NtQueryInformationProcess/i
    ];
    const hasAntiDebug = strings.some(s => antiDebugPatterns.some(p => p.test(s)));
    if (hasAntiDebug) {
        triggeredRules.push({
            ...SECURITY_RULES[14],
            details: 'Anti-debugging techniques detected'
        });
    }
    
    return triggeredRules;
}

/**
 * Calculate risk score based on triggered rules
 */
export function calculateRiskScore(triggeredRules) {
    let score = 0;
    
    triggeredRules.forEach(rule => {
        switch (rule.severity) {
            case 'HIGH':
                score += 25;
                break;
            case 'MEDIUM':
                score += 15;
                break;
            case 'LOW':
                score += 5;
                break;
        }
    });
    
    // Cap at 100
    return Math.min(score, 100);
}

/**
 * Get classification based on risk score
 */
export function getClassification(riskScore) {
    if (riskScore >= 60) return 'DANGER';
    if (riskScore >= 30) return 'SUSPICIOUS';
    if (riskScore >= 10) return 'WARNING';
    return 'SAFE';
}

/**
 * Get verdict based on risk score
 */
export function getVerdict(riskScore, triggeredRules) {
    if (riskScore >= 60) {
        return {
            title: 'High Risk Detected',
            description: `Multiple suspicious patterns detected: ${triggeredRules.map(r => r.name).join(', ')}. This file exhibits characteristics commonly associated with malware. Exercise extreme caution.`
        };
    }
    if (riskScore >= 30) {
        return {
            title: 'Suspicious File',
            description: `Suspicious patterns detected: ${triggeredRules.map(r => r.name).join(', ')}. This file may contain potentially unwanted content. Analyze in a sandboxed environment.`
        };
    }
    if (riskScore >= 10) {
        return {
            title: 'Caution Advised',
            description: `Minor suspicious indicators found: ${triggeredRules.map(r => r.name).join(', ')}. Review file content before execution.`
        };
    }
    return {
        title: 'File Appears Safe',
        description: 'No suspicious patterns detected. The static analysis found no indicators of malicious content. Note: This is a heuristic analysis and cannot guarantee complete safety.'
    };
}
