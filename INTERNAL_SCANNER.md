# Virus Scan Pro - Internal Static Analysis Engine

## Overview

Virus Scan Pro uses its own internal static analysis engine to analyze files. No files are sent to external malware scanning services. All analysis is performed locally in the browser using client-side JavaScript.

## Architecture

```
User uploads file
        ↓
Virus Scan Pro (Browser)
        ↓
┌──────────────────────────────────┐
│ File Identification Module       │
│ - Filename analysis              │
│ - Extension detection            │
│ - File size calculation          │
│ - MIME type detection            │
└──────────────────────────────────┘
        ↓
┌──────────────────────────────────┐
│ Hash Analysis Module             │
│ - MD5 calculation               │
│ - SHA-1 calculation             │
│ - SHA-256 calculation           │
└──────────────────────────────────┘
        ↓
┌──────────────────────────────────┐
│ Magic Byte Analysis Module       │
│ - File signature detection       │
│ - Extension/signature mismatch   │
│ - Format identification           │
└──────────────────────────────────┘
        ↓
┌──────────────────────────────────┐
│ Metadata Analysis Module         │
│ - File metadata extraction       │
│ - PE header analysis (if PE)     │
│ - Archive structure (if archive) │
└──────────────────────────────────┘
        ↓
┌──────────────────────────────────┐
│ String Extraction Module        │
│ - ASCII string extraction       │
│ - Unicode string extraction      │
│ - Suspicious string detection   │
└──────────────────────────────────┘
        ↓
┌──────────────────────────────────┐
│ IOC Extraction Module           │
│ - IPv4 addresses                │
│ - IPv6 addresses                │
│ - URLs                          │
│ - Domains                       │
│ - Email addresses               │
│ - Crypto wallets                │
└──────────────────────────────────┘
        ↓
┌──────────────────────────────────┐
│ Entropy Analysis Module         │
│ - Shannon entropy calculation   │
│ - Section entropy (if PE)       │
│ - Packed/encrypted detection    │
└──────────────────────────────────┘
        ↓
┌──────────────────────────────────┐
│ PE/Format Analysis Module       │
│ - PE header parsing             │
│ - Section analysis              │
│ - Import/export analysis        │
│ - APK analysis (if APK)         │
└──────────────────────────────────┘
        ↓
┌──────────────────────────────────┐
│ Rule Engine Module              │
│ - Suspicious pattern detection  │
│ - Rule matching                 │
│ - Severity classification        │
└──────────────────────────────────┘
        ↓
┌──────────────────────────────────┐
│ Risk Scoring Module             │
│ - Risk score calculation        │
│ - Classification assignment     │
│ - Verdict generation            │
└──────────────────────────────────┘
        ↓
Final Analysis Report
        ↓
UI Display
```

## Analysis Modules

### 1. File Identification Module
- **Purpose**: Identify basic file properties
- **Functions**:
  - Extract filename and extension
  - Calculate file size
  - Detect MIME type
  - Identify file type from extension

### 2. Hash Analysis Module
- **Purpose**: Calculate cryptographic hashes
- **Functions**:
  - MD5 hash calculation
  - SHA-1 hash calculation
  - SHA-256 hash calculation
- **Implementation**: Web Crypto API

### 3. Magic Byte Analysis Module
- **Purpose**: Detect actual file type from file signature
- **Functions**:
  - Read first bytes of file
  - Compare against known magic bytes
  - Detect extension/signature mismatches
- **Supported Formats**: PE, ELF, ZIP, PDF, PNG, JPEG, GIF, MP3, MP4, Office documents, archives

### 4. Metadata Analysis Module
- **Purpose**: Extract file metadata
- **Functions**:
  - PE header analysis (if Windows executable)
  - Archive structure inspection (if archive)
  - Document metadata (if supported)
  - Timestamp extraction

### 5. String Extraction Module
- **Purpose**: Extract readable strings from file
- **Functions**:
  - ASCII string extraction (4+ characters)
  - Unicode string extraction
  - Suspicious string identification
- **Implementation**: Web Workers for performance

### 6. IOC Extraction Module
- **Purpose**: Extract indicators of compromise
- **Functions**:
  - IPv4 address detection
  - IPv6 address detection
  - URL detection
  - Domain detection
  - Email address detection
  - Crypto wallet detection
  - Suspicious string detection

### 7. Entropy Analysis Module
- **Purpose**: Calculate Shannon entropy
- **Functions**:
  - Overall file entropy
  - Section entropy (if PE)
  - Packed/encrypted data detection
- **Scale**: 0-8 (higher = more random/compressed)

### 8. PE/Format Analysis Module
- **Purpose**: Analyze specific file formats
- **Functions**:
  - PE header parsing
  - Section analysis
  - Import/export analysis
  - APK manifest parsing (if APK)
  - Archive content listing (if archive)

### 9. Rule Engine Module
- **Purpose**: Detect suspicious patterns
- **Functions**:
  - Pattern matching against rules
  - Severity classification
  - Rule triggering
- **Implementation**: `scanner/rules.js`

## Security Rules

The rule engine includes 15 built-in rules:

| ID | Name | Severity | Category |
|----|------|----------|----------|
| RULE-001 | Extension Signature Mismatch | HIGH | spoofing |
| RULE-002 | High Entropy Detected | MEDIUM | entropy |
| RULE-003 | Suspicious PowerShell Command | HIGH | script |
| RULE-004 | Suspicious Command Shell | HIGH | script |
| RULE-005 | Encoded Command Pattern | MEDIUM | encoding |
| RULE-006 | Executable in Non-Executable File | HIGH | structure |
| RULE-007 | Suspicious URL Detected | MEDIUM | network |
| RULE-008 | Autorun Reference | MEDIUM | persistence |
| RULE-009 | Registry Modification Reference | MEDIUM | persistence |
| RULE-010 | Suspicious PE Characteristics | HIGH | pe |
| RULE-011 | High-Risk Extension | LOW | extension |
| RULE-012 | Archive with Executable | MEDIUM | archive |
| RULE-013 | Nested Archive | MEDIUM | archive |
| RULE-014 | Process Injection | HIGH | api |
| RULE-015 | Anti-Debugging Techniques | HIGH | evasion |

## Risk Scoring

Risk score is calculated based on triggered rules:

- **HIGH severity**: +25 points
- **MEDIUM severity**: +15 points
- **LOW severity**: +5 points

Maximum score: 100

### Classification

| Score Range | Classification | Verdict |
|-------------|----------------|---------|
| 0-9 | SAFE | File Appears Safe |
| 10-29 | WARNING | Caution Advised |
| 30-59 | SUSPICIOUS | Suspicious File |
| 60-100 | DANGER | High Risk Detected |

## File Format Support

### Fully Supported
- PE/EXE files (Windows executables)
- DLL files
- ZIP archives
- RAR archives (basic)
- 7Z archives (basic)
- PNG images
- JPEG images
- GIF images
- PDF documents
- MP3 audio
- MP4 video
- ELF executables (Linux)
- Java class files
- Office documents (basic)
- Text files
- Scripts (bat, cmd, ps1, vbs, js)

### Partially Supported
- APK files (manifest parsing)
- Other archive formats (basic structure)

### Not Supported
- Encrypted archives (password protected)
- Corrupted files
- Files larger than 100MB

## Privacy

**Files are analyzed by Virus Scan Pro's own static analysis engine. No files are sent to external services.**

All analysis is performed locally in the browser. Files are never uploaded to third-party malware scanning services.

## Limitations

### Static Analysis Only
- Files are never executed
- No dynamic analysis
- No behavioral analysis
- No sandbox execution

### Browser-Based
- Limited by browser memory
- Limited by browser performance
- Large files may cause performance issues

### Heuristic-Based
- Results are based on patterns and heuristics
- False positives possible
- False negatives possible
- Not a substitute for professional antivirus

### No Cloud Database
- No access to threat intelligence databases
- No reputation checking
- No historical analysis
- No community feedback

## Deployment

### Requirements
- Modern browser with Web Crypto API support
- JavaScript enabled
- Web Workers support

### No Backend Required
- No server-side processing
- No API keys needed
- No external dependencies
- Works entirely in browser

### Netlify Deployment
- Deploy as static site
- No serverless functions needed
- No environment variables needed
- No build process required (Vite dev server for development)

## Files

### Core Scanner
- `scanner/rules.js` - Rule engine and risk scoring

### Existing Analysis (Preserved)
- `analyzers/ioc.js` - IOC extraction and PE/APK parsing
- `intelligence/mitre.js` - MITRE ATT&CK mapping
- `reports/export.js` - Report generation

### UI
- `app.js` - Main application logic
- `index.html` - UI structure
- `styles.css` - Styling (including responsive design)

## Testing

### Test Files
Test with various file types:
- TXT files (text documents)
- PDF files (documents)
- JPG/PNG files (images)
- ZIP files (archives)
- EXE files (executables)

### Expected Behavior
- All files should be analyzed
- Hashes should be calculated correctly
- Magic bytes should be detected
- Strings should be extracted
- IOCs should be identified
- Rules should trigger appropriately
- Risk score should be calculated
- UI should display results

## Security Considerations

### File Execution
- **NEVER executes uploaded files**
- All analysis is static
- No code execution from uploaded content
- No macro execution
- No script execution

### Resource Limits
- Maximum file size: 100MB
- String extraction limits
- Memory usage monitoring
- Timeout protection

### Input Validation
- File type validation
- Size validation
- Content sanitization
- XSS prevention

## Future Enhancements

### Potential Additions
- More file format support
- Additional security rules
- Machine learning integration
- YARA rule support
- More detailed PE analysis
- Archive bomb detection
- Improved entropy analysis

### Not Planned
- Dynamic/sandbox analysis
- Cloud-based reputation checking
- Third-party API integration
- External database queries

## Summary

Virus Scan Pro is a **100% client-side static analysis tool** that:

- ✅ Analyzes files locally in the browser
- ✅ Uses internal rule engine for detection
- ✅ Calculates real hashes
- ✅ Detects file signatures
- ✅ Extracts strings and IOCs
- ✅ Calculates entropy
- ✅ Performs PE/Archive analysis
- ✅ Provides risk scoring
- ✅ Maintains privacy (no external services)
- ✅ Works on all devices (responsive design)
- ✅ Requires no backend
- ✅ Requires no API keys
- ✅ Requires no external dependencies

Virus Scan Pro does **NOT**:
- ❌ Send files to external services
- ❌ Use VirusTotal or any third-party scanner
- ❌ Execute uploaded files
- ❌ Perform dynamic analysis
- ❌ Access cloud threat intelligence
- ❌ Require server-side processing
