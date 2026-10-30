![Banner](banner.png)

# dep-vuln-DependencyLicenseChecker
A command-line tool that analyzes project dependencies and checks them for known vulnerabilities in the NVD or OSV databases. The --license_policy option is accepted but not evaluated: the code has no license data source, a warning is printed on every run, and the report covers vulnerabilities only. - Focused on Maps declared software dependencies in project manifest files (e.g., requirements.txt, package.json) to known vulnerabilities in public databases (e.g., NIST NVD, OSV). Generates a report detailing vulnerable dependencies and suggested remediation steps, such as updating to patched versions. Supports multiple dependency file formats and vulnerability data sources.

Note on versions: dependency entries are stored as requirement specifiers. The OSV check needs one concrete version, so only a pinned entry (a single == version, or a bare version in package.json) is queried; a range is skipped with a warning. The NVD check matches on the specifier text as before.

## Install
`git clone https://github.com/ShadowStrikeHQ/dep-vuln-dependencylicensechecker`

## Usage
`./dep-vuln-dependencylicensechecker [params]`

## Parameters
- `-h`: Show help message and exit
- `--license_policy`: No description provided
- `--vulnerability_db`: No description provided
- `--output`: No description provided

## License
Copyright (c) ShadowStrikeHQ
