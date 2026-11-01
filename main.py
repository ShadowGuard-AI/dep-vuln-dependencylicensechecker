import argparse
import logging
import json
import sys
from typing import List, Dict, Any
from packaging import requirements
import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_BASE_URL = "https://api.osv.dev/v1/query"


class UnpinnedVersionError(Exception):
    """Raised when a dependency has no exact version an OSV query can use."""

class DependencyVulnerabilityChecker:
    """
    A tool to analyze project dependencies, identify vulnerabilities, and flag license incompatibilities.
    """

    def __init__(self, dependency_file: str, license_policy: str, vulnerability_db: str):
        """
        Initializes the DependencyVulnerabilityChecker.

        Args:
            dependency_file: Path to the dependency file (e.g., requirements.txt, package.json).
            license_policy: License policy to enforce (e.g., "MIT", "GPL-2.0-or-later").
            vulnerability_db: Source of vulnerability data (e.g., "nvd", "osv").
        """
        self.dependency_file = dependency_file
        self.license_policy = license_policy
        self.vulnerability_db = vulnerability_db
        self.dependencies: List[Dict[str, str]] = []
        # Completed and failed check counts. Without them a run where
        # every query failed (or every version was skipped as unpinned)
        # reported "No vulnerabilities found." and exited 0.
        self.check_failures = 0
        self.check_successes = 0

    def load_dependencies(self) -> None:
        """
        Loads dependencies from the specified dependency file.
        Supports requirements.txt for now.
        """
        try:
            if self.dependency_file.endswith(".txt"):  # requirements.txt
                with open(self.dependency_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            try:
                                req = requirements.Requirement(line)
                                self.dependencies.append({"name": req.name, "version": str(req.specifier), "ecosystem": "PyPI"})
                            except Exception as e:
                                logging.warning(f"Could not parse dependency line: {line}. Error: {e}")
            elif self.dependency_file.endswith(".json"): #package.json
                with open(self.dependency_file, "r") as f:
                    data = json.load(f)
                if "dependencies" in data:
                    for name, version in data["dependencies"].items():
                        self.dependencies.append({"name": name, "version": version, "ecosystem": "npm"})
                if "devDependencies" in data:
                    for name, version in data["devDependencies"].items():
                        self.dependencies.append({"name": name, "version": version, "ecosystem": "npm"})


            else:
                raise ValueError("Unsupported dependency file format. Only .txt and .json supported.")
        except FileNotFoundError:
            logging.error(f"Dependency file not found: {self.dependency_file}")
            raise
        except Exception as e:
            logging.error(f"Error loading dependencies: {e}")
            raise

    def check_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Checks for vulnerabilities in the loaded dependencies using the specified vulnerability database.

        Returns:
            A list of dictionaries, where each dictionary represents a vulnerable dependency
            and contains information about the vulnerability.
        """
        vulnerable_dependencies: List[Dict[str, Any]] = []
        for dep in self.dependencies:
            try:
                if self.vulnerability_db == "nvd":
                    vulnerabilities = self._check_vulnerabilities_nvd(dep["name"], dep["version"])
                elif self.vulnerability_db == "osv":
                    vulnerabilities = self._check_vulnerabilities_osv(dep)
                else:
                    raise ValueError(f"Unsupported vulnerability database: {self.vulnerability_db}")

                if vulnerabilities:
                    vulnerable_dependencies.append({
                        "name": dep["name"],
                        "version": dep["version"],
                        "vulnerabilities": vulnerabilities
                    })
            except UnpinnedVersionError as e:
                # Not a failure and not a check: nothing was queried, so
                # this dependency must not count toward a completed run.
                logging.warning(str(e))
            except Exception as e:
                self.check_failures += 1
                logging.error(f"Error checking vulnerabilities for {dep['name']}: {e}")
            else:
                self.check_successes += 1

        return vulnerable_dependencies

    def _check_vulnerabilities_nvd(self, package_name: str, package_version: str) -> List[Dict[str, str]]:
        """
        Checks for vulnerabilities using the NIST NVD API.

        Args:
            package_name: Name of the package.
            package_version: Version of the package.

        Returns:
            A list of vulnerabilities (dictionaries) found for the given package and version.
        """
        concrete_version = self._concrete_version(package_version)
        if concrete_version is None:
            raise UnpinnedVersionError(
                f"Skipping NVD check for {package_name}: '{package_version}' is a range, not a pinned version."
            )
        # NVD API 2.0 names this parameter keywordSearch; the old
        # keyword= form is not the documented parameter.
        # The query is a keyword search, not a package lookup: the
        # version filtering happens locally below over whatever the
        # first page of results holds, and no further page is ever
        # requested. A package whose CVEs fall past that page, or
        # whose CPE criteria spell the name differently than the
        # manifest does, reads as having no vulnerabilities.
        url = f"{NVD_API_BASE_URL}?keywordSearch={package_name}"
        try:
            response = requests.get(url, timeout=10)  # Added timeout for network requests
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()

            vulnerabilities = []
            if "vulnerabilities" in data:
                for item in data["vulnerabilities"]:
                    cve = item["cve"]
                    if "configurations" in cve:
                        for config in cve["configurations"]:
                            if "nodes" in config:
                                for node in config["nodes"]:
                                    if "cpeMatch" in node:
                                        for cpe in node["cpeMatch"]:
                                            if package_name in cpe["criteria"]:
                                                # CPE criteria is colon separated and
                                                # field 5 is the version, a bare version
                                                # with no specifier prefix. Compare the
                                                # concrete version to that field, not the
                                                # raw specifier text to the whole string.
                                                criteria_parts = cpe["criteria"].split(":")
                                                criteria_version = criteria_parts[5] if len(criteria_parts) > 5 else ""
                                                if concrete_version == criteria_version:
                                                    vulnerability = {
                                                        "cve_id": cve["id"],
                                                        "description": cve["descriptions"][0]["value"],
                                                        "cvssv3": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")

                                                    }
                                                    vulnerabilities.append(vulnerability)


            return vulnerabilities
        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying NVD API: {e}")
            raise
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from NVD API: {e}")
            raise
        except Exception as e:
            logging.error(f"Error processing NVD data: {e}")
            raise


    @staticmethod
    def _concrete_version(specifier: str):
        # load_dependencies stores the requirement specifier (">=2.0",
        # "==1.0"), not a version. OSV only answers for one concrete
        # version, so only a single == pin can be sent; anything looser
        # has no honest answer from a per version query.
        text = (specifier or "").strip()
        if text.startswith("==") and "," not in text:
            # rstrip removes every trailing dot and asterisk, so a
            # wildcard pin like ==1.0.* comes out as the concrete
            # version 1.0 and is queried as if the manifest had pinned
            # exactly that. A wildcard is a range, and this quietly
            # narrows it to its first version.
            return text[2:].strip().rstrip(".*") or None
        if text and all(c.isalnum() or c in ".-_+" for c in text):
            return text
        return None

    def _check_vulnerabilities_osv(self, dep: Dict[str, str]) -> List[Dict[str, str]]:
        """
        Checks for vulnerabilities using the OSV API.

        Args:
            dep: Dependency dict with name, version specifier, and ecosystem.

        Returns:
            A list of vulnerabilities (dictionaries) found for the given package and version.
        """
        package_name = dep["name"]
        version = self._concrete_version(dep["version"])
        if version is None:
            raise UnpinnedVersionError(
                f"Skipping OSV check for {package_name}: '{dep['version']}' is a range, not a pinned version."
            )
        url = OSV_API_BASE_URL
        payload = {
            "package": {
                "name": package_name,
                # The ecosystem follows the manifest the dependency came
                # from; package.json entries queried as PyPI match nothing.
                "ecosystem": dep.get("ecosystem", "PyPI"),
                "version": version
            }
        }
        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            data = response.json()

            vulnerabilities = []
            if "vulns" in data:
                for vuln in data["vulns"]:
                    vulnerability = {
                        "id": vuln["id"],
                        "summary": vuln["summary"],
                        "details": vuln["details"],
                        "severity": vuln.get("severity", "N/A")
                    }
                    vulnerabilities.append(vulnerability)

            return vulnerabilities
        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying OSV API: {e}")
            raise
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from OSV API: {e}")
            raise
        except Exception as e:
            logging.error(f"Error processing OSV data: {e}")
            raise


    def generate_report(self, vulnerable_dependencies: List[Dict[str, Any]]) -> str:
        """
        Generates a report detailing the vulnerable dependencies.

        Args:
            vulnerable_dependencies: A list of dictionaries representing vulnerable dependencies.

        Returns:
            A string containing the report.
        """
        if not vulnerable_dependencies:
            report = "No vulnerabilities found."
            if self.check_failures:
                report += f"\nWarning: {self.check_failures} dependency check(s) failed; this result is incomplete."
            return report

        report = "Vulnerability Report:\n"
        for dep in vulnerable_dependencies:
            report += f"  Package: {dep['name']} (Version: {dep['version']})\n"
            for vuln in dep["vulnerabilities"]:
                report += f"    - Vulnerability ID: {vuln.get('id', vuln.get('cve_id', 'N/A'))}\n"
                report += f"      Description: {vuln.get('summary', vuln.get('description', 'N/A'))}\n"
                report += f"      Severity: {vuln.get('severity', vuln.get('cvssv3', 'N/A'))}\n"

        return report


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        An argparse.ArgumentParser object.
    """
    parser = argparse.ArgumentParser(description="Dependency Vulnerability Checker")
    parser.add_argument("dependency_file", help="Path to the dependency file (e.g., requirements.txt, package.json)")
    parser.add_argument("--license_policy", help="License policy to enforce (e.g., MIT, GPL-2.0-or-later)", default="MIT")
    parser.add_argument("--vulnerability_db", help="Source of vulnerability data (nvd or osv)", default="nvd", choices=["nvd", "osv"])
    parser.add_argument("--output", help="Path to save the report (optional).  If not provided the report will be printed to stdout.", required=False)
    return parser


def main() -> None:
    """
    Main function to execute the dependency vulnerability checker.
    """
    try:
        parser = setup_argparse()
        args = parser.parse_args()

        # The stored license policy is not evaluated: this code has no
        # license data source for a package, so claiming a license verdict
        # would be inventing one. Say so on every run instead.
        logging.warning("License policy is accepted but not evaluated; the report covers vulnerabilities only.")
        checker = DependencyVulnerabilityChecker(args.dependency_file, args.license_policy, args.vulnerability_db)
        checker.load_dependencies()
        if not checker.dependencies:
            # Nothing was parsed, so nothing can be checked. A clean line
            # here would claim a result the run never produced.
            logging.error("No dependencies were parsed/found to check.")
            print("No dependencies were parsed/found to check.")
            sys.exit(1)
        vulnerable_dependencies = checker.check_vulnerabilities()
        report = checker.generate_report(vulnerable_dependencies)

        if args.output:
            try:
                with open(args.output, "w") as f:
                    f.write(report)
                print(f"Report saved to {args.output}")
            except Exception as e:
                logging.error(f"Error writing to output file: {e}")
                print(report)
        else:
            print(report)

        # A run where no check completed (every query failed, or every
        # version was skipped as unpinned) produced no evidence either
        # way; it must not exit 0 behind a clean-sounding report.
        if checker.dependencies and checker.check_successes == 0:
            logging.error("No dependency check completed; the report above is not a clean result.")
            sys.exit(1)

    except ValueError as e:
        logging.error(e)
        sys.exit(1)
    except FileNotFoundError as e:
        logging.error(e)
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred:") # Include traceback in the log
        sys.exit(1)


if __name__ == "__main__":
    main()