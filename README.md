# CuckooSpear Threat Campaign - CTI Publication

Welcome to the **CuckooSpear Threat Campaign / APT10** repository by Cybereason. This publication is dedicated to sharing detailed insights, Indicators of Compromise (IoCs), Yara rules, and Python scripts related to the CuckooSpear threat campaign. The goal of this repository is to aid cybersecurity professionals and researchers in detecting, analyzing, and mitigating threats associated with this campaign.

## Table of Contents

- [Overview](#overview)
- [Yara Rules](#yara-rules)
- [Python Scripts](#python-scripts)
- [Indicators of Compromise (IoCs)](#indicators-of-compromise-iocs)
- [How to Use This Repository](#how-to-use-this-repository)
- [Contributing](#contributing)
- [License](#license)

## Overview

CuckooSpear is a sophisticated threat campaign observed targeting various sectors and particularly Japan. The campaign is characterized by custom malware, and strategic use of infrastructure to evade detection. This repository consolidates our research findings and provides actionable resources to help the cybersecurity community defend against this threat.

## Yara Rules

In the `yara_rules/` directory, you will find a set of Yara rules specifically crafted to detect the malware and associated artifacts used in the CuckooSpear campaign.


## Python Scripts

The `scripts/` directory contains Python scripts developed to automate the detection and analysis of CuckooSpear-related activities. These scripts can be used to better understand the binary analyzed in the Threat Analysis Report.


## Indicators of Compromise (IoCs)

The `iocs/` directory contains files listing the IoCs related to the CuckooSpear campaign, including:

- **Domain names**
- **File hashes**
- **Registry keys where NOOPDOOR was stored**

These IoCs can be integrated into your security tools for proactive detection and blocking.

## How to Use This Repository

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Cybereason-Open-Source/CuckooSpear
   cd CuckooSpear
   ```

2. **Review and apply Yara rules:**
   - Navigate to the `yara_rules/` directory.
   - Use the rules with your Yara-enabled security solutions to detect CuckooSpear-related threats.

3. **Run Python scripts:**
   - Navigate to the `scripts/` directory.
   - Execute the scripts to automate detection or analysis tasks.

4. **Integrate IoCs:**
   - Use the IoCs from the `iocs/` directory in your SIEM, IDS/IPS, or other security tools.

## Contributing

We welcome contributions from the community. If you have additional Yara rules, scripts, or IoCs to share, please submit a pull request. For significant changes, please open an issue first to discuss your proposal.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

This `README.md` file provides a clear overview of the repository's purpose, contents, and usage instructions. It is structured to be user-friendly for anyone interested in contributing to or using the resources to defend against the CuckooSpear threat campaign.