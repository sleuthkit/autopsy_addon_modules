- __Description:__ The Autopsy ForensicVM client is an innovative tool designed to streamline the process of digital forensics. It leverages advanced virtualization technology to enable secure and efficient analysis of forensic images. The client is specifically developed for cybersecurity professionals, digital forensics investigators, and information security teams.
- __Author:__ Nuno Mourinho 
- __Minimum Autopsy version:__ 4.20.0
- __Module Location__: https://github.com/nunomourinho/AutopsyForensicVM/releases/tag/v1.0.2
- __Website:__ https://forensicvm-autopsy-plugin-user-manual.readthedocs.io/en/latest/
- __Source Code:__ https://github.com/nunomourinho/AutopsyForensicVM
- __License:__  EUPL-1.2 license


# Autopsy ForensicVM client
[![Actions Status](https://github.com/nunomourinho/AutopsyForensicVM/workflows/Python%20application/badge.svg)](https://github.com/nunomourinho/AutopsyForensicVM/actions) [![DOI](https://zenodo.org/badge/628277916.svg)](https://zenodo.org/badge/latestdoi/628277916) [![Documentation Status](https://readthedocs.org/projects/forensicvm-autopsy-plugin-user-manual/badge/?version=latest)](https://forensicvm-autopsy-plugin-user-manual.readthedocs.io/en/latest/?badge=latest)


Documentation and manuals: [ForensicVM Autopsy Client Documentation](https://forensicvm-autopsy-plugin-user-manual.readthedocs.io/en/latest/)



## Introduction

The Autopsy ForensicVM client is an innovative tool designed to streamline the process of digital forensics. It leverages advanced virtualization technology to enable secure and efficient analysis of forensic images. The client is specifically developed for cybersecurity professionals, digital forensics investigators, and information security teams.

## Purpose of ForensicVM

ForensicVM aims to enhance the forensic analysis process by providing a range of features and capabilities. It offers a secure and scalable environment for analyzing forensic images, making it an invaluable tool in the field of digital forensics.

## Overview of Features

ForensicVM provides the following key features to enhance the forensic analysis process:

1. **Virtualization of Forensic Images:** ForensicVM allows the creation and management of virtualized instances of forensic images. This provides flexibility and scalability in the analysis process, with options for quick selection or full conversion to maximize performance and features.

2. **Forensic Image Lifecycle Management:** Users can manage the entire lifecycle of forensic images, from creation to decommissioning. This includes converting images into virtual machines, starting, stopping, resetting, snapshotting, and safely deleting them when no longer required.

3. **Advanced Analysis Tools:** ForensicVM is equipped with a suite of powerful analysis tools to assist investigators in uncovering vital evidence.

4. **Integrated Hypervisor:** The ForensicVM Server includes a robust hypervisor based on QEMU and KVM, ensuring efficient execution and management of virtual machines.

5. **Collaboration:** ForensicVM facilitates remote and secure collaboration among forensic investigators. It enables team members to work simultaneously on investigations regardless of their location, fostering productivity and communication. Advanced encryption and security protocols ensure the confidentiality and integrity of collaborative efforts.

6. **Plugin Architecture:** ForensicVM supports plugins that can be applied to the forensic virtual machine. These plugins enable security bypassing, customization, and the development of custom solutions that interact with ForensicVM.

7. **Evidence Disk:** An additional disk is automatically created with all tags from Autopsy Software, simplifying the gathering and importing of evidence back to Autopsy.

8. **Optional Network Card:** The network card, disabled by default, records all network traffic on the server while protecting local networking from potential attacks using pre-installed firewall rules. It also records traffic in Wireshark PCAP format.

9. **On-the-Fly Memory Dumps:** ForensicVM allows the creation of volatility memory dumps at any moment during the analysis.

10. **Integrated Screenshots:** The client includes a built-in feature for capturing screenshots, eliminating the need for an additional screenshot program.

11. **Integrated Video Recording:** ForensicVM enables the recording of individual videos with a maximum duration of three hours, providing additional evidence if required. Please note that audio recording is currently not available.

12. **Media Management:** The client allows investigators to manage ISO files and use their own tools during the investigation.

13. **Snapshot Management:** Users can freeze the virtual machine at a specific state and recall previous states for performing "what if" tests.

> **Warning:** The network card is currently a work-in-progress and may expose your network to potential risks under certain circumstances. While it safeguards your internal system, your external IP may still be visible if a C2C client is installed. Proceed with caution.

> **Important:** Video recording is currently under development and does not include audio. This limitation is expected to be addressed in future updates.

## Use Cases

ForensicVM can be utilized in various scenarios, including but not limited to:

- Cybersecurity Investigations
- Incident Response
- Training and Education
- Legal Investigations
- Corporate Audits and Investigations

In each of these scenarios, ForensicVM contributes to the analysis and understanding of digital evidence, aiding in investigations, incident mitigation, training, and maintaining a secure work environment.

Documentation and manuals: [ForensicVM Autopsy Client Documentation](https://forensicvm-autopsy-plugin-user-manual.readthedocs.io/en/latest/)


## 📖 Citation

Reference to cite if you use AutopsyForensicVM in a paper:
```
@software{Mourinho_AutopsyForensicVM_2023,
author = {Mourinho, Nuno},
doi = {10.5281/zenodo.8153316},
month = {07},
title = {{Autopsy ForensicVM Client}},
url = {https://github.com/nunomourinho/AutopsyForensicVM},
year = {2023}
}


