"""Seed the database with the admin user and NIST CSF 2.0 reference data."""

import secrets

NIST_CSF_DATA = [
    # GV – Govern
    ("GV", "Govern", "GV.OC", "Organizational Context", "GV.OC-01", "Organizational mission is understood and informs cybersecurity risk management."),
    ("GV", "Govern", "GV.OC", "Organizational Context", "GV.OC-02", "Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered."),
    ("GV", "Govern", "GV.OC", "Organizational Context", "GV.OC-03", "Legal, regulatory, and contractual requirements regarding cybersecurity — including privacy and civil liberties obligations — are understood and managed."),
    ("GV", "Govern", "GV.OC", "Organizational Context", "GV.OC-04", "Critical objectives, capabilities, and services that stakeholders depend on or expect from the organization are understood and communicated."),
    ("GV", "Govern", "GV.OC", "Organizational Context", "GV.OC-05", "Outcomes, capabilities, and services that the organization depends on are understood and communicated."),
    ("GV", "Govern", "GV.RM", "Risk Management Strategy", "GV.RM-01", "Risk management objectives are established and agreed to by organizational stakeholders."),
    ("GV", "Govern", "GV.RM", "Risk Management Strategy", "GV.RM-02", "Risk appetite and risk tolerance statements are established, communicated, and maintained."),
    ("GV", "Govern", "GV.RM", "Risk Management Strategy", "GV.RM-03", "Cybersecurity risk management activities and outcomes are included in enterprise risk management processes."),
    ("GV", "Govern", "GV.RM", "Risk Management Strategy", "GV.RM-04", "Strategic direction that describes appropriate risk response options is established and communicated."),
    ("GV", "Govern", "GV.RM", "Risk Management Strategy", "GV.RM-05", "Lines of communication across the organization are established for cybersecurity risks, including risks from suppliers and other third parties."),
    ("GV", "Govern", "GV.RM", "Risk Management Strategy", "GV.RM-06", "A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established and communicated."),
    ("GV", "Govern", "GV.RM", "Risk Management Strategy", "GV.RM-07", "Strategic opportunities (i.e., positive risks) are characterized and are included in organizational cybersecurity risk discussions."),
    ("GV", "Govern", "GV.RR", "Roles, Responsibilities, and Authorities", "GV.RR-01", "Organizational leadership is responsible and accountable for cybersecurity risk and fosters a culture that is risk-aware, ethical, and continually improving."),
    ("GV", "Govern", "GV.RR", "Roles, Responsibilities, and Authorities", "GV.RR-02", "Roles, responsibilities, and authorities related to cybersecurity risk management are established, communicated, understood, and enforced."),
    ("GV", "Govern", "GV.RR", "Roles, Responsibilities, and Authorities", "GV.RR-03", "Adequate resources are allocated commensurate with the cybersecurity risk strategy, roles, responsibilities, and policies."),
    ("GV", "Govern", "GV.RR", "Roles, Responsibilities, and Authorities", "GV.RR-04", "Cybersecurity is included in human resources practices."),
    ("GV", "Govern", "GV.PO", "Policy", "GV.PO-01", "Policy for managing cybersecurity risks is established based on organizational context, cybersecurity strategy, and priorities and is communicated and enforced."),
    ("GV", "Govern", "GV.PO", "Policy", "GV.PO-02", "Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced to reflect changes in requirements, threats, technology, and organizational mission."),
    ("GV", "Govern", "GV.OV", "Oversight", "GV.OV-01", "Cybersecurity risk management strategy outcomes are reviewed to inform and adjust strategy and direction."),
    ("GV", "Govern", "GV.OV", "Oversight", "GV.OV-02", "The cybersecurity risk management strategy is reviewed and adjusted to ensure coverage of organizational requirements and risks."),
    ("GV", "Govern", "GV.OV", "Oversight", "GV.OV-03", "Organizational cybersecurity risk management performance is evaluated and reviewed for adjustments needed."),
    ("GV", "Govern", "GV.SC", "Cybersecurity Supply Chain Risk Management", "GV.SC-01", "A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders."),
    ("GV", "Govern", "GV.SC", "Cybersecurity Supply Chain Risk Management", "GV.SC-02", "Cybersecurity roles and responsibilities for suppliers, customers, and partners are established, communicated, and coordinated internally and externally."),
    ("GV", "Govern", "GV.SC", "Cybersecurity Supply Chain Risk Management", "GV.SC-03", "Cybersecurity supply chain risk management is integrated into cybersecurity and enterprise risk management, risk assessment, and improvement processes."),
    ("GV", "Govern", "GV.SC", "Cybersecurity Supply Chain Risk Management", "GV.SC-04", "Suppliers are known and prioritized by criticality."),
    ("GV", "Govern", "GV.SC", "Cybersecurity Supply Chain Risk Management", "GV.SC-05", "Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts and other types of agreements with suppliers and other relevant third parties."),
    ("GV", "Govern", "GV.SC", "Cybersecurity Supply Chain Risk Management", "GV.SC-06", "Planning and due diligence are performed to reduce risks before entering into formal supplier or other third-party relationships."),
    ("GV", "Govern", "GV.SC", "Cybersecurity Supply Chain Risk Management", "GV.SC-07", "The risks posed by a supplier, their products and services, and other third parties are identified, recorded, assessed, and communicated."),
    ("GV", "Govern", "GV.SC", "Cybersecurity Supply Chain Risk Management", "GV.SC-08", "Relevant suppliers and other third parties are included in incident planning."),
    ("GV", "Govern", "GV.SC", "Cybersecurity Supply Chain Risk Management", "GV.SC-09", "Supply chain security practices are integrated into cybersecurity and enterprise risk management programs, and their performance is monitored throughout the technology product and service life cycle."),
    ("GV", "Govern", "GV.SC", "Cybersecurity Supply Chain Risk Management", "GV.SC-10", "Cybersecurity supply chain risk management plans include provisions for activities that occur after the conclusion of a partnership or service agreement."),
    # ID – Identify
    ("ID", "Identify", "ID.AM", "Asset Management", "ID.AM-01", "Inventories of hardware managed by the organization are maintained."),
    ("ID", "Identify", "ID.AM", "Asset Management", "ID.AM-02", "Inventories of software, services, and systems managed by the organization are maintained."),
    ("ID", "Identify", "ID.AM", "Asset Management", "ID.AM-03", "Representations of the organization's authorized network communication and internal and external network data flows are maintained."),
    ("ID", "Identify", "ID.AM", "Asset Management", "ID.AM-04", "Inventories of services provided by suppliers are maintained."),
    ("ID", "Identify", "ID.AM", "Asset Management", "ID.AM-05", "Assets are prioritized based on classification, criticality, resources, and impact on the mission."),
    ("ID", "Identify", "ID.AM", "Asset Management", "ID.AM-07", "Inventories of data and corresponding metadata for designated data types are maintained."),
    ("ID", "Identify", "ID.AM", "Asset Management", "ID.AM-08", "Systems, hardware, software, services, and data are managed throughout their life cycles."),
    ("ID", "Identify", "ID.RA", "Risk Assessment", "ID.RA-01", "Vulnerabilities in assets are identified, validated, and recorded."),
    ("ID", "Identify", "ID.RA", "Risk Assessment", "ID.RA-02", "Cyber threat intelligence is received from information sharing forums and sources."),
    ("ID", "Identify", "ID.RA", "Risk Assessment", "ID.RA-03", "Internal and external threats to the organization are identified and recorded."),
    ("ID", "Identify", "ID.RA", "Risk Assessment", "ID.RA-04", "Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded."),
    ("ID", "Identify", "ID.RA", "Risk Assessment", "ID.RA-05", "Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization."),
    ("ID", "Identify", "ID.RA", "Risk Assessment", "ID.RA-06", "Risk responses are chosen, prioritized, planned, tracked, and communicated."),
    ("ID", "Identify", "ID.RA", "Risk Assessment", "ID.RA-07", "Changes and exceptions are managed, assessed for risk impact, recorded, and tracked."),
    ("ID", "Identify", "ID.RA", "Risk Assessment", "ID.RA-08", "Processes for receiving, analyzing, and responding to vulnerability disclosures are established."),
    ("ID", "Identify", "ID.RA", "Risk Assessment", "ID.RA-09", "The authenticity and integrity of hardware and software are assessed prior to acquisition and use."),
    ("ID", "Identify", "ID.RA", "Risk Assessment", "ID.RA-10", "Critical suppliers are assessed prior to acquisition."),
    ("ID", "Identify", "ID.IM", "Improvement", "ID.IM-01", "Improvements are identified from evaluations."),
    ("ID", "Identify", "ID.IM", "Improvement", "ID.IM-02", "Improvements are identified from security tests and exercises, including those done in coordination with suppliers and relevant third parties."),
    ("ID", "Identify", "ID.IM", "Improvement", "ID.IM-03", "Improvements are identified from execution of operational processes, procedures, and activities."),
    ("ID", "Identify", "ID.IM", "Improvement", "ID.IM-04", "Incident response plans and other cybersecurity plans that affect operations are established, communicated, maintained, and improved."),
    # PR – Protect
    ("PR", "Protect", "PR.AA", "Identity Management, Authentication, and Access Control", "PR.AA-01", "Identities and credentials for authorized users, services, and hardware are managed by the organization."),
    ("PR", "Protect", "PR.AA", "Identity Management, Authentication, and Access Control", "PR.AA-02", "Identities are proofed and bound to credentials based on the context of interactions."),
    ("PR", "Protect", "PR.AA", "Identity Management, Authentication, and Access Control", "PR.AA-03", "Users, services, and hardware are authenticated."),
    ("PR", "Protect", "PR.AA", "Identity Management, Authentication, and Access Control", "PR.AA-04", "Identity assertions are protected, conveyed, and verified."),
    ("PR", "Protect", "PR.AA", "Identity Management, Authentication, and Access Control", "PR.AA-05", "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties."),
    ("PR", "Protect", "PR.AA", "Identity Management, Authentication, and Access Control", "PR.AA-06", "Physical access to assets is managed, monitored, and enforced commensurate with risk."),
    ("PR", "Protect", "PR.AT", "Awareness and Training", "PR.AT-01", "Personnel are provided with awareness and training so that they possess the knowledge and skills to perform general tasks with cybersecurity risks in mind."),
    ("PR", "Protect", "PR.AT", "Awareness and Training", "PR.AT-02", "Individuals in specialized roles are provided with awareness and training so that they possess the knowledge and skills to perform relevant tasks with cybersecurity risks in mind."),
    ("PR", "Protect", "PR.DS", "Data Security", "PR.DS-01", "The confidentiality, integrity, and availability of data-at-rest are protected."),
    ("PR", "Protect", "PR.DS", "Data Security", "PR.DS-02", "The confidentiality, integrity, and availability of data-in-transit are protected."),
    ("PR", "Protect", "PR.DS", "Data Security", "PR.DS-10", "The confidentiality, integrity, and availability of data-in-use are protected."),
    ("PR", "Protect", "PR.DS", "Data Security", "PR.DS-11", "Backups of data are created, protected, maintained, and tested."),
    ("PR", "Protect", "PR.IR", "Technology Infrastructure Resilience", "PR.IR-01", "Networks and environments are protected from unauthorized logical access and usage."),
    ("PR", "Protect", "PR.IR", "Technology Infrastructure Resilience", "PR.IR-02", "The organization's technology assets are protected from environmental threats."),
    ("PR", "Protect", "PR.IR", "Technology Infrastructure Resilience", "PR.IR-03", "Mechanisms are implemented to achieve resilience requirements in normal and adverse situations."),
    ("PR", "Protect", "PR.IR", "Technology Infrastructure Resilience", "PR.IR-04", "Adequate resource capacity to ensure availability is maintained."),
    ("PR", "Protect", "PR.PS", "Platform Security", "PR.PS-01", "Configuration management practices are established and applied."),
    ("PR", "Protect", "PR.PS", "Platform Security", "PR.PS-02", "Software is maintained, replaced, and removed commensurate with risk."),
    ("PR", "Protect", "PR.PS", "Platform Security", "PR.PS-03", "Hardware is maintained, replaced, and removed commensurate with risk."),
    ("PR", "Protect", "PR.PS", "Platform Security", "PR.PS-04", "Log records are generated and made available for continuous monitoring."),
    ("PR", "Protect", "PR.PS", "Platform Security", "PR.PS-05", "Installation and execution of unauthorized software are prevented."),
    ("PR", "Protect", "PR.PS", "Platform Security", "PR.PS-06", "Secure software development practices are integrated, and their security is evaluated."),
    # DE – Detect
    ("DE", "Detect", "DE.AE", "Adverse Event Analysis", "DE.AE-02", "Potentially adverse events are analyzed to better understand associated activities."),
    ("DE", "Detect", "DE.AE", "Adverse Event Analysis", "DE.AE-03", "Information is correlated from multiple sources."),
    ("DE", "Detect", "DE.AE", "Adverse Event Analysis", "DE.AE-04", "The estimated impact and scope of adverse events are understood."),
    ("DE", "Detect", "DE.AE", "Adverse Event Analysis", "DE.AE-06", "Information on adverse events is provided to authorized staff and tools."),
    ("DE", "Detect", "DE.AE", "Adverse Event Analysis", "DE.AE-07", "Cyber threat intelligence and other contextual information are integrated into the analysis."),
    ("DE", "Detect", "DE.AE", "Adverse Event Analysis", "DE.AE-08", "Incidents are declared when adverse events meet the defined incident criteria."),
    ("DE", "Detect", "DE.CM", "Continuous Monitoring", "DE.CM-01", "Networks and network services are monitored to find potentially adverse events."),
    ("DE", "Detect", "DE.CM", "Continuous Monitoring", "DE.CM-02", "The physical environment is monitored to find potentially adverse events."),
    ("DE", "Detect", "DE.CM", "Continuous Monitoring", "DE.CM-03", "Personnel activity and technology usage are monitored to find potentially adverse events."),
    ("DE", "Detect", "DE.CM", "Continuous Monitoring", "DE.CM-06", "External service provider activities and services are monitored to find potentially adverse events."),
    ("DE", "Detect", "DE.CM", "Continuous Monitoring", "DE.CM-09", "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events."),
    # RS – Respond
    ("RS", "Respond", "RS.MA", "Incident Management", "RS.MA-01", "The incident response plan is executed in coordination with relevant third parties once an incident is declared."),
    ("RS", "Respond", "RS.MA", "Incident Management", "RS.MA-02", "Incident reports are triaged and validated."),
    ("RS", "Respond", "RS.MA", "Incident Management", "RS.MA-03", "Incidents are categorized and prioritized."),
    ("RS", "Respond", "RS.MA", "Incident Management", "RS.MA-04", "Incidents are escalated or elevated as needed."),
    ("RS", "Respond", "RS.MA", "Incident Management", "RS.MA-05", "The criteria for initiating incident recovery are applied."),
    ("RS", "Respond", "RS.AN", "Incident Analysis", "RS.AN-03", "Analysis is performed to establish what has taken place during an incident and the root cause of the incident."),
    ("RS", "Respond", "RS.AN", "Incident Analysis", "RS.AN-06", "Actions performed during an investigation are recorded, and the records' integrity and provenance are preserved."),
    ("RS", "Respond", "RS.AN", "Incident Analysis", "RS.AN-07", "Incident data and metadata are collected, and their integrity is preserved."),
    ("RS", "Respond", "RS.AN", "Incident Analysis", "RS.AN-08", "An incident's magnitude is estimated and validated."),
    ("RS", "Respond", "RS.CO", "Incident Response Reporting and Communication", "RS.CO-02", "Internal and external stakeholders are notified of incidents in a timely manner as required."),
    ("RS", "Respond", "RS.CO", "Incident Response Reporting and Communication", "RS.CO-03", "Information is shared with designated internal and external stakeholders as defined in the incident response plan."),
    ("RS", "Respond", "RS.MI", "Incident Mitigation", "RS.MI-01", "Incidents are contained."),
    ("RS", "Respond", "RS.MI", "Incident Mitigation", "RS.MI-02", "Incidents are eradicated."),
    # RC – Recover
    ("RC", "Recover", "RC.RP", "Incident Recovery Plan Execution", "RC.RP-01", "The recovery portion of the incident response plan is executed once initiated from the incident response process."),
    ("RC", "Recover", "RC.RP", "Incident Recovery Plan Execution", "RC.RP-02", "Recovery actions are selected, scoped, prioritized, and performed."),
    ("RC", "Recover", "RC.RP", "Incident Recovery Plan Execution", "RC.RP-03", "The integrity of backups and other restoration assets is verified before using them for restoration."),
    ("RC", "Recover", "RC.RP", "Incident Recovery Plan Execution", "RC.RP-04", "Critical mission functions and cybersecurity risk management are considered to establish post-incident operational norms."),
    ("RC", "Recover", "RC.RP", "Incident Recovery Plan Execution", "RC.RP-05", "The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed."),
    ("RC", "Recover", "RC.RP", "Incident Recovery Plan Execution", "RC.RP-06", "The end of incident recovery is declared based on criteria, and incident-related documentation is completed."),
    ("RC", "Recover", "RC.CO", "Incident Recovery Communication", "RC.CO-03", "Recovery activities and progress in restoring operational capabilities are communicated to designated internal and external stakeholders."),
    ("RC", "Recover", "RC.CO", "Incident Recovery Communication", "RC.CO-04", "Public updates on incident recovery are shared using approved methods and messaging."),
]


def seed_nist_csf(db, NISTCSFReference):
    if NISTCSFReference.query.first():
        return  # Already seeded
    for row in NIST_CSF_DATA:
        func_code, func_name, cat_code, cat_name, sub_code, desc = row
        entry = NISTCSFReference(
            function_code=func_code,
            function_name=func_name,
            category_code=cat_code,
            category_name=cat_name,
            subcategory_code=sub_code,
            description=desc,
        )
        db.session.add(entry)
    db.session.commit()


LOOKUP_DEFAULTS = {
    "threat_actor_type": [
        "Cybercriminal", "Nation State", "Malicious Insider",
        "Hacktivist", "Script Kiddie", "Unknown",
    ],
    "attack_vector": [
        "Web Application", "Phishing / Social Engineering", "Supply Chain",
        "Removable Media", "Network Intrusion", "Insider Threat",
        "Vulnerability Exploit", "Physical Access", "Other",
    ],
    "threat_intel_source": [
        "Self-Assessment", "Vulnerability Scan", "Penetration Test",
        "Threat Intelligence Feed", "Internal Audit",
        "Incident Report", "News / Public Disclosure",
    ],
    "risk_owner": [],  # populated by admins for their organisation
}


def seed_lookup_defaults(db, LookupItem):
    if LookupItem.query.first():
        return  # Already seeded
    order = 0
    for category, values in LOOKUP_DEFAULTS.items():
        for value in values:
            db.session.add(LookupItem(
                category=category,
                value=value,
                display_order=order,
            ))
            order += 1
    db.session.commit()


def seed_admin(db, User, app):
    if User.query.filter_by(email=app.config["ADMIN_EMAIL"]).first():
        return  # Already exists

    # A shipped default password is a published password. If ADMIN_PASSWORD is
    # not set, generate a strong one and print it once to the startup log so the
    # operator can retrieve it and change it — nobody inherits a known secret.
    password = app.config.get("ADMIN_PASSWORD") or ""
    generated = False
    if not password:
        password = secrets.token_urlsafe(18)
        generated = True

    admin = User(
        username=app.config["ADMIN_USERNAME"],
        email=app.config["ADMIN_EMAIL"],
        name=app.config["ADMIN_NAME"],
        role="admin",
        is_active=True,
    )
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()

    if generated:
        app.logger.warning(
            "\n%s\nBootstrap admin created.\n  username: %s\n  password: %s\n"
            "This password is shown once, in this log line only. Sign in and\n"
            "change it now, then clear it from your container logs.\n%s",
            "=" * 68, app.config["ADMIN_USERNAME"], password, "=" * 68,
        )
