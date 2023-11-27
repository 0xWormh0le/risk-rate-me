data = {
    'topic': (
        (0, 'Identify', 'Have you identified the confidential data (credit card numbers, social security numbers, etc...) collected or stored by your company?'),
        (0, 'Protect', 'The next set of questions will pertain to the NIST Cybersecurity Framework’s Protect category. These questions will help determine the basic practices you have in place to protect your systems.'),
        (0, 'Detect', 'The next set of questions will pertain to the NIST Cybersecurity Framework’s Detect category.  These questions will help determine the basic practices you have in place to detect malicious activity in your systems.'),
        (0, 'Respond', 'The next set of questions will pertain to the NIST Cybersecurity Framework’s Respond category. These questions will help determine the basic practices you have in place to respond and deal with a cybersecurity event when one occurs.'),
        (0, 'Recover', 'The next set of questions will pertain to the NIST Cybersecurity Framework’s Recover category. These questions will help determine the basic practices you have in place to get your business back to normal after a cybersecurity event.'),
        (1, 'Firewalls and Gateways', ''),
        (1, 'Secure configuration', ''),
        (1, 'Access control', ''),
        (1, 'Malware protection', ''),
        (1, 'Patch management', '')
    ),
    'question': (
        # Identify
        (
            (False, 1, 'Have you identified the confidential data (credit card numbers, social security numbers, etc...) collected or stored by your company?'),
            (False, 3, 'Have your employees been trained to identify phishing emails?'),
            (False, 4, 'How do you restrict employee access to business confidential information?'),
            (False, 4, 'How often does your business update the operating system on devices that have access to business confidential information?'),
            (False, 1, 'Have you identified all devices that store or have access to business confidential information?'),
            (False, 1, 'Do you remove non-essential applications from business hardware?'),
            (False, 1, 'Are legal and regulatory requirements regarding cybersecurity, including privacy and civil liberties obligations, understood and managed?'),
            (False, 1, 'Do you receive and share threat and vulnerability information from/with internal and external sources?'),
            (False, 1, 'Are threats, vulnerabilities, likelihoods, and impacts used to determine risk?'),
            (False, 1, 'Is organizational risk tolerance determined and clearly expressed?'),
            (False, 2, 'How do you manage your employee’s passwords?'),
            (False, 5, 'How complex are your passwords?'),
            (False, 3, 'How often do you change your passwords?')
        ),
        # Protect
        (
            (False, 1, 'Do your computers automatically time-out after a duration of inactivity?'),
            (False, 3, 'How does your company utilize firewalls to block unauthorized access?'),
            (False, 4, 'How often do you train your employees on the company’s cybersecurity policy and procedures?'),
            (False, 3, 'Do you allow your employees to access company files remotely?'),
            (False, 1, 'Is physical access to assets managed and protected?'),
            (False, 3, 'Is data at rest and in transit encrypted?'),
            (False, 3, 'Is data retained recorded and is data destroyed according to policy?'),
            (False, 4, 'Do you have response and recovery plans in place and managed?'),
            (False, 1, 'Is cybersecurity included in human resources practices (e.g. personnel screening, locking/closing accounts, return of equipment, and granting/loss of access)?'),
            (False, 1, 'Do you have a vulnerability management plan that includes scanning for patch levels, scanning for functions, ports, protocols, and services that should not be accessible to users or devices, and scanning for improperly configured or incorrectly operating information flow control mechanisms?'),
            (False, 1, 'Are maintenance tools carried into the facility inspected for obvious improper modifications?'),
            (False, 1, 'Is remote maintenance approved, logged, and performed in a manner that prevents unauthorized access?')
        ),
        # Detect
        (
            (False, 3, 'Does your business have anti-virus software installed on all devices?'),
            (False, 3, 'Does your business have anti-malware protection installed on all devices?'),
            (False, 4, 'How often do you check your devices for malware?'),
            (False, 4, 'Is your business able to detect cybersecurity events (select all applicable responses)?'),
            (False, 1, 'Are system network security incidents tracked and used to correlated with other system log files?')
        ),
        # Respond
        (
            (False, 1, 'Are roles and responsibilities assigned and do all parties know what to do?'),
            (True,  7, 'In the event of a cybersecurity event, what response plan do you have in place (select all applicable responses)?'),
            (False, 3, 'If a cybersecurity event has occurred in the past, have you made changes to your system(s) to ensure that this same event will not occur again?'),
            (False, 3, 'Do you have an individual or group assigned to control the cybersecurity event and discover how or where the event occurred?'),
            (False, 2, 'Does your business have a customer notification plan in place if customer confidential information was or may have been stolen? Note that you may be required by law to notify your customers.')
        ),
        # Recover
        (
            (False, 4, 'How often do you backup your data?'),
            (True,  6, 'Do you have easy access to contact information for the following resources that can help you recover (select all that apply)?'),
            (False, 2, 'Does your recovery plan include actions you and your employees will take to bring your business back to normal operations following a cybersecurity event?'),
            (False, 1, 'Is there someone in your organization who is designated to manage recover after a cybersecurtity event?'),
            (False, 1, 'Do your recovery plans incorporate lessons learned?'),
            (False, 1, 'Are your recovery strategies updated as technology and/or plans change?'),
            (False, 1, 'Do you have cyber insurance?')
        ),
        # Firewalls and Gateways
        (
            (
                False,
                1,
                "Have one or more firewalls (or similar network device) been installed to protect the organisation’s internal network?",
                "It is essential to install and configure a firewall or equivalent network device at the organisations network boundary."
            ),
            (
                False,
                1,
                "Has the default administrative password of the firewall been changed to an alternative strong password?",
                "Ensure  that you change the default password to a unique strong password."
            ),
            (
                False,
                1,
                "Has each open connection (i.e.  allowed ports and services) on the firewall been subject to approval and documented (including an explanation of business need)?",
                "Ensure each open connection on the firewall has been authorised and documented."
            ),
            (
                False,
                1,
                "Have vulnerable services (e.g.  Server Message Block (SMB), NetBIOS, Telnet, TFTP, RPC, rlogin, rsh or rexec) been disabled (blocked) by default and those that are allowed have a business justification?",
                "Ensure vulnerable services have been disabled and those that are open have a valid justification and documentation for being open."
            ),
            (
                False,
                1,
                "Are firewall rules subject to regular review?",
                "Ensure firewall rules are regularly reviewed and remove unused firewall rules."
            ),
            (
                False,
                1,
                "Have computers that do not need to connect to the Internet been prevented from initiating connections to the Internet (Default deny)?",
                "Ensure that the firewall has a default deny all rule in place and that Internet access is only provided to systems on an as required basis."
            ),
            (
                False,
                1,
                "Has the administrative interface used to manage the  firewall been configured such that it is not accessible from the Internet?",
                "Ensure that the admin interface of the firewall is not accessible from the internet."
            ),
            (
                False,
                1,
                "Does the administrative interface require second factor authentication or is access limited to a specific address?",
                "Ensure that the admin interface requires two factor authentication or access is limited to a specific address."
            ),
        ),
        # Secure configuration,
        (
            (
                False,
                1,
                "Are unnecessary user accounts on internal workstations  (eg Guest, previous employees) removed or disabled?",
                "Disable all accounts not in active use and ensure that processes for staff who leave include notification to the IT department to ensure accounts are disabled."
            ),
            (
                False,
                1,
                "Have default passwords for any user accounts been changed to a suitably strong password?",
                "Ensure all default passwords are changed."
            ),
            (
                False,
                1,
                "Are strong, complex passwords defined in policy and enforced technically for all users and administrators?",
                "Ensure a suitable password complexity policy is in place."
            ),
            (
                False,
                1,
                "Has the auto-run feature been disabled to prevent software programs running automatically when removable storage media is connected to a computer or network folders are mounted?",
                "Ensure that auto-run is disabled on all systems."
            ),
            (
                False,
                1,
                "Has unnecessary software been removed or disabled and do systems only have software on them that is required to meet business requirements?",
                "Ensure all systems only have the required software needed to meet their business needs installed."
            ),
            (
                False,
                1,
                "Is all additional software added to workstations approved by IT or Management staff prior to installation and are standard users prevented from installing software?",
                "Ensure only authorised software is installed on systems and ensure that users are prevented from installing software without prior authorisation."
            ),
            (
                False,
                1,
                "Has a personal firewall (or equivalent) been enabled on desktop PCs and laptops, and configured to disable (block) unapproved connections by default",
                "Ensure all available local firewalls are enabled."
            ),
            (
                False,
                1,
                "Are all user workstations built from a fully hardened base platform to ensure consistency and security across the estate",
                "Ensure systems use standard consistent build templates which are  hardened in accordance with vendor guidance."
            ),
            (
                False,
                1,
                "Is an offline backup solution in place to provide protection against malware that encrypts user data files?",
                "Ensure that backups or file versioning solutions cannot be accessed directly via the network in order to provide a reasonable level of protection against extortion malware."
            ),
            (
                False,
                1,
                "Is there a corporate policy on log retention and the centralised storage and management of log information?",
                "Ensure a corporate policy is in place to define the strategy for log retention."
            ),
            (
                False,
                1,
                "Are log files retained for relevant applications on both servers (including DHCP logs) and workstations for a period of at least three months?",
                "Ensure all server and workstation log files are retained for a defined minimum period."
            ),
            (
                False,
                1,
                "Are Internet access (for both web and mail) log files retained for a period of least three months?",
                "Ensure all server and workstation log files are retained for a defined minimum period."
            ),
            (
                False,
                1,
                "Are mobile devices and tablets managed centrally to provide remote wiping and locking in the event of loss or theft?",
                "Ensure mobile devices can be remotely erased in the event of loss or theft."
            ),
            (
                False,
                1,
                "Is a Mobile Device Management solution in place for hardening and controlling all mobile platforms in use within the organisation?",
                "Use Mobile Device Management technologies to harden, monitor and manage mobile devices."
            )
        ),
        # Access Control
        (
            (
                False,
                1,
                "Is user account creation subject to a full provisioning and approval process?",
                "Ensure there is a documented and audited user account approval and provisioning process."
            ),
            (
                False,
                1,
                "Are system administrative access privileges restricted to a limited number of authorised individuals?",
                "Ensure all system administrative access privileges are restricted to a limited number of authorised individuals on an as required basis."
            ),
            (
                False,
                1,
                "Are user accounts assigned to specific individuals and are staff trained not to disclose their password to anyone?",
                "Ensure user accounts are assigned to specific individuals and staff awareness training includes instruction that they are not to disclose their password to anyone."
            ),
            (
                False,
                1,
                "Are all administrative accounts (including service accounts) only used to perform legitimate administrative activities, with no access granted to external email or the Internet?",
                "Ensure that there is a documented and audited user privilege assignment process."
            ),
            (
                False,
                1,
                "Are system administrative accounts (including service accounts) configured to lock out after a number of unsuccessful attempts?",
                "Ensure all system administrative accounts (including service accounts) are subject to a lockout policy."
            ),
            (
                False,
                1,
                "Is there a password policy covering the following points:\n"
                "a. How to avoid choosing obvious passwords (such as those based on easily-discoverable information).\n"
                "b. Not to choose common passwords (use of technical means, using a password blacklist recommended).\n"
                "c. No password reuse.\n"
                "d. Where and how they may record passwords to store and retrieve them securely.\n"
                "e. If password management software is allowed, if so, which.\n"
                "f. Which passwords they really must memorise and not record anywhere.\n",
                "Ensure that there is a robust and clear policy in place and advice available to all users in how passwords are to be created and managed."
            ),
            (
                False,
                1,
                "Are users authenticated using suitably strong passwords, as a minimum, before being granted access to applications and computers?",
                "Ensure that the requirement for using strong passwords is enforced with a centralised management solution."
            ),
            (
                False,
                1,
                "Are user accounts removed or disabled when no longer required (e.g.  when an individual changes role or leaves the organisation) or after a predefined period of inactivity (e.g.  3 months)?",
                "Ensure that there is a documented and audited process for staff leaving and role change."
            ),
            (
                False,
                1,
                "Are data shares (shared drives) configured to provide access strictly linked to job function in order to maintain the security of information held within sensitive business functions such as HR and Finance?",
                "Ensure all centrally managed shared drives are adequately controlled and where possible end users should be prevented from creating local shares on their systems."
            ),
        ),
        # Malware Protection
        (
            (
                False,
                1,
                "Has anti-virus or malware protection software been installed on all computers that are connected to or capable of connecting to the Internet?",
                "Ensure Anti-Virus software is installed on appropriate systems as part of a defence in depth strategy."
            ),
            (
                False,
                1,
                "Has anti-virus or malware protection software been kept up-to-date, either by configuring it to update automatically or through the use of centrally managed service?",
                "Ensure all Anti-Virus software is kept fully up to date."
            ),
            (
                False,
                1,
                "Has anti-virus or malware protection software been configured to scan files automatically upon access (including when downloading and opening files, accessing files on removable storage media or a network folder) and scan web pages when accessed (via a web browser)?",
                "Ensure all Anti-Virus software is configured to provide real-time on-access scanning."
            ),
            (
                False,
                1,
                "Has malware protection software been configured to perform regular periodic scans (eg daily)?",
                "Ensure all Anti-Virus software is configured to provide regular scans."
            ),
            (
                False,
                1,
                "Does the organisation maintain a list of approved applications?",
                "Ensure that a list of approved applications is maintained and audited with procedures in place to add and remove applications from the list."
            ),
            (
                False,
                1,
                "Are users prevented from installing any other applications and by what means?",
                "Ensure that users cannot install unapproved applications which may contain malware or that malware cannot install them."
            ),
            (
                False,
                1,
                "Is any unknown code limited to execute within a sandbox and cannot access other resources unless the user grants explicit permission?",
                "Ensure that users are alerted to any request for access to resources and any unknown code is only permitted to be executed in a restricted environment."
            )
        ),
        # Patch Management
        (
            (
                False,
                1,
                "Do you apply security patches to all software running on computers and network devices?",
                "Ensure all available security patches are applied in a timely manner."
            ),
            (
                False,
                1,
                "Has software running on computers that are connected to or capable of connecting to the Internet been licensed and supported (by the software vendor or supplier of the software) to ensure security patches for known vulnerabilities are made available?",
                "Ensure that security patches are available for all system software and approved applications."
            ),
            (
                False,
                1,
                "Has out-date or older software been removed from computer and network devices that are connected to or capable of connecting to the Internet?",
                "Ensure that all software is appropriately supported by the Vendor and that software updates are available."
            ),
            (
                False,
                1,
                "Have all security patches for software running on computers and network devices that are connected to or capable of connecting to the Internet been installed within 14 days of release or automatically when they become available from vendors?",
                "Ensure all software updates are applied as quickly as possible to all systems that have access to the Internet."
            ),
            (
                False,
                1,
                "Are all smart phones kept up to date with vendor updates and application updates?",
                "Ensure all software updates are applied as quickly as possible to smart phones."
            ),
            (
                False,
                1,
                "Are all tablets kept up to date with vendor updates and application updates?",
                "Ensure all software updates are applied as quickly as possible to tablets."
            ),
            (
                False,
                1,
                "Do you perform regular vulnerability scans of your internal networks and workstations to identify possible problems and ensure they are addressed?",
                "Ensure regular vulnerability scans are performed of internal networks and systems and ensure any problems found are addressed."
            ),
            (
                False,
                1,
                "Do you perform regular vulnerability scans (annual or more frequent) of your external network to identify possible problems and ensure they are addressed?",
                "Ensure regular vulnerability scans are performed of external networks and systems and ensure any problems found are addressed."
            )
        )
    ),
    'answer': (
        # Identify
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (3, 'Yes, our employees are trained on identifying phishing emails and our business has a plan in place regarding how to address them.'),
            (2, 'Yes, our employees are trained on identifying phishing emails.'),
            (1, 'Our employees have some knowledge on phishing emails.'),
            (0, 'No, our employees have not been trained to deal with phishing emails.')
        ),
        (
            (4, 'Only those who require access to the organization’s data for their job functions and who have received management approval to access the data may access the data.'),
            (3, 'Only individuals who have received management approval to access the data may access the data.'),
            (2, 'Only certain departments have access to the information.'),
            (1, 'Anyone currently employed by the organization has access to the information.'),
            (0, 'Anyone who has worked for the organization has access to the information.')
        ),
        (
            (4, 'The operating system is kept up to date with patches as soon as patches are made available.'),
            (3, 'The operating system is updated regularly.'),
            (2, 'Will only update the operating system when the old system is no longer patched and supported by its developer.'),
            (1, 'Will only update the operating system if all current business applications run on the newest version of the system.'),
            (0, 'Never update the operating system.')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (2, 'All users have their own logins.'),
            (1, 'Some systems use a common login'),
            (0, 'No logins in place/one shared login.')
        ),
        (
            (5, 'Multi-factor or 2-factor authentication is used.'),
            (4, 'At least 8 characters, contain Upper-Case Letters, Lower-Case Letters, Numbers, and Symbols.'),
            (3, 'At least 8 characters, contain Upper-Case Letters, Lower-Case Letters, and Numbers.'),
            (2, 'At least 8 characters, contain Upper-Case Letters and Lower-Case Letters.'),
            (1, 'At least 8 characters, contain only letters and numbers.'),
            (0, 'None of the above')
        ),
        (
            (3, 'More than twice a year'),
            (2, 'Twice a year'),
            (1, 'Once a year'),
            (0, 'Never')
        ),
        # Protect
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (3, 'We have a hardware firewall built into our company’s network to protect our internal network structure.'),
            (2, 'We use a software firewall installed on our Windows or Apple computers.'),
            (3, 'We use both hardware and software firewalls.'),
            (0, 'We do not use firewalls.')
        ),
        (
            (4, 'They are trained on hire and annually thereafter.'),
            (3, 'They are trained annually.'),
            (2, 'They are trained one time when they are hired.'),
            (1, 'They are trained as-needed.'),
            (0, 'They are never trained.')
        ),
        (
            (3, 'No, we do NOT allow remote access of any files.'),
            (2, 'Yes, employees use a VPN to connect securely.'),
            (1, 'Yes, but employees cannot access sensitive information from remote locations.'),
            (0, 'None of the options apply.')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (3, 'Both data at rest and in transit are encrypted'),
            (2, 'Some data at rest and transit is encrypted'),
            (1, 'Only data in transit is encrypted'),
            (1, 'Only data at rest is encrypted'),
            (0, 'None of our data is encrypted')
        ),
        (
            (3, 'Data retention is documented and data is destroyed for all types of data'),
            (2, 'Data retention is documented and data is destroyed for our business confidential data only'),
            (0, 'Our data is never destroyed')
        ),
        (
            (4, 'We have incident response plans and business continuity plans in place'),
            (4, 'We have incident recovery and disaster recovery in place'),
            (3, 'We have only business continuity plan in place'),
            (3, 'We have only incident response plans in place'),
            (1, 'We have incident recovery in place'),
            (1, 'We have disaster recovery in place'),
            (0, 'We have no response or recovery plans at all')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        # Detect
        (
            (3, 'Yes, on all devices (desktops, laptops, tablets, phones, servers, etc.).'),
            (2, 'Yes, but only on some devices.'),
            (0, 'No, our devices do not have antivirus software installed.'),
            (0, 'I do not know.')
        ),
        (
            (3, 'Yes, on all devices (desktops, laptops, tablets, phones, servers, etc.).'),
            (2, 'Yes, but only on some devices.'),
            (0, 'No, our devices do not have malware protection.'),
            (0, 'I do not know.')
        ),
        (
            (4, 'Daily'),
            (3, '2-4 times per week'),
            (2, 'Once a week'),
            (1, 'Once a month'),
            (0, 'Never')
        ),
        (
            (4, 'Yes, our network is monitored to detect potential cybersecurity events.'),
            (3, 'Yes, our physical environment is monitored to detect potential cybersecurity events.'),
            (3, 'Yes, personnel activity is monitored to detect potential cybersecurity events.'),
            (0, 'No, we do not have the time to detect potential cybersecurity events.'),
            (0, 'No, we do not have the resources to do so.')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        # Resond
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (1, 'Response processes and procedures are executed in a timely manner.'),
            (1, 'Response activities are coordinated with internal and external stakeholders, as appropriate, to include external support from law enforcement agencies.'),
            (1, 'Analysis is conducted to ensure adequate response and support recovery activities.'),
            (1, 'Activities are performed to prevent expansion of an event, mitigate its effects, and eradicate the incident.'),
            (1, 'Organizational response activities are improved by incorporating lessons learned from current and previous detection/response activities.'),
            (1, 'Recovery processes and procedures are executed to ensure timely restoration of systems or assets affected by cybersecurity events.'),
            (1, 'Recovery planning and processes are improved by incorporating lessons learned into future activities.'),
            (0, 'None of these')
        ),
        (
            (3, 'Yes, the necessary changes are made to the system(s) to stop future events.'),
            (2, 'Changes are made, but the cause has not been discovered.'),
            (1, 'An event has not occurred in the past.'),
            (0, 'No changes are made based on past events.')
        ),
        (
            (3, 'Yes, we have an individual or group readily available and well-trained in this area.'),
            (2, 'Yes, but the individual or group may not be readily available.'),
            (0, 'No, we do not currently have the resources to do this.'),
            (0, 'No, we would establish this after an event occurred.')
        ),
        (
            (2, 'Yes, we can quickly notify our customers.'),
            (2, 'No, our business does not keep any permanent records of customer information.'),
            (1, 'Yes, but it might take some time to notify customers.'),
            (1, 'Yes, but we would have to figure out how to notify our customers.'),
            (0, 'No, we do not know how to notify our customers.')
        ),
        # Recover
        (
            (4, 'Multiple times per day'),
            (3, 'Daily'),
            (2, 'Weekly'),
            (1, 'Monthly'),
            (0, 'Never')
        ),
        (
            (1, 'A legal agency which specializes in cyber crime'),
            (1, 'Law enforcement agency (police, FBI, etc.)'),
            (1, 'Internet service provider(s)'),
            (1, 'Coordinating centers – InfraGard, HITRUST, etc.'),
            (1, 'Public relations agency'),
            (1, 'List of software/hardware vendors who supplied your systems/devices'),
            (0, 'None of the above')
        ),
        (
            (2, 'We have a recovery plan in place that lists clear, comprehensive steps.'),
            (1, 'We have part of a recovery plan in place, but it may be short or vague.'),
            (0, 'We do not have a recovery plan in place.')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        ),
        (
            (1, 'Yes'),
            (0, 'No')
        )
    )
}
