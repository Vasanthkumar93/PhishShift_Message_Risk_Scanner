"""
PhishShift Dataset Synthesizer and Corpus Builder
Generates 420+ realistic, strictly sanitized (NFR-01, NFR-02) email and SMS records
satisfying FR-01 (duplicate templates), FR-03 (campaign-separated holdouts),
FR-05 (urgent legitimate messages), and Section 05 schema.
"""

import json
import csv
import random
from datetime import datetime, timedelta

def generate_corpus():
    random.seed(42)
    corpus = []
    msg_id = 1

    def make_entry(channel, subject, body, url_features, sender_type, label, campaign, date_offset_days):
        nonlocal msg_id
        entry = {
            "message_id": f"MSG-{msg_id:04d}",
            "channel": channel,
            "subject_or_title": subject,
            "body_text": body,
            "sanitized_url_features": url_features,
            "sender_domain_type": sender_type,
            "label": label,
            "campaign_group": campaign,
            "collected_date": (datetime(2026, 9, 1) + timedelta(days=date_offset_days % 55)).strftime("%Y-%m-%d")
        }
        msg_id += 1
        return entry

    # 1. camp_01_it_urgent_cred (Phishing: Obvious Credential Harvesting) - 40 samples (with near duplicates for FR-01)
    it_cred_templates = [
        ("URGENT: Your Office365 password expires in {hours} hours",
         "Dear Employee, your network password is set to expire today. You must verify your credentials immediately at {url} to prevent account lockout. Failure to do so will result in lost access to your mailbox and active directory services.",
         "lookalike"),
        ("Action Required: IT Helpdesk Account Verification",
         "Notice: Unsynchronized login attempt detected from an unrecognized IP address. Please validate your corporate security key at {url} within 24 hours.",
         "freemail"),
        ("CRITICAL: Storage Quota Exceeded - Mail Delivery Paused",
         "Your corporate inbox has exceeded 99.4% capacity. Several inbound emails are currently held in quarantine. Review and clear cache at {url} immediately.",
         "suspicious"),
        ("System Security Warning: Session Re-Authentication",
         "IT Department requires all active users to renew multi-factor tokens immediately. Click {url} to authenticate and avoid service suspension.",
         "lookalike")
    ]
    for i in range(40):
        tmpl = it_cred_templates[i % len(it_cred_templates)]
        h = random.choice([2, 4, 12, 24])
        url = random.choice(["hxxps://login-microsoft-secure[.]net/auth", "hxxps://portal-verify-it[.]biz/sso", "hxxps://auth-adfs-update[.]org/login"])
        body = tmpl[1].format(hours=h, url=url)
        # introduce deliberate near-duplicates for FR-01 testing
        if i >= 30:
            body = it_cred_templates[0][1].format(hours=24, url="hxxps://login-microsoft-secure[.]net/auth")
        corpus.append(make_entry(
            channel="email",
            subject=tmpl[0].format(hours=h),
            body=body,
            url_features={"url_count": 1, "is_defanged": True, "has_ip": False, "is_shortener": False, "domain": "login-microsoft-secure[.]net"},
            sender_type=tmpl[2],
            label="phishing",
            campaign="camp_01_it_urgent_cred",
            date_offset_days=i
        ))

    # 2. camp_02_payroll_direct_deposit (Phishing: Financial / Payroll Phishing) - 35 samples
    payroll_templates = [
        ("Direct Deposit Account Discrepancy",
         "We were unable to process your bi-weekly direct deposit due to routing number inconsistencies. Please update your banking information at {url} before 5:00 PM EST to ensure prompt settlement.",
         "lookalike"),
        ("Payroll Advisory: 2026 Compensation Tax Form W-2 Review",
         "Your electronic W-2 and compensation adjustment form is ready for review. Access your secure employee payroll dashboard at {url} to confirm deductions.",
         "suspicious"),
        ("Urgent Notification: Unclaimed Year-End Retention Bonus",
         "Human Resources and Finance have processed your supplemental bonus allotment. Confirm your electronic disbursement account at {url}.",
         "freemail")
    ]
    for i in range(35):
        tmpl = payroll_templates[i % len(payroll_templates)]
        url = random.choice(["hxxp://paychex-adp-portal[.]info/direct-deposit", "hxxps://workday-payroll-verify[.]online/tax", "hxxps://payroll-portal-sync[.]cc/bonus"])
        body = tmpl[1].format(url=url)
        if i >= 28:
            body = payroll_templates[0][1].format(url="hxxp://paychex-adp-portal[.]info/direct-deposit")
        corpus.append(make_entry(
            channel="email",
            subject=tmpl[0],
            body=body,
            url_features={"url_count": 1, "is_defanged": True, "has_ip": False, "is_shortener": False, "domain": "paychex-adp-portal[.]info"},
            sender_type=tmpl[2],
            label="phishing",
            campaign="camp_02_payroll_direct_deposit",
            date_offset_days=i + 5
        ))

    # 3. camp_03_courier_delivery_sms (Phishing: Smishing Delivery / Banking SMS) - 45 samples
    smish_templates = [
        ("USPS Alert: Package tracking #US940294 requires redelivery fee of $1.50. Update address at {url} within 12h.", "suspicious"),
        ("DHL Express: Delivery on hold due to missing apartment unit number. Confirm details immediately: {url}", "suspicious"),
        ("Wells Fargo Alert: Unusual debit transaction of $842.10 flagged. If this was not you, lock card at {url}", "freemail"),
        ("FedEx: Shipment status pending clearance at local hub. Verify signature at {url}", "lookalike"),
        ("Alert: Your streaming subscription billing failed. Update card at {url} to keep service active.", "suspicious")
    ]
    for i in range(45):
        tmpl = smish_templates[i % len(smish_templates)]
        url = random.choice(["hxxps://bit[.]ly/usps-pkg-892", "hxxp://tinyurl[.]com/dhl-track-99", "hxxps://t[.]co/wf-sec-alert", "hxxp://ow[.]ly/pkg-track"])
        body = tmpl[0].format(url=url)
        if i >= 38:
            body = smish_templates[0][0].format(url="hxxps://bit[.]ly/usps-pkg-892")
        corpus.append(make_entry(
            channel="sms",
            subject="SMS Notification",
            body=body,
            url_features={"url_count": 1, "is_defanged": True, "has_ip": False, "is_shortener": True, "domain": "bit[.]ly"},
            sender_type=tmpl[1],
            label="phishing",
            campaign="camp_03_courier_delivery_sms",
            date_offset_days=i + 2
        ))

    # 4. camp_04_mfa_push_fatigue (Phishing: MFA bypass / credential prompt) - 30 samples
    mfa_templates = [
        ("Okta Verify: New Device Enrollment",
         "A new iPhone 15 requested enrollment for your Okta Single Sign-On account. If you did not initiate this, deny and reset security questions at {url} promptly.",
         "lookalike"),
        ("Duo Security: Multiple Denied Push Notifications Detected",
         "Security alert: 5 consecutive push notifications were denied for your corporate profile. Your token is locked. Synchronize hardware key at {url}.",
         "suspicious"),
        ("Microsoft Authenticator: Session Invalidation Notice",
         "Your cloud authentication session has been flagged for unexpected geographic velocity. Re-establish trusted credentials at {url}.",
         "lookalike")
    ]
    for i in range(30):
        tmpl = mfa_templates[i % len(mfa_templates)]
        url = random.choice(["hxxps://okta-sso-verify[.]net/enroll", "hxxps://duo-sec-push[.]co/auth", "hxxps://msft-authenticator-reset[.]xyz/login"])
        body = tmpl[1].format(url=url)
        corpus.append(make_entry(
            channel="email",
            subject=tmpl[0],
            body=body,
            url_features={"url_count": 1, "is_defanged": True, "has_ip": False, "is_shortener": False, "domain": "okta-sso-verify[.]net"},
            sender_type=tmpl[2],
            label="phishing",
            campaign="camp_04_mfa_push_fatigue",
            date_offset_days=i + 10
        ))

    # 5. UNSEEN HOLDOUT CAMPAIGN 1: camp_05_unseen_vendor_wire (Novel phrasing, vendor banking change) - 20 samples
    wire_templates = [
        ("Notice of Banking Institution Relocation & Updated Remittance Advice",
         "Greetings, Please find attached the updated ACH routing coordinates for Apex Solutions Ltd effective for invoice #INV-2026-881. Our treasury team transitioned commercial banking partners. Please route pending wire transactions to the new escrow ledger detailed at {url}. Warm regards, Accounts Receivable.",
         "external_known"),
        ("Fiscal Year 2027 Supplier Remittance Profile Transition",
         "Hello team, In accordance with quarterly compliance reconciliations, please review the revised direct credit clearing instructions for upcoming contract disbursements at {url}. Thank you for your continued partnership.",
         "suspicious")
    ]
    for i in range(20):
        tmpl = wire_templates[i % len(wire_templates)]
        url = random.choice(["hxxps://remit-portal-doc[.]cloud/invoice-881", "hxxps://apex-treasury-banking[.]top/remit"])
        body = tmpl[1].format(url=url)
        corpus.append(make_entry(
            channel="email",
            subject=tmpl[0],
            body=body,
            url_features={"url_count": 1, "is_defanged": True, "has_ip": False, "is_shortener": False, "domain": "remit-portal-doc[.]cloud"},
            sender_type=tmpl[2],
            label="phishing",
            campaign="camp_05_unseen_vendor_wire",
            date_offset_days=i + 15
        ))

    # 6. UNSEEN HOLDOUT CAMPAIGN 2: camp_06_unseen_executive_giftcard (Unfamiliar conversational phrasing) - 20 samples
    exec_templates = [
        ("Quick favor - Are you at your desk right now?",
         "Hey, I am tied up in an offsite executive strategic summit and cannot take incoming telephone calls. Could you quickly assist me with an urgent confidential task for the regional leadership team? Let me know once you see this message.",
         "freemail"),
        ("Discreet inquiry regarding department recognition cards",
         "Good morning. I need a confidential supplier procurement favor before the end-of-quarter board assembly. Please confirm your mobile number so I can send the specifications for the procurement cards.",
         "freemail"),
        ("Urgent executive task: Vendor electronic gift tokens",
         "Hi, please check the project document at {url} regarding our surprise employee wellness incentives. Keep this confidential between us until the company announcement.",
         "freemail")
    ]
    for i in range(20):
        tmpl = exec_templates[i % len(exec_templates)]
        url = "hxxps://drive-sharepoint-view[.]link/doc" if "{url}" in tmpl[1] else ""
        body = tmpl[1].format(url=url) if "{url}" in tmpl[1] else tmpl[1]
        has_url = 1 if url else 0
        corpus.append(make_entry(
            channel="email",
            subject=tmpl[0],
            body=body,
            url_features={"url_count": has_url, "is_defanged": True, "has_ip": False, "is_shortener": False, "domain": "drive-sharepoint-view[.]link" if has_url else "none"},
            sender_type=tmpl[2],
            label="phishing",
            campaign="camp_06_unseen_executive_giftcard",
            date_offset_days=i + 20
        ))

    # 7. UNSEEN HOLDOUT CAMPAIGN 3: camp_07_unseen_collab_sharepoint (Document sharing smishing/email) - 20 samples
    collab_templates = [
        ("Document Shared: 'Q3_Confidential_Salary_Grading_Structure.pdf'",
         "Sarah from Human Capital shared a secured cloud dossier with you: 'Q3_Confidential_Salary_Grading_Structure.pdf'. This item is hosted on corporate cloud storage. Click {url} to authenticate through single sign-on viewer.",
         "lookalike"),
        ("SMS Notification: Project blueprint shared",
         "Team member marked task urgent: review design specs at {url} prior to 4 PM sync.",
         "suspicious")
    ]
    for i in range(20):
        tmpl = collab_templates[i % len(collab_templates)]
        url = random.choice(["hxxps://onedrive-secure-share[.]site/doc89", "hxxps://is[.]gd/sharepoint92"])
        body = tmpl[1].format(url=url)
        channel = "sms" if "SMS" in tmpl[0] else "email"
        corpus.append(make_entry(
            channel=channel,
            subject=tmpl[0],
            body=body,
            url_features={"url_count": 1, "is_defanged": True, "has_ip": False, "is_shortener": "is[.]gd" in url, "domain": "onedrive-secure-share[.]site"},
            sender_type=tmpl[2],
            label="phishing",
            campaign="camp_07_unseen_collab_sharepoint",
            date_offset_days=i + 25
        ))

    # -------------------------------------------------------------
    # LEGITIMATE DATASET (Total 210 records)
    # -------------------------------------------------------------

    # 8. camp_benign_it_password_reset (CRITICAL FOR FR-05 & AT-01: Legitimate urgent password resets) - 40 samples
    legit_it_templates = [
        ("Scheduled Active Directory Password Expiry Warning - 7 Days Remaining",
         "Dear Colleague, In accordance with company cybersecurity policy, your corporate password will expire in 7 days. You may update your password on your domain-joined laptop by pressing Ctrl+Alt+Del and selecting 'Change a password', or by visiting the internal portal at hxxps://sso.internal.corp[.]local/myprofile. IT will never ask for your current password.",
         "internal"),
        ("IT Support Ticket #84912 Closed: Self-Service Password Reset Completed",
         "Hello, This automated notification confirms that your corporate network credentials were successfully updated on your managed workstation. If you did not perform this action, please call the IT helpdesk extension x4433 immediately.",
         "internal"),
        ("Annual Security Token Rollover Reminder",
         "Good morning, IT Enterprise Infrastructure is performing routine certificate renewal for all engineering VPN profiles. No action is required unless your connection drops. Documentation is on the internal intranet at hxxps://intranet.corp[.]local/wiki/vpn-renew.",
         "internal"),
        ("Notice: Multi-Factor Authentication Backup Codes Generation",
         "Greetings from Enterprise Security. We recommend generating backup authentication codes for your corporate smartphone authenticator app. Navigate to your security settings in your employee portal.",
         "internal")
    ]
    for i in range(40):
        tmpl = legit_it_templates[i % len(legit_it_templates)]
        corpus.append(make_entry(
            channel="email",
            subject=tmpl[0],
            body=tmpl[1],
            url_features={"url_count": 1 if "hxxps" in tmpl[1] else 0, "is_defanged": True, "has_ip": False, "is_shortener": False, "domain": "internal.corp[.]local"},
            sender_type=tmpl[2],
            label="legitimate",
            campaign="camp_benign_it_password_reset",
            date_offset_days=i
        ))

    # 9. camp_benign_finance_payroll (CRITICAL FOR FR-05: Legitimate payroll & benefits) - 40 samples
    legit_finance_templates = [
        ("Payroll Processing Schedule for Upcoming Public Holiday",
         "Team, Due to the upcoming bank holiday next Monday, all timesheet submissions for the current pay period must be approved by Thursday at 3:00 PM. Direct deposit disbursements will be initiated on Friday as scheduled through our payroll partner ADP.",
         "internal"),
        ("Important: Health Benefits Open Enrollment 2027 Documentation",
         "Human Resources and Benefits Administration has published the 2027 health, vision, and dental plan comparisons. Open enrollment commences next Tuesday. Visit the internal employee benefits hub at hxxps://benefits.internal.corp[.]local for plan matrices.",
         "internal"),
        ("Quarterly Expense Reimbursement Cut-Off Deadline",
         "All employees with outstanding business travel or meal expense reports are kindly requested to submit Concur receipts before the month-end close on Friday at 5:00 PM.",
         "internal"),
        ("Annual 401(k) Matching Contribution Summary Statement",
         "Your fiscal year employer retirement matching contribution statement is now archived and accessible in your employee portal document repository.",
         "internal")
    ]
    for i in range(40):
        tmpl = legit_finance_templates[i % len(legit_finance_templates)]
        corpus.append(make_entry(
            channel="email",
            subject=tmpl[0],
            body=tmpl[1],
            url_features={"url_count": 1 if "hxxps" in tmpl[1] else 0, "is_defanged": True, "has_ip": False, "is_shortener": False, "domain": "benefits.internal.corp[.]local" if "hxxps" in tmpl[1] else "none"},
            sender_type=tmpl[2],
            label="legitimate",
            campaign="camp_benign_finance_payroll",
            date_offset_days=i + 5
        ))

    # 10. camp_benign_routine_hr (Legitimate HR communications, routine policies) - 40 samples
    legit_hr_templates = [
        ("Welcome to our new team members joining this week",
         "Please join us in giving a warm welcome to our new team members joining the engineering and customer success departments today! Check the internal intranet for introductory bios and team coffee chat links.",
         "internal"),
        ("Notice: Workplace Ergonomic Assessments Available",
         "Health & Safety is organizing complimentary virtual ergonomic workspace assessments this month. If you are interested in a consultation, reach out to facilities@corp.local.",
         "internal"),
        ("Monthly All-Hands Meeting Agenda & Q&A Link",
         "Hi everyone, Here is the scheduled agenda for our Thursday All-Hands company briefing. Topics include Q3 milestone reviews and global product rollout updates. Slido link for questions is available on the calendar invite.",
         "internal"),
        ("Reminder: Flexible Remote Work Stipend Submission",
         "Employees eligible for the annual remote work equipment reimbursement should submit eligible hardware invoices through standard accounting channels by November 15.",
         "internal")
    ]
    for i in range(40):
        tmpl = legit_hr_templates[i % len(legit_hr_templates)]
        corpus.append(make_entry(
            channel="email",
            subject=tmpl[0],
            body=tmpl[1],
            url_features={"url_count": 0, "is_defanged": True, "has_ip": False, "is_shortener": False, "domain": "none"},
            sender_type=tmpl[2],
            label="legitimate",
            campaign="camp_benign_routine_hr",
            date_offset_days=i + 8
        ))

    # 11. camp_benign_system_alerts (Legitimate vendor alerts, GitHub, Jira, AWS) - 45 samples
    legit_sys_templates = [
        ("[Jira] Issue PROJ-409 assigned to you by Tech Lead",
         "Tech Lead assigned task PROJ-409 'Refactor database connection pooling' to your queue. Priority: High. View ticket details on Jira workspace.",
         "external_known"),
        ("[GitHub] Security advisory alert: dependabot bumped certifi to 2026.07.22",
         "Automated security alert from GitHub: dependabot opened pull request #114 to upgrade certifi library across repository services.",
         "external_known"),
        ("Amazon Web Services: Scheduled Maintenance for RDS Postgres Cluster",
         "AWS Notification: Your Multi-AZ RDS instance in region us-east-1 is scheduled for non-disruptive minor maintenance on Sunday between 02:00 UTC and 03:00 UTC.",
         "external_known"),
        ("Google Calendar: Invitation 'Sprint Retrospective & Sprint Planning' @ Fri 10am",
         "You have been invited to Sprint Retrospective & Sprint Planning. Guests: Core Engineering Team. Google Meet link attached to meeting invitation.",
         "external_known")
    ]
    for i in range(45):
        tmpl = legit_sys_templates[i % len(legit_sys_templates)]
        corpus.append(make_entry(
            channel="email",
            subject=tmpl[0],
            body=tmpl[1],
            url_features={"url_count": 0, "is_defanged": True, "has_ip": False, "is_shortener": False, "domain": "none"},
            sender_type=tmpl[2],
            label="legitimate",
            campaign="camp_benign_system_alerts",
            date_offset_days=i + 12
        ))

    # 12. camp_benign_sms_notifications (Legitimate OTPs, Bank Alerts, Courier texts) - 45 samples
    legit_sms_templates = [
        ("Your verification code is 849201. It will expire in 10 minutes. Do not share this code with anyone.", "external_known"),
        ("Chase Fraud Protection: Did you attempt a $24.50 charge at COFFEE SHOP? Reply YES if recognized, NO if unauthorized.", "external_known"),
        ("FedEx: Delivery scheduled for today between 1:00 PM and 4:30 PM. Signature not required. Track on fedex[.]com with tracking #891024.", "external_known"),
        ("United Airlines: Flight UA 402 to Chicago is on schedule departing Gate C12 at 14:35. Boarding begins at 14:00.", "external_known"),
        ("IT Helpdesk: Your VPN two-factor temporary access token is 502914. Valid for 5 minutes.", "internal")
    ]
    for i in range(45):
        tmpl = legit_sms_templates[i % len(legit_sms_templates)]
        corpus.append(make_entry(
            channel="sms",
            subject="SMS Notice",
            body=tmpl[0],
            url_features={"url_count": 0, "is_defanged": True, "has_ip": False, "is_shortener": False, "domain": "none"},
            sender_type=tmpl[1],
            label="legitimate",
            campaign="camp_benign_sms_notifications",
            date_offset_days=i + 3
        ))

    return corpus

if __name__ == "__main__":
    records = generate_corpus()
    print(f"Total records generated: {len(records)}")
    
    # Save JSON
    with open("data/phishshift_corpus.json", "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    
    # Save CSV
    with open("data/phishshift_corpus.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "message_id", "channel", "subject_or_title", "body_text", 
            "sanitized_url_features", "sender_domain_type", "label", 
            "campaign_group", "collected_date"
        ])
        writer.writeheader()
        for r in records:
            r_copy = dict(r)
            r_copy["sanitized_url_features"] = json.dumps(r_copy["sanitized_url_features"])
            writer.writerow(r_copy)

    print("Successfully built data/phishshift_corpus.json and data/phishshift_corpus.csv")
