# Incident Response Playbook: Ransomware Attack on Hodasi Incorporated

**Author:** Selorm Hodasi ([GitHub: Skhodasi](https://github.com/Skhodasi))
**Category:** Blue Team / Incident Response / Security Operations
**Status:** Complete — playbook written, tabletop exercise conducted and documented
**Framework:** NIST SP 800-61 Rev. 2

## Summary

This project is an incident response playbook — a step-by-step guide for what to do if hackers attack — built around a fictional ransomware incident at a fictional company, **Hodasi Incorporated**, a sports equipment and apparel maker and retailer. After writing the plan, I ran a tabletop (practice) exercise to see if the plan actually holds up when real decisions have to be made under pressure.

The company and the people in this story are made up. But the attack itself isn't invented out of thin air — the timeline, and especially the mistakes in spotting and responding to it, are based on a real, well-documented ransomware attack: the **May 2021 attack on Ireland's public healthcare system (the HSE)**, one of the most serious ransomware attacks ever recorded against a public organization. That real event was investigated afterward by outside experts (PwC), and their findings are public. I built a fictional company around that real attack pattern instead of using the real healthcare organization, since I wasn't involved in that response and don't have inside knowledge of their systems — but the mistakes and missed warning signs described below are based on what really happened, not invented for effect.

This plan follows NIST SP 800-61's four-phase incident response lifecycle: **Phase 1: Preparation → Phase 2: Detection & Analysis → Phase 3: Containment, Eradication & Recovery → Phase 4: Post-Incident Activity.**

## Scenario

**The company:** Hodasi Incorporated — about 200 employees, head office in Winnipeg, with a factory, a separate warehouse, and an online store. The important systems: the inventory/manufacturing scheduling system, the warehouse order-picking system, the online store (which also stores customer order and payment information), the shared company file drive, and email.

**Timeline:**

| Date | What happened |
|---|---|
| Aug 16 | Someone in Accounts Payable opens an email that looks like it's from a vendor, with an attached invoice file. It's actually a trick — opening it quietly installs hidden malware onto their computer. This is where the attack starts. |
| Aug 23 | The hackers set up a way to keep getting into the computer even if it's restarted (persistence). |
| Sep 1 | Antivirus notices tools commonly used by hackers to move around inside a network — but the alert just sits there. Nobody looks into it or raises the alarm. |
| Sep 1 – Oct 4 | For about five weeks, the hackers quietly explore the network undetected, using the access they already have. |
| Oct 5 | The hackers get into two more important systems — inventory/manufacturing and the warehouse system. Antivirus flags the same warning signs again. Again, nobody acts. |
| Oct 6–8 | The hackers reach the online store's backend systems and the shared company file drive. |
| Oct 9 | The online store lead notices checkout issues and odd account activity. IT resets a few passwords and runs a scan — but doesn't connect it to the antivirus warnings from weeks earlier, since those were never turned into an actual investigation. |
| Oct 10 | Unusual network activity is spotted, but it's mistakenly assumed to be a remote warehouse employee logging in over VPN. Because of this, the company waits before calling in outside help. |
| Oct 11 | Ransomware detonates everywhere at once — inventory, warehouse, online store, and shared files are all locked. Manufacturing stops, the website goes down, and orders can't ship. IT disconnects the company from the internet to stop further spread. **This is officially declared a security incident.** |

**The damage:** About 75% of the company's systems were locked up. Manufacturing was stopped for over a week, and the online store was down during Thanksgiving and Black Friday — two of the busiest shopping periods of the year. Full recovery took about 10 weeks.

## Phase 1: Preparation — Getting Ready Before Anything Happens

Think of this like a fire drill — everything that should already be in place *before* an attack happens. These are the gaps Hodasi Incorporated had, based on the same kinds of gaps found in the real HSE attack this story is modeled on:

- **No one had clear authority to declare an emergency** across the factory, warehouse, and online store — three teams that don't normally talk to each other about security.
- **The company relied only on antivirus software**, with no one actually watching and following up on what it flagged. The software did its job twice; the people and processes around it didn't.
- **There was no written, practiced emergency plan.** The first time anyone figured out their role in a situation like this was during the actual attack, not before it.
- **IT was split into silos.** Manufacturing, the warehouse, and the online store each managed their own technology separately, with no shared process for raising the alarm.
- **Nobody had an up-to-date inventory of systems**, which made it harder to figure out exactly what needed fixing once the attack was discovered.

### What Should Happen Instead

1. Name an incident commander beforehand — someone with authority across all departments, decided before any emergency, not during one.
2. Set a firm rule: if any security tool detects known hacking tools, someone investigates within 1 hour — no alert sits unreviewed, even if marked "low priority."
3. Use security monitoring that's actually reviewed by a person, not just antivirus running in the background with nobody watching (e.g. a SIEM like Splunk).
4. Write the emergency plan down, and actually practice it with a tabletop exercise at least once a year.
5. Keep an up-to-date, easy-to-find inventory of every important system across all parts of the business.

## Phase 2: Detection & Analysis — Spotting the Attack

This wasn't a sneaky attack that was impossible to catch — it was caught twice (Sep 1 and Oct 5) and nobody followed up either time. If the company had acted on the first warning, they'd have had over five weeks' head start before the hackers caused any real damage on Oct 11. That five-week gap is the single biggest missed opportunity in this whole story.

**What should have happened the moment that first warning appeared on September 1:**
1. Confirm it's a real threat — the hacking tools flagged here have no normal, everyday business use.
2. Disconnect that computer from the network right away.
3. Treat it as high priority immediately — don't wait to see if anything bad actually happens first.
4. Check the rest of the network for the same warning signs before the hackers get a chance to spread further.

## Connecting the Dots: How Projects 1 and 2 Help Here

This project doesn't exist in isolation — it's built to use the actual skills from my first two projects, not just mention them in passing.

### Using Project 1's Detection Approach to Fix the Biggest Gap

The single biggest failure here is that real detections on Sep 1 and Oct 5 sat unescalated. That's exactly the gap [Project 1 (home-lab detection)](https://github.com/Skhodasi/detection-lab-password-spray) was built to close: turning a raw log signal into a correlation search and a real-time alert that nobody has to notice by luck. Using the same Splunk approach as Project 1's password-spray detection rule:

```spl
index=* sourcetype=antivirus (signature="Cobalt Strike" OR signature="Mimikatz")
| stats count min(_time) as first_seen by host, signature
```

Saved as a real-time alert (same pattern as Project 1): trigger condition Per-Result, action = page the on-call analyst immediately, not just "add to triggered alerts" and wait for someone to check. That one configuration choice — page versus passively log — is the entire difference between this incident ending on September 1 and ending on October 11.

### Using Project 2's Approach to Investigate the Email That Started This

The entry point (Aug 16) was a phishing email with a malicious attachment — precisely what [Project 2 (phishing/IOC investigation)](https://github.com/Skhodasi/phishing-investigation-ioc-enrichment) was built to analyze. If that email had been reported instead of opened, the same extraction script from Project 2 would have pulled its indicators of compromise within seconds: sender domain, IP addresses, embedded links. Enriching that domain against VirusTotal (Project 2's second script) would very likely have flagged it as newly registered and unrelated to any real vendor — giving Hodasi Incorporated a chance to block it before anyone opened the attachment at all.

Together, these two projects aren't just earlier portfolio pieces sitting next to this one — they're the two technical building blocks (detection engineering and IOC investigation) that this playbook's Preparation and Detection phases are actually asking the company to have in place.

## Phase 3: Containment, Eradication & Recovery — Stopping It, Cleaning Up, and Getting Back Online

### Stopping It (What Should Have Happened on Sep 1 and Oct 5 — Not Oct 11)
- Disconnect any flagged computer or server from the network the moment hacking tools are confirmed — don't wait until files start getting locked up.
- Immediately reset passwords for any account used on a flagged computer, rather than waiting until there's no other choice.
- Call in outside security help the moment known hacking tools are confirmed, instead of spending days internally debating whether it's really a problem.

### Cleaning Up
- Don't just "clean" an infected machine — wipe it and rebuild from a known-safe copy. Patching risks missing a hidden backdoor.
- Close the actual entry point: stop allowing email attachments with embedded macros company-wide, since an exception had been made for Accounts Payable's vendor invoices.

### Getting Back Online
- Find the most recent backup that's actually confirmed clean — not just the most recent backup. Here, the nightly backups from the three nights before the attack were also partly compromised, since the hackers had already reached the file server. The only trustworthy backup predates Sep 1.
- Restore in an isolated environment first, confirm it's clean, then bring systems back online in order: manufacturing first, then the warehouse, then the online store, then general files.
- Monitor closely for at least 72 hours after restoring to confirm the infection doesn't reappear.

## Phase 4: Post-Incident Activity — What We Do Afterward

- Hold a "what went wrong, what went right" meeting within a week, including IT, manufacturing, the warehouse manager, the online store lead, and the outside security firm.
- Document the full timeline (like the one above) and keep it on file for next time.
- Report the real cost to leadership: days of lost production, affected online sales, and what's already been fixed.
- Determine whether customer data was actually accessed (not just encrypted) — if so, Canadian privacy law may require notifying affected customers. That call goes to a lawyer/privacy expert, not the IT team under pressure.
- Apologize to affected customers for missed or delayed orders and offer a goodwill gesture to protect trust.

## Tabletop Exercise: Testing Whether This Plan Actually Works

Writing a plan is one thing — the real test is whether it holds up when people have to make hard calls under pressure. I walked through this scenario step by step, as if I were the analyst on call, making real decisions at each point, including a couple of curveballs thrown in partway through, the way a real drill would.

| When | What I decided to do |
|---|---|
| Sep 1 — hacking tools spotted on the first infected computer | Disconnect that computer right away, treat it as serious, and open an official investigation. Worst case if I'm wrong: a little wasted time. Worst case if I do nothing: five weeks of hackers quietly spreading — exactly what happened in real life. |
| Oct 5 — hacking tools spotted on two more systems | Declare an official emergency, disconnect both systems, reset every connected password. This is no longer a one-off — it's the hackers spreading. |
| Oct 10 — unusual activity dismissed as normal, help not called in yet | **Curveball 1:** While the team is still debating whether it's a remote employee, the warehouse reports its scanning system has started rejecting valid barcodes — a sign the ransomware may already be starting to lock things up. Decision: call in outside help immediately instead of finishing the internal debate first. |
| While planning recovery | **Curveball 2:** The team discovers the three most recent nightly backups are also partly locked up. Decision: accept losing some recent data and restore from the last confirmed-clean backup — and make "always verify a backup is clean before trusting it" a permanent rule. |
| After the incident is over | **Curveball 3:** Leadership asks whether customers need to be told their payment information may have been exposed. Decision: hand this straight to a lawyer/privacy expert to decide, not have IT figure it out on the spot. |

### What This Taught Me

Walking through a real attack pattern, instead of a tidy made-up one, makes the lesson hard to brush off: the actual gap between "we noticed something" (Sep 1) and "we actually did something" (Oct 11) was over five weeks. Every rule in this plan closes a specific day in that gap — this isn't a vague "be more careful" message, it points at exact moments where a different decision would have changed the outcome. The two curveballs (the bad backups, the legal question) also exposed gaps the first draft of this plan didn't cover — both are now built into the Recovery and Post-Incident sections above.

## Skills Demonstrated

- Applying a recognized industry framework (NIST SP 800-61) to a real-world attack pattern
- Judging how serious a threat is based on the tools/techniques involved, not waiting until damage is done
- Making tough containment and recovery calls, including real trade-offs (accepting some data loss to ensure a backup is safe)
- Running and documenting a tabletop exercise, including moments based on a real incident's actual failures
- Knowing when to hand a decision to someone else (e.g., a lawyer for a privacy question) instead of a technical team deciding alone
- Turning a real, publicly documented security incident into a usable, practical plan rather than a generic checklist
- Connecting detection engineering (Project 1) and IOC investigation (Project 2) to concrete gaps in an incident response lifecycle

## Next Steps

- Build a simple one-page "if you see this, do this" checklist so the biggest lesson here (act within the hour, don't wait) is usable by anyone under pressure, not just a security expert.
- Apply this same approach — fictional company, modeled on a real attack — to a different incident type (e.g., cloud account takeover).
- Turn the illustrative detection rule and phishing-extraction examples above into a working demo run against synthetic log data, the way Projects 1 and 2 were built and validated end-to-end.

## Sources (real incident this scenario is modeled on)

- [Health Service Executive cyberattack — Wikipedia](https://en.wikipedia.org/wiki/Health_Service_Executive_cyberattack)
- [Timeline to a cyberattack: the signs missed before the State's health service was crippled — The Irish Times](https://www.irishtimes.com/news/crime-and-law/timeline-to-a-cyberattack-the-signs-missed-before-state-s-health-service-crippled-1.4752451)
- [Opening of email attachment led to HSE cyber attack, report finds — The Irish Times](https://www.irishtimes.com/news/crime-and-law/opening-of-email-attachment-led-to-hse-cyber-attack-report-finds-1.4752043)
- [Report dissects Conti ransomware attack on Ireland's HSE — GovInfoSecurity](https://www.govinfosecurity.com/report-dissects-conti-ransomware-attack-on-irelands-hse-a-18102)
- [HC3: Lessons Learned from the Ransomware Attack on Ireland's HSE — U.S. Dept. of Health & Human Services](https://www.hhs.gov/sites/default/files/lessons-learned-hse-attack.pdf)
- [Inside Ireland's Public Healthcare Ransomware Scare — Krebs on Security](https://krebsonsecurity.com/2021/12/inside-irelands-public-healthcare-ransomware-scare/)
