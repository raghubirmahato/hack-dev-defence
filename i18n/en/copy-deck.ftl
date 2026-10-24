# HDD copy deck: the English source strings of B13 (T-0019 step 5).
# Naming: keys are lowercase semantic words joined by hyphens (for example domain-add-title), never sentences.
# Each value is the exact English text of the B13 table in docs/SPEC.md; a key whose text is missing would keep an
# empty value with the comment `# empty: needs text` above it. Do not add a key that B13 does not define: the
# `ux-docs` style check compares the key set and every value with the master specification.

tagline = Put a firewall in front of your website. See what it blocks. Undo anything.
claims-footnote = HDD reduces exposure to common web attacks. It does not replace patching your application.
signup-title = Create your account
signup-email-sent = If this address can be used, we sent a message with a link to continue. Check your inbox and spam folder.
login-error = Email or password is incorrect.
login-locked = Too many attempts. Try again in a few minutes.
mfa-required = Add a second step to keep your account safe.
recovery-codes-warning = Save these codes now. We show them only once. Each code works one time.
domain-add-title = Add a website
domain-add-help = Enter the domain you own, like example.org. We will look at its current DNS and show you what to change. Nothing changes until you do it.
integration-full-ns = Use HDD nameservers (recommended). HDD answers DNS for your domain and protects every proxied name.
integration-cname = Keep your DNS provider. Point a name such as www at HDD with one CNAME record.
integration-apex-note = A CNAME cannot be used at the root of a domain. Use an A record, an ALIAS/ANAME record, or switch to HDD nameservers.
verify-dns-txt = Add this TXT record at your DNS provider to prove you own the domain.
verify-http-file = Or publish this file at the path shown.
monitor-explainer = Monitor mode records what HDD would block but lets every request through. Use it first.
block-confirm-title = Switch {domain} to block mode?
block-confirm-body = HDD will block matching requests and ban the sending IP address. Visitors sharing an address with an attacker can be affected. You can switch back at any time.
shield-title = Assume your website has bugs
shield-body = The shield uses stricter rules and bans an address on its first clear attack attempt, such as a SQL injection typed into a login form. It reduces exposure; it does not fix vulnerable code.
shield-limit = Signature-based detection can miss new techniques. Keep your software updated.
block-page-title = Access denied
block-page-body = Your request looked like an attack on this website, so it was blocked. If you believe this is a mistake, you can tell the site owner.
block-page-ray = Reference: {ray_id}
appeal-title = Report a mistaken block
appeal-sent = Thank you. The site owner can review your report using the reference above.
ban-self-warning = This change would block your own address ({ip}). You would lose access to your site.
virtual-patch-banner = A virtual patch is not a fix. The vulnerability remains open until the component is updated.
readiness-footnote = Measures configuration completeness, not security.
empty-events = No events yet. When requests reach this domain, they appear here within seconds.
empty-domains = You have not added a website yet. Add one to get started.
unknown-value = Unknown ({reason})
cutover-warning = Changing nameservers affects your whole domain, including email. Review the checklist first.
rollback-instruction = To undo: set the nameservers back to {old_ns} at your registrar. This can take up to {ttl} to take effect.
under-attack-title = Under attack mode
under-attack-body = New visitors must pass a quick automatic check. Real visitors may see a brief delay. It turns off automatically at {time}.
impersonation-banner = You are viewing {org} as read-only support. Session ends in {remaining}.
admin-banner = Platform admin
