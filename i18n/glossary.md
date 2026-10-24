# Glossary (translator copy)

Translator copy of the interface glossary. The terms, the definitions and the `Do not translate` column are the same
as in [docs/UX/glossary.md](../docs/UX/glossary.md); do not edit one copy without the other. `Do not translate` = yes
means the term stays in English in every locale; no means translate it and use the locale's established term.

## Terms

| Term | Plain definition | Do not translate |
| --- | --- | --- |
| WAF | A filter that inspects web requests and blocks those that match a rule. | yes |
| SQL injection | An attack that puts database commands into a request so the database runs them. | no |
| XSS | An attack that puts script into a page so it runs in a visitor's browser. | yes |
| DNS | The system that turns a domain name into the addresses of the servers that answer for it. | yes |
| nameserver | A DNS server that answers the records for a domain. | no |
| CNAME | A DNS record that points one name at another name instead of an address. | yes |
| TLS | The protocol that encrypts traffic between a visitor and a website. | yes |
| HSTS | A rule that tells browsers to use TLS only for a domain after the first visit. | yes |
| origin | The server that hosts the website behind HDD. | no |
| ban | A timed restriction placed on an address after a matching request. | no |
| challenge | A short automatic step that a visitor passes before a request continues. | no |
| Ray ID | The identifier that links a blocked request on the page to one event in the console. | yes |
| proxied | A record state in which that name's traffic passes through HDD. | no |
| monitor mode | A mode that records the requests HDD would block and lets them through. | no |
| block mode | A mode that blocks matching requests and bans the sending address. | no |
| never-ban list | A list of addresses that HDD never bans, even during an attack. | no |
