//! Extended SQL injection corpus (user requirement 2026-10-24): about 200 classic payloads across authentication
//! bypass, UNION, boolean/time blind, error based, stacked queries, sub-selects and encodings must be blocked by the
//! detector in at least one of the common field kinds, and everyday text must never be blocked.
//!
//! The corpus is a regression guard, not a completeness claim: `KNOWN_GAPS` lists payload shapes that are still
//! allowed and why.

use hdd_waf_core::{Action, InspectInput, SiteSettings, Verdict, inspect};

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn inspect_query(value: &str, field: &str) -> Verdict {
    let query = format!("{field}={}", percent_encode(value));
    let input = InspectInput {
        method: "GET",
        path: "/login",
        query: Some(&query),
        headers: &[],
        content_type: None,
        body: b"",
    };
    inspect(&input, &SiteSettings::default())
}

fn blocked_somewhere(value: &str) -> bool {
    ["q", "username", "search", "id"]
        .iter()
        .any(|field| inspect_query(value, field).action == Action::Block)
}

/// Shapes that are still allowed on purpose or because blocking them would cut real input:
/// a lone quote or backslash with text around it (`1'`), a bare sub-select with no break-out, a keyword split by a comment
/// that no SQL engine accepts (`O/**/R`), (`char()` equalities are now recognised), and a whole `SELECT * FROM` statement pasted as
/// data (the specification keeps documentation text out of the block list).
const KNOWN_GAPS: &[&str] = &[
    "admin'||'",
    "(SELECT password FROM users LIMIT 1)",
    "' O/**/R 1=1--",
    "1'",
    "1\"",
    "SELECT * FROM users WHERE id=1",
];

const MUST_BLOCK: &[&str] = &[
    r##"' or char(49)=char(49)--"##,
    r##"(1)or(1)=(1)"##,
    r##"' OR (1)=(1)--"##,
    r##"' or char(97)=char(97)#"##,
    r##"' OR ~0--"##,
    r##"' OR 1=1--"##,
    r##"' OR '1'='1"##,
    r##"admin' --"##,
    r##"admin' #"##,
    r##"admin'/*"##,
    r##"' or 1=1 LIMIT 1 --"##,
    r##"" OR ""=""##,
    r##"" OR 1=1--"##,
    r##"') OR ('1'='1"##,
    r##"') OR 1=1--"##,
    r##"' OR 'a'='a"##,
    r##"' OR 1=1#"##,
    r##"' OR 1=1/*"##,
    r##"admin' OR '1'='1'--"##,
    r##"admin')--"##,
    r##"' OR ''='"##,
    r##"1' OR '1'='1' -- -"##,
    r##"' or true--"##,
    r##"' OR 2>1--"##,
    r##"' OR 'x'='x'#"##,
    r##"x' OR 1=1 OR 'x'='y"##,
    r##"' || '1'='1"##,
    r##"' OR 1 -- -"##,
    r##"or 1=1"##,
    r##"' OR TRUE--"##,
    r##"') or ('a'='a"##,
    r##"'-'"##,
    r##"' OR 0=0 --"##,
    r##"' or 5=5#"##,
    r##"" or "a"="a"##,
    r##"") or ("a"="a"##,
    r##"' OR 'unusual'='unusual"##,
    r##"' OR 'text' = N'text"##,
    r##"' OR 1=1 AND 'a'='a"##,
    r##"') OR '1'='1'--"##,
    r##"' UNION SELECT 1,2,3--"##,
    r##"' UNION SELECT NULL--"##,
    r##"' UNION ALL SELECT username,password FROM users--"##,
    r##"1 UNION SELECT table_name,2 FROM information_schema.tables"##,
    r##"' UNION SELECT @@version--"##,
    r##"-1 UNION SELECT 1,group_concat(table_name) FROM information_schema.tables--"##,
    r##"' UNION SELECT sqlite_version()--"##,
    r##"' union select 1,name,sql from sqlite_master--"##,
    r##"1' UNION SELECT user(),database()-- -"##,
    r##"') UNION SELECT 1,2--"##,
    r##"0 UNION SELECT 1,2,3,4"##,
    r##"' UnIoN SeLeCt 1,2,3--"##,
    r##"' UNION%0aSELECT 1,2--"##,
    r##"' /*!UNION*/ /*!SELECT*/ 1,2--"##,
    r##"' UNION/**/SELECT/**/1,2--"##,
    r##"1 UNION ALL SELECT NULL,NULL,NULL--"##,
    r##"' UNION SELECT username||':'||password FROM users--"##,
    r##"' UNION SELECT load_file('/etc/passwd')--"##,
    r##"' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/x'--"##,
    r##"' UNION SELECT current_user,2--"##,
    r##"' union distinct select 1,2--"##,
    r##"1 union select 1,2 from dual"##,
    r##"-1' union select 1,concat(user,0x3a,password) from mysql.user-- -"##,
    r##"1 AND 1=1"##,
    r##"1 AND 1=2"##,
    r##"1' AND '1'='1"##,
    r##"1' AND '1'='2"##,
    r##"1 AND (SELECT COUNT(*) FROM users)>0"##,
    r##"1' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'--"##,
    r##"1 AND ASCII(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>64"##,
    r##"1' AND LENGTH(database())>3--"##,
    r##"1 AND EXISTS(SELECT * FROM users)"##,
    r##"1' AND 1=(SELECT 1 FROM users LIMIT 1)--"##,
    r##"1 OR 1=1"##,
    r##"1) AND (1=1"##,
    r##"1' RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))--"##,
    r##"1 AND MID(version(),1,1)=5"##,
    r##"1' AND ORD(MID((SELECT password FROM users LIMIT 1),1,1))>50#"##,
    r##"1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)"##,
    r##"1 or 1=1 --"##,
    r##"1 ORDER BY 10--"##,
    r##"1' ORDER BY 5-- -"##,
    r##"1 GROUP BY 1,2,3 HAVING 1=1--"##,
    r##"' HAVING 1=1--"##,
    r##"' GROUP BY columnnames HAVING 1=1--"##,
    r##"1 PROCEDURE ANALYSE()"##,
    r##"1; WAITFOR DELAY '0:0:5'--"##,
    r##"1' AND SLEEP(5)--"##,
    r##"1 AND SLEEP(5)"##,
    r##"1';SELECT pg_sleep(5)--"##,
    r##"1' OR SLEEP(5)#"##,
    r##"1 AND BENCHMARK(5000000,MD5(1))"##,
    r##"'; WAITFOR DELAY '0:0:10'--"##,
    r##"1) AND SLEEP(5) AND (1=1"##,
    r##"1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)"##,
    r##"' OR pg_sleep(5)--"##,
    r##"1' AND IF(1=1,SLEEP(5),0)--"##,
    r##"1;SELECT randomblob(1000000000)--"##,
    r##"1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--"##,
    r##"1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1"##,
    r##"'||(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM dual)||'"##,
    r##"1' AND (SELECT COUNT(*) FROM generate_series(1,5000000))>0--"##,
    r##"' AND extractvalue(1,concat(0x7e,version()))--"##,
    r##"' AND updatexml(1,concat(0x7e,(SELECT user())),1)--"##,
    r##"1 AND 1=CONVERT(int,(SELECT @@version))"##,
    r##"' AND 1=CAST((SELECT version()) AS int)--"##,
    r##"' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)a)--"##,
    r##"1' AND EXP(~(SELECT * FROM (SELECT user())a))--"##,
    r##"' AND GTID_SUBSET(version(),1)--"##,
    r##"1 AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version())) USING utf8)))"##,
    r##"' || (SELECT CTXSYS.DRITHSX.SN(user,(select banner from v$version where rownum=1)) FROM dual)--"##,
    r##"'; SELECT 1/0--"##,
    r##"' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE rownum=1))--"##,
    r##"'; DROP TABLE users--"##,
    r##"1; DROP TABLE users"##,
    r##"'; INSERT INTO users VALUES('a','b')--"##,
    r##"1; UPDATE users SET password='x' WHERE username='admin'--"##,
    r##"'; DELETE FROM users--"##,
    r##"1; EXEC xp_cmdshell('whoami')--"##,
    r##"'; EXEC master..xp_cmdshell 'dir'--"##,
    r##"1;SHUTDOWN--"##,
    r##"'; TRUNCATE TABLE users--"##,
    r##"1; CREATE TABLE x(a int)--"##,
    r##"'; ALTER TABLE users ADD x int--"##,
    r##"1; GRANT ALL ON *.* TO 'a'@'%'--"##,
    r##"'; SELECT * FROM users;--"##,
    r##"1;SELECT load_extension('x')--"##,
    r##"'; ATTACH DATABASE '/tmp/x.db' AS x--"##,
    r##"'; PRAGMA table_info(users)--"##,
    r##"1; COPY users TO '/tmp/x'--"##,
    r##"'; SET @a=1--"##,
    r##"1; DECLARE @q VARCHAR(99);SET @q='\\x'; EXEC master.dbo.xp_dirtree @q--"##,
    r##"' AND (SELECT password FROM users WHERE username='admin')='x'--"##,
    r##"' OR (SELECT COUNT(*) FROM users)>0--"##,
    r##"1 AND (SELECT user FROM mysql.user LIMIT 1)"##,
    r##"' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--"##,
    r##"' IN (SELECT password FROM users)--"##,
    r##"1 AND 1 IN (SELECT 1)"##,
    r##"' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sysobjects),1,1))>64--"##,
    r##"' OR 1=(SELECT 1)--"##,
    r##"1' AND (SELECT 'a' FROM users LIMIT 1)='a"##,
    r##"%27%20OR%201%3D1--"##,
    r##"%27+OR+%271%27%3D%271"##,
    r##"%2527%2520OR%25201%253D1--"##,
    r##"'/**/OR/**/1=1--"##,
    r##"'%09OR%091=1--"##,
    r##"'%0aOR%0a1=1--"##,
    r##"' oR 1=1--"##,
    r##"' Or '1'='1"##,
    r##"%u0027 OR 1=1--"##,
    r##"&#39; OR 1=1--"##,
    r##"\' OR 1=1--"##,
    r##"' OR 1=1--%00"##,
    r##"'+OR+1=1+--+"##,
    r##"' OR(1)=(1)--"##,
    r##"' OR 1 LIKE 1--"##,
    r##"' OR 1 BETWEEN 0 AND 2--"##,
    r##"' OR 1 IN (1)--"##,
    r##"'||1=1--"##,
    r##"' or 0x31=0x31--"##,
    r##"' OR 'a'=CHAR(97)--"##,
    r##"UNI%4fN SEL%45CT 1,2"##,
    r##"%55nion %53elect 1,2"##,
    r##"' AND 1=1 UNION%23%0ASELECT 1,2--"##,
    r##"'OR'1'='1"##,
    r##"'or'1'='1'--"##,
    r##"' OR 1=1 LIMIT 1 OFFSET 0--"##,
    r##"admin'--"##,
    r##"'"##,
    r##"''"##,
    r##"""##,
    r##"' --"##,
    r##"';"##,
    r##"' )"##,
    r##"\"##,
    r##"') --"##,
    r##"' OR"##,
    r##"'; --"##,
    r##"1 --"##,
    r##"x' AND email IS NULL; --"##,
    r##"'; EXEC sp_configure 'show advanced options',1--"##,
    r##"' ; SELECT sleep(1) --"##,
    r##"' INTO OUTFILE '/tmp/x' --"##,
    r##"'; COPY (SELECT '') TO PROGRAM 'id'--"##,
    r##"1 INTO DUMPFILE '/tmp/x'"##,
    r##"' AND LOAD_FILE('/etc/passwd')--"##,
    r##"' UNION SELECT 1 INTO @a--"##,
    r##"1 or sleep(5)"##,
    r##"id=1 and 1=1"##,
    r##"(1)or(1)=(1)"##,
    r##"-1 OR 1=1"##,
    r##"1e0 UNION SELECT 1"##,
    r##"1.0 UNION SELECT 1"##,
    r##"1' IS NOT NULL OR '1'='1"##,
    r##"' OR username LIKE '%admin%'--"##,
    r##"' OR username LIKE 'a%'#"##,
    r##"'; SELECT * FROM information_schema.columns--"##,
    r##"0' OR 1=1 /*"##,
    r##"' OR 1=1; --"##,
    r##"'""##,
    r##"' AND 1=0 UNION SELECT 1,2--"##,
    r##"'/**/AND/**/1=0/**/UNION/**/SELECT/**/1--"##,
    r##"' || (SELECT 1) --"##,
    r##"';waitfor delay '0:0:1'--"##,
];

const MUST_ALLOW: &[&str] = &[
    r##"hello world"##,
    r##"John O'Brien"##,
    r##"Don't stop believing"##,
    r##"O'Reilly Media"##,
    r##"I want to select a union card for my team"##,
    r##"how to drop a table cloth"##,
    r##"user@example.com"##,
    r##"12 Main Street, Apt 4B"##,
    r##"SELECT is a keyword in SQL (documentation sentence)"##,
    r##"We 'love' this product, 5 stars"##,
    r##"What's the difference between OR and AND in logic?"##,
    r##"a=1&b=2"##,
    r##"2024-10-23 10:15:00"##,
    r##"Smith & Sons Ltd."##,
    r##"gaming laptop 16GB RAM"##,
    r##"NovaCore N7-7800"##,
    r##"100% cotton, size M/L"##,
    r##"cats or dogs?"##,
    r##"1 + 1 = 2"##,
    r##"the quick brown fox -- jumps over"##,
    r##"C++ and C# developer"##,
    r##"Q&A: union rules"##,
    r##"I'll order 2 of them; ship fast"##,
    r##"update your profile settings"##,
    r##"insert coin to continue"##,
    r##"drop shipping 101"##,
    r##"delete my account please"##,
    r##"create new playlist"##,
    r##"O'Neil's #1 pick; best price"##,
    r##"password123"##,
    r##"Passw0rd!"##,
    r##"my--dash--name"##,
    r##"50% off -- today only"##,
    r##"Mary's lamb's wool"##,
    r##"it's 5 o'clock; time to go"##,
];

#[test]
fn the_extended_sql_injection_corpus_is_blocked() {
    let missed: Vec<&str> = MUST_BLOCK
        .iter()
        .copied()
        .filter(|payload| !blocked_somewhere(payload))
        .collect();
    assert!(
        missed.is_empty(),
        "payloads that are no longer blocked: {missed:?}"
    );
    assert!(MUST_BLOCK.len() >= 190, "the corpus must stay large");
}

#[test]
fn everyday_text_is_never_blocked_by_the_extended_rules() {
    for field in ["q", "username", "search", "comment"] {
        for text in MUST_ALLOW {
            let verdict = inspect_query(text, field);
            assert_eq!(
                verdict.action,
                Action::Allow,
                "false positive in `{field}`: {text:?} -> {verdict:?}"
            );
        }
    }
}

#[test]
fn the_known_gaps_are_documented_and_stay_few() {
    assert!(KNOWN_GAPS.len() <= 10);
}

fn inspect_user_agent(agent: &str) -> Verdict {
    let headers = vec![("User-Agent".to_owned(), agent.to_owned())];
    let input = InspectInput {
        method: "GET",
        path: "/",
        query: None,
        headers: &headers,
        content_type: None,
        body: b"",
    };
    inspect(&input, &SiteSettings::default())
}

#[test]
fn announced_attack_tools_are_refused_and_ordinary_clients_are_not() {
    for agent in [
        "sqlmap/1.7.2#stable (https://sqlmap.org)",
        "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)",
        "Mozilla/5.0 (compatible; Acunetix Web Vulnerability Scanner)",
        "gobuster/3.6",
        "Fuzz Faster U Fool v2.1.0 ffuf",
        "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        "WPScan v3.8.25",
    ] {
        let verdict = inspect_user_agent(agent);
        assert_eq!(verdict.action, Action::Block, "{agent}");
        assert_eq!(verdict.rule_id, Some("T1-001"));
        assert_eq!(verdict.category, Some("policy"));
    }
    for agent in [
        "curl/8.7.1",
        "python-requests/2.32.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "HDD-verify-probe/1.0",
        "PostmanRuntime/7.39.0",
    ] {
        assert_eq!(inspect_user_agent(agent).action, Action::Allow, "{agent}");
    }
}
