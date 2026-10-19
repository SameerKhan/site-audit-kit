"""Adversarial table for sql_guard.check_statement. No database anywhere."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import testcfg  # noqa: E402
testcfg.use_config()

import sql_guard  # noqa: E402
from sql_guard import check_statement  # noqa: E402

PUB = "p.post_status = 'publish' AND p.post_type IN ('page','post')"

# (install, sql) that must pass.
ALLOW = [
    # wp_options, a typical preflight probe and the configured option names
    ("site", "SELECT option_value FROM wp_options WHERE option_name='siteurl'"),
    ("site", "SELECT option_name, option_value FROM wp_options WHERE option_name IN "
                "('siteurl','home','permalink_structure','blog_public','rank-math-options-titles')"),
    ("blog", "SELECT option_value FROM wp_options WHERE BINARY option_name = 'blog_public'"),
    ("site", "SELECT o.option_value FROM wp_options o WHERE o.option_name = 'home' AND 1 = 1"),
    ("site", "SELECT option_value FROM wp_options WHERE (option_name = 'home')"),
    ("site", "SELECT COUNT(*) FROM wp_options WHERE 'siteurl' = option_name"),
    # wp_posts without content
    ("site", "SELECT ID, post_title, post_name FROM wp_posts WHERE post_type = 'page' "
                "AND post_status = 'publish'"),
    ("site", "SELECT COUNT(*) FROM wp_posts WHERE post_type <> 'revision'"),
    ("site", "SELECT COUNT(*) FROM wp_posts WHERE post_type != 'revision'"),
    ("site", "SELECT COUNT(*) FROM wp_posts WHERE post_type NOT IN ('revision','nav_menu_item')"),
    ("site", "SELECT post_type, COUNT(*) AS n FROM wp_posts WHERE post_status = 'publish' "
                "GROUP BY post_type ORDER BY n DESC"),
    ("site", "select id, post_parent, post_date, post_modified from wp_posts "
                "where post_type = 'page'"),
    ("site", "SELECT `ID` FROM `wp_posts` WHERE `post_type` = 'page'"),
    ("site", "SELECT ID AS x FROM wp_posts WHERE post_type='page' ORDER BY x LIMIT 10"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' LIMIT 5, 10"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' LIMIT 10 OFFSET 20"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' AND post_title = 'it''s'"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' AND post_title LIKE '50\\%%'"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' AND "
                "post_title = 'a; DROP TABLE x -- # /* */ /*! */'"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' AND post_title = 'café ☕'"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' AND post_title = 'x' 'y'"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type = 'page' AND post_date BETWEEN "
                "'2030-01-01' AND '2030-02-01'"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type = 'page' AND post_date > "
                "DATE '2030-01-01' + INTERVAL 1 DAY"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type = 'page' AND post_parent IS NOT NULL"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type = 'page' AND NOT post_parent = 0"),
    ("site", "SELECT CASE WHEN post_status = 'publish' THEN 1 ELSE 0 END AS pub "
                "FROM wp_posts WHERE post_type = 'page'"),
    ("site", "SELECT SUBSTRING(post_title FROM 1 FOR 10), SUBSTRING(post_name, 1, 5) "
                "FROM wp_posts WHERE post_type='page'"),
    ("site", "SELECT TRIM(BOTH ' ' FROM post_title), TRIM(post_name) FROM wp_posts "
                "WHERE post_type='page'"),
    ("site", "SELECT CAST(ID AS CHAR), CAST(post_parent AS UNSIGNED INTEGER), "
                "CONVERT(post_title USING utf8mb4), CONVERT(ID, CHAR(10)) FROM wp_posts "
                "WHERE post_type='page'"),
    ("site", "SELECT GROUP_CONCAT(DISTINCT post_type ORDER BY post_type DESC SEPARATOR ',') "
                "FROM wp_posts WHERE post_status = 'publish'"),
    ("site", "SELECT COUNT(DISTINCT post_type), MAX(post_date), IFNULL(MIN(ID), 0) FROM wp_posts "
                "WHERE post_status = 'publish'"),
    ("site", "SELECT DISTINCT(post_type) FROM wp_posts WHERE post_status = 'publish'"),
    ("site", "SELECT LOWER(post_name), LENGTH(post_title), LEFT(post_title, 3), "
                "RIGHT(post_title, 3), REPLACE(post_name, '-', '_'), LOCATE('a', post_title), "
                "HEX(ID), DATE_FORMAT(post_date, '%Y-%m'), DATE(post_modified), "
                "IF(post_parent = 0, 'top', 'child'), NULLIF(post_name, ''), "
                "CONCAT_WS('/', post_type, post_name), SUBSTRING_INDEX(post_name, '-', 1) "
                "FROM wp_posts WHERE post_type = 'page'"),
    # post_content: published, public types
    ("site", "SELECT ID, post_content FROM wp_posts WHERE post_status='publish' "
                "AND post_type IN ('post','page')"),
    ("site", "SELECT p.ID, LENGTH(p.post_content) FROM wp_posts p WHERE " + PUB),
    ("site", "SELECT ID FROM wp_posts WHERE post_status = 'publish' AND post_type = 'post' "
                "AND post_content LIKE '%evil.example%'"),
    (sql_guard.InstallPolicy("site", public_post_types=("post", "page", "glossary")),
     "SELECT post_content FROM wp_posts WHERE post_status='publish' AND post_type='glossary'"),
    # wp_postmeta joined to published public posts or templates
    ("site", "SELECT p.ID, m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID "
                "WHERE p.post_status = 'publish' AND p.post_type IN ('page','bricks_template') "
                "AND m.meta_key = '_bricks_page_content_2'"),
    ("site", "SELECT p.ID, m.meta_key, m.meta_value FROM wp_posts AS p INNER JOIN wp_postmeta "
                "AS m ON p.ID = m.post_id WHERE p.post_status='publish' AND p.post_type='post' "
                "AND m.meta_key LIKE 'rank\\_math\\_%'"),
    ("site", "SELECT m.meta_value FROM wp_postmeta m, wp_posts p WHERE m.post_id = p.ID AND "
                "p.post_status = 'publish' AND p.post_type = 'elementor_library' AND "
                "m.meta_key IN ('_elementor_data', '_wp_page_template')"),
    ("blog", "SELECT p.ID, m.meta_value FROM wp_posts p LEFT JOIN wp_postmeta m ON "
             "m.post_id = p.ID AND m.meta_key = 'rank_math_title' WHERE " + PUB),
    ("docs", "SELECT m.meta_value FROM wp_postmeta m JOIN wp_posts p ON p.ID = m.post_id "
             "WHERE " + PUB + " AND m.meta_key LIKE '\\_yoast\\_wpseo\\_%'"),
    # unrestricted tables
    ("site", "SELECT * FROM wp_rank_math_redirections"),
    ("site", "SELECT * FROM wp_rank_math_redirections_cache"),
    ("blog", "SELECT uri, times_accessed FROM wp_rank_math_404_logs ORDER BY times_accessed DESC"),
    ("site", "SELECT t.name, tt.taxonomy, COUNT(*) AS n FROM wp_terms t JOIN wp_term_taxonomy tt "
                "ON tt.term_id = t.term_id GROUP BY t.name, tt.taxonomy ORDER BY n DESC LIMIT 50"),
    ("site", "SELECT r.object_id FROM wp_term_relationships r"),
    # subqueries, CTEs, derived tables, unions
    ("site", "SELECT p.ID FROM wp_posts p WHERE p.post_type='post' AND p.ID IN "
                "(SELECT r.object_id FROM wp_term_relationships r WHERE r.term_taxonomy_id = 5)"),
    ("site", "SELECT p.ID FROM wp_posts p WHERE p.post_type='post' AND EXISTS "
                "(SELECT 1 FROM wp_term_relationships r WHERE r.object_id = p.ID)"),
    ("site", "WITH pub AS (SELECT ID, post_title FROM wp_posts WHERE post_status='publish' "
                "AND post_type='page') SELECT COUNT(*) FROM pub"),
    ("site", "WITH a AS (SELECT term_id FROM wp_terms), b AS (SELECT term_id FROM a) "
                "SELECT COUNT(*) FROM b"),
    ("site", "SELECT d.n FROM (SELECT COUNT(*) AS n FROM wp_posts WHERE post_type='page') AS d"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name='home' UNION ALL "
                "SELECT option_value FROM wp_options WHERE option_name='siteurl'"),
    ("site", "(SELECT name FROM wp_terms) UNION (SELECT slug FROM wp_terms) LIMIT 5"),
    ("site", "SELECT (SELECT COUNT(*) FROM wp_terms) AS terms"),
    # misc
    ("site", "SELECT 1"),
    ("site", "SELECT 1;"),
    ("site", "SELECT 1 ;  \n"),
    ("site", "SELECT 1 FROM DUAL"),
    ("site", "SELECT -1.5e3, 0x41, .5, 1. , X'41', N'x'"),
    ("site", "SELECT CURRENT_USER()"),
    ("site", "SELECT VERSION()"),
    ("site", "SELECT DATABASE()"),
    ("site", "SHOW GRANTS FOR CURRENT_USER()"),
    ("site", "SHOW GRANTS"),
    ("site", "show grants for current_user"),
    ("site", "EXPLAIN SELECT ID FROM wp_posts WHERE post_type='page'"),
    ("site", "SELECT SQL_NO_CACHE DISTINCT name FROM wp_terms"),
    ("site", "SELECT name FROM wp_terms WHERE name REGEXP '^a' AND slug NOT LIKE 'b%' "
                "AND term_id NOT BETWEEN 1 AND 3 AND name SOUNDS LIKE 'x' AND name COLLATE "
                "utf8mb4_bin = 'A'"),
    # read-only views: the views restrict rows and columns, and the guard checks the same column and
    # row rules on top (defence in depth; see test_regressions.ViewsDefenceInDepth).
    ("site_ro", "SELECT ID, post_title FROM wp_posts WHERE post_type = 'page'"),
    ("site_ro", "SELECT post_content FROM wp_posts WHERE post_status = 'publish' "
                      "AND post_type = 'page'"),
    ("site_ro", "SELECT option_name, option_value FROM wp_options WHERE option_name IN "
                      "('siteurl', 'home')"),
    ("site_ro", "SELECT COUNT(*) FROM audit_site.wp_posts WHERE post_type <> 'revision'"),
    ("site_ro", "SELECT COUNT(*) FROM `audit_site`.`wp_posts` WHERE post_type = 'post'"),
    ("blog_ro", "SELECT p.ID, m.meta_value FROM wp_posts p JOIN wp_postmeta m "
                   "ON m.post_id = p.ID WHERE " + PUB + " AND m.meta_key LIKE 'rank\\_math\\_%'"),
    ("blog_ro", "SELECT * FROM wp_rank_math_redirections"),
    # configurable prefix
    (sql_guard.InstallPolicy("site", prefix="xy_"),
     "SELECT ID FROM xy_posts WHERE post_type='page'"),
]

# (install, sql, substring expected in the reason or None)
REJECT = [
    # comments of every kind
    ("site", "SELECT 1 -- x", "comment"),
    ("site", "SELECT 1--1", "comment"),
    ("site", "SELECT 1 --\n", "comment"),
    ("site", "SELECT 1 # x", "comment"),
    ("site", "SELECT 1 #", "comment"),
    ("site", "SELECT 1 /* x */", "comment"),
    ("site", "SELECT /**/ 1", "comment"),
    ("site", "SELECT /*! 1 */", "executable comment"),
    ("site", "SELECT name FROM wp_terms /*!50000 UNION SELECT user_pass FROM wp_users */",
     "executable comment"),
    ("site", "SELECT /*M! 1 */ 1", "executable comment"),
    ("site", "SELECT /*+ MAX_EXECUTION_TIME(1) */ 1", "optimizer hint"),
    ("site", "SELECT 1 */", "comment terminator"),
    ("site", "SELECT 'a'#'", "comment"),
    ("site", "SELECT 'a'--'", "comment"),
    ("site", "SELECT `a`/*`*/", "comment"),
    # stacked statements
    ("site", "SELECT 1; SELECT 2", "more than one statement"),
    ("site", "SELECT 1; DROP TABLE wp_posts", None),
    ("site", "SELECT 1;;", "more than one statement"),
    ("site", "SELECT 'a'; DELETE FROM wp_posts", None),
    ("site", ";SELECT 1", None),
    ("site", "SELECT 'a\\'; DROP TABLE wp_posts; SELECT '", "NO_BACKSLASH_ESCAPES"),
    ("site", "SELECT 'a\\\\'; DROP TABLE wp_posts; SELECT '", None),
    ("site", "SELECT 'it\\'s'", "NO_BACKSLASH_ESCAPES"),
    ("site", "SELECT 'abc", "unterminated"),
    ("site", "SELECT `abc", "unterminated"),
    # INTO in every form
    ("site", "SELECT * FROM wp_terms INTO OUTFILE '/tmp/x'", "INTO"),
    ("site", "SELECT * FROM wp_terms INTO DUMPFILE '/tmp/x'", "INTO"),
    ("site", "SELECT name FROM wp_terms INTO @x", None),
    ("site", "SELECT name INTO @x FROM wp_terms", None),
    ("site", "SELECT name FROM wp_terms LIMIT 1 INTO @a", None),
    ("site", "SELECT 1 InTo OuTfIlE '/tmp/x'", "INTO"),
    ("site", "SELECT name FROM wp_terms INTO `x`", "INTO"),
    ("site", "SELECT @x", "variable"),
    ("site", "SELECT @@secure_file_priv", "variable"),
    ("site", "SELECT name FROM wp_terms WHERE (@a := 1)", None),
    ("site", "SELECT name FROM wp_terms WHERE term_id := 1", "assignment"),
    # forbidden tables, directly, via UNION, subqueries, CTEs, quoting, case
    ("site", "SELECT * FROM wp_users", "user or comment data"),
    ("site", "SELECT name FROM wp_terms UNION SELECT user_pass FROM wp_users", "wp_users"),
    ("site", "SELECT name FROM wp_terms UNION ALL SELECT user_login FROM `wp_users`", "wp_users"),
    ("site", "sElEcT * FrOm Wp_UsErS", "user or comment data"),
    ("site", "SELECT * FROM `WP_USERS`", "user or comment data"),
    ("site", "SELECT COUNT(*) FROM wp_usermeta", "user or comment data"),
    ("site", "SELECT comment_content FROM wp_comments", "user or comment data"),
    ("site", "SELECT * FROM wp_commentmeta", "user or comment data"),
    ("site", "SELECT * FROM wp_gf_entry", "not on the allowlist"),
    ("site", "SELECT * FROM wp_actionscheduler_actions", "not on the allowlist"),
    ("site", "SELECT * FROM wp_posts_backup", "not on the allowlist"),
    ("site", "SELECT * FROM users", "not on the allowlist"),
    ("site", "SELECT name FROM wp_terms WHERE term_id IN (SELECT ID FROM wp_users)", "wp_users"),
    ("site", "SELECT (SELECT user_pass FROM wp_users LIMIT 1)", "wp_users"),
    ("site", "SELECT name FROM wp_terms WHERE EXISTS (SELECT 1 FROM wp_users)", "wp_users"),
    ("site", "SELECT * FROM (SELECT * FROM wp_users) x", "wp_users"),
    ("site", "SELECT * FROM wp_terms t JOIN wp_users u ON u.ID = t.term_id", "wp_users"),
    ("site", "SELECT * FROM wp_terms t LEFT JOIN wp_usermeta u ON 1=1", "wp_usermeta"),
    ("site", "SELECT * FROM wp_terms, wp_users", "wp_users"),
    ("site", "WITH u AS (SELECT * FROM wp_users) SELECT * FROM u", "wp_users"),
    ("site", "WITH wp_users AS (SELECT 1) SELECT * FROM wp_users", "looks like a WordPress"),
    ("site", "WITH c AS (SELECT 1 AS a) SELECT a FROM c UNION SELECT user_pass FROM wp_users",
     "wp_users"),
    ("site", "WITH RECURSIVE r AS (SELECT 1 UNION ALL SELECT 1 FROM r) SELECT * FROM r",
     "RECURSIVE"),
    ("site", "WITH c(a) AS (SELECT 1) SELECT a FROM c", "column lists"),
    ("site", "SELECT * FROM wp_terms AS wp_users", "looks like a WordPress"),
    ("site_ro", "SELECT * FROM wp_users", "user or comment data"),
    ("blog_ro", "SELECT * FROM wp_posts UNION SELECT * FROM wp_usermeta", "wp_usermeta"),
    # schema-qualified and system schemas
    ("site", "SELECT * FROM information_schema.tables", "system schema"),
    ("site", "SELECT * FROM INFORMATION_SCHEMA.`TABLES`", "system schema"),
    ("site", "SELECT * FROM `information_schema`.`columns`", "system schema"),
    ("site", "SELECT * FROM mysql.user", "system schema"),
    ("site", "SELECT * FROM performance_schema.threads", "system schema"),
    ("site", "SELECT * FROM sys.version", "system schema"),
    ("site", "SELECT * FROM wordpress.wp_users", None),
    ("site", "SELECT ID FROM `wordpress`.`wp_posts` WHERE post_type='page'", "schema"),
    ("site", "SELECT information_schema.tables.table_name", "system schema"),
    ("site", "SELECT name FROM wp_terms WHERE name = mysql.user.password", "system schema"),
    ("site_ro", "SELECT * FROM audit_blog.wp_posts", "schema"),
    ("site_ro", "SELECT * FROM site_db.wp_posts", "schema"),
    ("site_ro", "SELECT * FROM `AUDIT_SITE`.wp_posts", "schema"),
    ("site_ro", "SELECT * FROM `audit_site.wp_posts`", "not on the allowlist"),
    ("site", "SELECT * FROM .wp_posts", None),
    # locking and side-effect functions
    ("site", "SELECT * FROM wp_terms FOR UPDATE", "FOR UPDATE"),
    ("site", "SELECT * FROM wp_terms FOR UPDATE NOWAIT", "FOR UPDATE"),
    ("site", "SELECT * FROM wp_terms FOR SHARE", "FOR"),
    ("site", "SELECT * FROM wp_terms LOCK IN SHARE MODE", "LOCK"),
    ("site", "SELECT * FROM wp_terms FOR SYSTEM_TIME ALL", None),
    ("site", "SELECT SLEEP(1)", "SLEEP"),
    ("site", "SELECT sleep (1)", "sleep"),
    ("site", "SELECT `SLEEP`(1)", "quoted function"),
    ("site", "SELECT mysql.sleep(1)", None),
    ("site", "SELECT name FROM wp_terms WHERE SLEEP(5) = 0", "SLEEP"),
    ("site", "SELECT name FROM wp_terms WHERE name = 'a' AND 1 = (SELECT SLEEP(5))", "SLEEP"),
    ("site", "SELECT BENCHMARK(1000000, HEX('a'))", "BENCHMARK"),
    ("site", "SELECT GET_LOCK('a', 10)", "GET_LOCK"),
    ("site", "SELECT RELEASE_LOCK('a')", "RELEASE_LOCK"),
    ("site", "SELECT IS_FREE_LOCK('a')", "IS_FREE_LOCK"),
    ("site", "SELECT LOAD_FILE('/etc/passwd')", "LOAD_FILE"),
    ("site", "SELECT MASTER_POS_WAIT('x', 1)", "MASTER_POS_WAIT"),
    ("site", "SELECT SYS_EVAL('id')", "SYS_EVAL"),
    ("site", "SELECT USER()", "USER"),
    ("site", "SELECT NOW()", "NOW"),
    ("site", "SELECT UUID()", "UUID"),
    ("site", "SELECT CHAR(65)", "CHAR"),
    ("site", "SELECT JSON_EXTRACT('{}', '$.a')", "JSON_EXTRACT"),
    ("site", "SELECT ROW_NUMBER() OVER ()", None),
    ("site", "SELECT COUNT(*) OVER () FROM wp_terms", "OVER"),
    ("site", "SELECT CURRENT_USER(1)", "no arguments"),
    ("site", "SELECT * FROM JSON_TABLE('[]', '$[*]' COLUMNS (a INT PATH '$')) j", None),
    # DML, DDL, session, procedural, other statements
    ("site", "UPDATE wp_posts SET post_title='x'", "UPDATE"),
    ("site", "DELETE FROM wp_posts", "DELETE"),
    ("site", "INSERT INTO wp_terms VALUES (1)", "INSERT"),
    ("site", "REPLACE INTO wp_terms VALUES (1)", "REPLACE"),
    ("site", "DROP TABLE wp_posts", "DROP"),
    ("site", "CREATE TABLE x (a int)", "CREATE"),
    ("site", "ALTER TABLE wp_posts ADD c int", "ALTER"),
    ("site", "TRUNCATE wp_posts", "TRUNCATE"),
    ("site", "RENAME TABLE wp_posts TO x", "RENAME"),
    ("site", "SET SESSION TRANSACTION READ WRITE", "SET"),
    ("site", "SET autocommit = 0", "SET"),
    ("site", "CALL p()", "CALL"),
    ("site", "DO SLEEP(1)", "DO"),
    ("site", "HANDLER wp_users OPEN", "HANDLER"),
    ("site", "LOAD DATA INFILE '/x' INTO TABLE wp_terms", None),
    ("site", "LOAD XML INFILE '/x' INTO TABLE wp_terms", None),
    ("site", "GRANT ALL ON *.* TO x", "GRANT"),
    ("site", "REVOKE SELECT ON *.* FROM x", "REVOKE"),
    ("site", "KILL 1", "KILL"),
    ("site", "SHOW TABLES", "TABLES"),
    ("site", "SHOW DATABASES", "SHOW GRANTS"),
    ("site", "SHOW GRANTS FOR 'root'@'localhost'", None),
    ("site", "SHOW GRANTS FOR root", "SHOW GRANTS"),
    ("site", "SHOW CREATE TABLE wp_users", None),
    ("site", "DESCRIBE wp_users", "DESCRIBE"),
    ("site", "DESC wp_users", None),
    ("site", "EXPLAIN wp_users", "EXPLAIN"),
    ("site", "EXPLAIN ANALYZE SELECT 1", "ANALYZE"),
    ("site", "EXPLAIN FORMAT=JSON SELECT 1", "EXPLAIN"),
    ("site", "SELECT 1 UNION SHOW GRANTS", "SHOW"),
    ("site", "TABLE wp_users", "TABLE"),
    ("site", "SELECT 1 UNION TABLE wp_users", "TABLE"),
    ("site", "VALUES ROW(1)", "VALUES"),
    ("site", "START TRANSACTION", "START"),
    ("site", "BEGIN", "BEGIN"),
    ("site", "COMMIT", "COMMIT"),
    ("site", "ROLLBACK", "ROLLBACK"),
    ("site", "PREPARE s FROM 'SELECT 1'", "PREPARE"),
    ("site", "EXECUTE s", "EXECUTE"),
    ("site", "SELECT 1 PROCEDURE ANALYSE()", "PROCEDURE"),
    ("site", "LOCK TABLES wp_posts READ", "LOCK"),
    ("site", "UNLOCK TABLES", "UNLOCK"),
    ("site", "FLUSH PRIVILEGES", "FLUSH"),
    ("site", "OPTIMIZE TABLE wp_posts", "OPTIMIZE"),
    ("site", "CHECKSUM TABLE wp_users", None),
    ("site", "XA START 'x'", None),
    ("site", "SELECT * FROM wp_terms PARTITION (p0)", "PARTITION"),
    ("site", "SELECT * FROM wp_terms USE INDEX (PRIMARY)", "USE"),
    ("site", "SELECT * FROM wp_terms FORCE INDEX (PRIMARY)", "index hints"),
    ("site", "SELECT * FROM wp_terms t IGNORE INDEX (PRIMARY)", "index hints"),
    ("site", "SELECT * FROM wp_terms WINDOW w AS ()", "WINDOW"),
    ("site", "SELECT * FROM wp_terms, LATERAL (SELECT 1) x", "LATERAL"),
    ("site", "SELECT * FROM wp_terms t RIGHT JOIN wp_term_taxonomy tt ON 1=1", "RIGHT"),
    ("site", "SELECT * FROM wp_terms NATURAL JOIN wp_term_taxonomy", "NATURAL"),
    ("site", "SELECT * FROM (wp_terms t JOIN wp_term_taxonomy tt ON 1=1)", "parenthesised"),
    ("site", "SELECT * FROM wp_terms WHERE name = 'x' FETCH FIRST 1 ROWS ONLY", None),
    ("site", "SELECT CAST('a' AS CHAR CHARACTER SET utf8mb4)", None),
    # wp_options without the name filter
    ("site", "SELECT option_value FROM wp_options", "option_name"),
    ("site", "SELECT COUNT(*) FROM wp_options", "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name LIKE '%'", "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name LIKE 'site%'", "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name = 'siteurl' OR 1=1",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE 1 AND option_name = 'siteurl' OR 1",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name = 'siteurl' || 1",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name = 'siteurl' XOR 1",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE CASE WHEN 1 AND option_name = "
                "'siteurl' AND 1 THEN 1 ELSE 1 END", "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name IN ('siteurl','auth_key')",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name='active_plugins'",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name = 'SITEURL'", "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name = 'siteurl '", "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE NOT option_name = 'siteurl'",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name <> 'siteurl'", "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name = (SELECT 'siteurl')",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name = CONCAT('site', 'url')",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name = 'site\\url'", "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name = X'7369746575726C'",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name = 'siteurl' COLLATE utf8mb4_bin",
     "option_name"),
    ("site", "SELECT o.option_value FROM wp_options o LEFT JOIN wp_terms t ON "
                "o.option_name = 'siteurl'", None),
    ("site", "SELECT * FROM wp_options WHERE option_name='siteurl'", "SELECT *"),
    ("site", "SELECT o.* FROM wp_options o WHERE o.option_name='siteurl'", "alias.*"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name='siteurl' UNION "
                "SELECT option_value FROM wp_options", "option_name"),
    ("site", "SELECT x.v FROM (SELECT option_value AS v FROM wp_options) x", "option_name"),
    ("site", "SELECT name FROM wp_terms WHERE name IN (SELECT option_value FROM wp_options)",
     None),
    # wp_posts columns and rows
    ("site", "SELECT post_password FROM wp_posts WHERE post_type='page'", "post_password"),
    ("site", "SELECT guid FROM wp_posts WHERE post_type='page'", "guid"),
    ("site", "SELECT post_excerpt FROM wp_posts WHERE post_type='page'", "post_excerpt"),
    ("site", "SELECT post_author FROM wp_posts WHERE post_type='page'", "post_author"),
    ("site", "SELECT * FROM wp_posts WHERE post_type='page'", "SELECT *"),
    ("site", "SELECT p.* FROM wp_posts p WHERE p.post_type='page'", "alias.*"),
    ("site", "SELECT ID FROM wp_posts", "revisions"),
    ("site", "SELECT COUNT(*) FROM wp_posts", "revisions"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type IN ('Revision')", "revisions"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type IN ('page', 'revision')", "revisions"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type = 'révision'", "revisions"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type <> 'revisions'", "revisions"),
    ("site", "SELECT ID FROM wp_posts WHERE post_status = 'inherit'", "revisions"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type = 'page' OR post_type = 'revision'",
     "revisions"),
    ("site", "SELECT post_content FROM wp_posts WHERE post_type='page'", "publish"),
    ("site", "SELECT post_content FROM wp_posts WHERE post_status='publish'", "public post types"),
    ("site", "SELECT post_content FROM wp_posts WHERE post_status='publish' AND "
                "post_type='flamingo_inbound'", "public post types"),
    ("site", "SELECT post_content FROM wp_posts WHERE post_status='publish' AND "
                "post_type='bricks_template'", "public post types"),
    ("site", "SELECT post_content FROM wp_posts WHERE post_status IN ('publish','private') AND "
                "post_type='page'", "publish"),
    ("site", "SELECT post_content FROM wp_posts WHERE post_status='publish' AND "
                "post_type='revision'", "public post types"),
    ("site", "SELECT post_content FROM wp_posts WHERE post_status='publish' AND "
                "post_type IN ('page') OR 1=1", None),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' AND post_content LIKE '%x%'",
     "publish"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' AND LENGTH(post_content) > 5",
     "publish"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' AND post_password = ''",
     "post_password"),
    ("site", "SELECT ID AS post_password FROM wp_posts WHERE post_type='page' AND "
                "post_password='x'", "post_password"),
    ("site", "SELECT ID AS post_password FROM wp_posts WHERE post_type='page' ORDER BY "
                "post_password", "post_password"),
    ("site", "SELECT t.name FROM wp_terms t WHERE EXISTS (SELECT 1 FROM wp_posts p WHERE "
                "p.post_type='page' AND p.post_password = t.name)", "post_password"),
    ("site", "SELECT p.ID FROM wp_posts p WHERE p.post_type='page' AND EXISTS (SELECT 1 FROM "
                "wp_terms t WHERE t.name = p.post_password)", "post_password"),
    ("site", "SELECT p.ID FROM wp_posts p WHERE p.post_type='page' AND EXISTS (SELECT 1 FROM "
                "wp_terms t WHERE t.name = post_password)", "qualif"),
    ("site", "SELECT post_title FROM wp_posts p JOIN wp_terms t ON 1=1 WHERE p.post_type='page'",
     "unqualified"),
    ("site", "SELECT p.ID FROM wp_posts p JOIN wp_terms t ON 1=1 WHERE post_type='page'",
     "unqualified"),
    ("site", "SELECT p.post_title FROM wp_posts p LEFT JOIN wp_terms t ON "
                "p.post_type = 'page'", "revisions"),
    ("site", "SELECT p.ID FROM wp_posts p JOIN wp_term_relationships r USING (ID) "
                "WHERE p.post_type='page'", "unqualified"),
    ("site", "SELECT d.c FROM (SELECT post_content AS c FROM wp_posts WHERE post_type='page') d",
     "publish"),
    ("site", "WITH c AS (SELECT post_content FROM wp_posts WHERE post_type='page') "
                "SELECT * FROM c", "publish"),
    ("site", "SELECT p.post_content FROM wp_posts p JOIN wp_posts q ON q.ID = p.post_parent "
                "WHERE q.post_status='publish' AND q.post_type='page' AND p.post_type <> 'revision'",
     "publish"),
    ("site", "SELECT x.post_title FROM wp_posts p WHERE p.post_type='page'", "qualifier"),
    ("site", "SELECT wp_posts.post_title FROM wp_posts p WHERE p.post_type='page'", "qualifier"),
    # wp_postmeta
    ("site", "SELECT meta_value FROM wp_postmeta WHERE meta_key='_elementor_data'", "joined"),
    ("site", "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID WHERE "
                + PUB + " AND m.meta_key = '_edit_lock'", "meta_key"),
    ("site", "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID WHERE "
                + PUB, "meta_key"),
    ("site", "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID WHERE "
                + PUB + " AND m.meta_key LIKE 'rank_math%'", "meta_key"),
    ("site", "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID WHERE "
                + PUB + " AND m.meta_key LIKE '%'", "meta_key"),
    ("site", "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID WHERE "
                + PUB + " AND m.meta_key LIKE 'rank\\_math\\_%' ESCAPE '|'", "meta_key"),
    ("site", "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID WHERE "
                "p.post_type = 'page' AND m.meta_key = '_elementor_data'", "joined"),
    ("site", "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID WHERE "
                "p.post_status='publish' AND p.post_type = 'wpforms' AND m.meta_key = '_elementor_data'",
     "joined"),
    ("site", "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.post_parent "
                "WHERE " + PUB + " AND m.meta_key = '_elementor_data'", "joined"),
    ("site", "SELECT m.meta_value FROM wp_postmeta m LEFT JOIN wp_posts p ON p.ID = m.post_id "
                "AND p.post_status='publish' AND p.post_type='page' WHERE m.meta_key='_elementor_data'",
     "joined"),
    ("site", "SELECT m.meta_value FROM wp_postmeta m WHERE m.meta_key = '_elementor_data' AND "
                "m.post_id IN (SELECT p.ID FROM wp_posts p WHERE " + PUB + ")", "joined"),
    ("site", "SELECT m.* FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID WHERE "
                + PUB + " AND m.meta_key = '_elementor_data'", "alias.*"),
    ("site", "SELECT meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID WHERE "
                + PUB + " AND m.meta_key = '_elementor_data'", "unqualified"),
    # hand-written bypass attempts against the row and column analysis
    ("site", "SELECT o.option_value FROM wp_options o JOIN wp_options o2 ON "
                "o2.option_name='siteurl'", "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name='siteurl' AND option_value "
                "IN (SELECT option_value FROM wp_options)", "option_name"),
    ("site", "SELECT p.ID FROM wp_posts p WHERE " + PUB + " GROUP BY p.ID HAVING "
                "MAX(p.post_password) > ''", "post_password"),
    ("site", "SELECT post_type AS t FROM wp_posts WHERE post_status='publish' GROUP BY t",
     "not on the allowlist"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' AND post_status='publish' AND "
                "ID = (SELECT MAX(q.ID) FROM wp_posts q WHERE q.post_content LIKE 'a%')", None),
    ("site", "SELECT p.ID, (SELECT m.meta_value FROM wp_postmeta m WHERE m.post_id = p.ID AND "
                "m.meta_key='_elementor_data') FROM wp_posts p WHERE " + PUB, "joined"),
    ("site", "SELECT p.ID FROM wp_posts p WHERE p.post_type='page' AND p.ID IN "
                "(SELECT post_id FROM wp_postmeta)", "meta_key"),
    ("site", "SELECT o.option_value FROM wp_options o, wp_terms t WHERE option_name='siteurl'",
     "unqualified"),
    ("site", "SELECT t.name FROM wp_terms t WHERE EXISTS (SELECT 1 FROM wp_posts p WHERE "
                "p.post_type='page' AND p.post_content LIKE CONCAT('%', t.name, '%'))", "publish"),
    ("site", "SELECT option_value FROM wp_options WHERE (option_name) = ('siteurl')",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE ! option_name = 'siteurl'",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name = 'siteurl' + 0",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name IN ('siteurl') IS TRUE",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE 1 BETWEEN 0 AND option_name = 'siteurl'",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options WHERE option_name = 'siteurl' = 1",
     "option_name"),
    ("site", "SELECT option_value FROM wp_options HAVING option_name = 'siteurl'",
     "option_name"),
    ("site", "SELECT p.post_content FROM wp_terms t LEFT JOIN wp_posts p ON "
                "p.post_status='publish' WHERE p.post_type='page' OR 1", None),
    ("site", "SELECT p.post_title FROM wp_posts AS p, wp_posts AS P WHERE p.post_type='page'",
     "duplicate"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' AND post_status='publish' "
                "ORDER BY post_password", "post_password"),
    ("site", "SELECT COUNT(*) post_content FROM wp_posts WHERE post_type='page' AND "
                "post_content <> ''", "publish"),
    ("site", "SELECT 1 FROM wp_terms WHERE name = 'a' AND (SELECT COUNT(*) FROM wp_options) > 0",
     "option_name"),
    ("site", "WITH x AS (SELECT option_value FROM wp_options) SELECT * FROM x WHERE 1",
     "option_name"),
    ("site", "SELECT * FROM (SELECT p.post_title FROM wp_posts p) d WHERE d.post_title = 'x'",
     "revisions"),
    ("site", "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID OR 1 "
                "WHERE " + PUB + " AND m.meta_key='_elementor_data'", "joined"),
    ("site", "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID WHERE "
                + PUB + " AND m.meta_key='_elementor_data' OR m.meta_key='x'", None),
    ("site", "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m WHERE m.post_id = p.ID AND "
                "p.post_status='publish' AND p.post_type IN ('page','revision') AND "
                "m.meta_key='_elementor_data'", "joined"),
    # residue exception is for residue_hosts installs only and revision-only
    ("site", "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision'", "revisions"),
    # string, quoting and unicode tricks
    ("site", 'SELECT "x"', "double-quoted"),
    ("site", 'SELECT * FROM "wp_users"', "double-quoted"),
    ("site", "SELECT name FROM wp_terms WHERE name = \"a\" ", "double-quoted"),
    ("site", "SELECT ID FROM wp_posts WHERE post_type='page' AND ID = 1", "non-ASCII"),
    ("site", "SELECT * FROM wp_uѕers", "non-ASCII"),
    ("site", "SELECT 1； DROP TABLE wp_posts", "non-ASCII"),
    ("site", "SELECT ١", "non-ASCII"),
    ("site", "SELECT .١", "non-ASCII"),
    ("site", "SELECT 1\x00; DROP TABLE wp_posts", "NUL"),
    ("site", "SELECT 'a\x00'", "NUL"),
    ("site", "SELECT _utf8mb4'x'", "introducer"),
    ("site", "SELECT _binary'x'", "introducer"),
    ("site", "SELECT 1abc", "glued"),
    ("site", "SELECT 1e5x", "glued"),
    ("site", "SELECT 0x41g", "glued"),
    ("site", "SELECT 1 FROM 1wp_users", "glued"),
    ("site", "SELECT ?", "placeholder"),
    ("site", "SELECT {fn NOW()}", "ODBC"),
    ("site", "SELECT [a]", None),
    ("site", "SELECT 1 \\G", "backslash"),
    ("site", "SELECT ``", "empty backtick"),
    ("site", "SELECT X'4G'", "malformed"),
    # structural nonsense and limits
    ("site", "", "empty"),
    ("site", "   ", "empty"),
    ("site", ";", "empty"),
    ("site", "SELECT", "empty"),
    ("site", "SELECT 1 FROM", "empty FROM"),
    ("site", "SELECT ((1)", "unbalanced"),
    ("site", "SELECT 1)", "unbalanced"),
    ("site", "SELECT " + "(" * 60 + "1" + ")" * 60, "nested"),
    ("site", "SELECT 1 LIMIT 1 + 1", "LIMIT"),
    ("site", "SELECT 1 LIMIT (SELECT 1)", "LIMIT"),
    ("site", "SELECT name FROM wp_terms WHERE name = 'a' 'b' c", None),
    ("site", "SELECT name FROM wp_terms ORDER BY name WHERE 1", "out of order"),
    ("site", "SELECT name FROM wp_terms WHERE 1 WHERE 2", "duplicate"),
    ("site", "SELECT x FROM wp_terms t, (SELECT 1) ", "alias"),
    ("nosuch", "SELECT 1", "unknown install"),
    ("site", 12345, "not a string"),
]


def _label(install):
    return install.name if isinstance(install, sql_guard.InstallPolicy) else install


class StatementAllowTests(unittest.TestCase):
    def test_allowed(self):
        for install, sql in ALLOW:
            with self.subTest(install=_label(install), sql=sql):
                v = check_statement(sql, install)
                self.assertTrue(v.allowed, f"expected allowed, got {v.reasons}")


class StatementRejectTests(unittest.TestCase):
    def test_rejected(self):
        for install, sql, needle in REJECT:
            with self.subTest(install=_label(install), sql=sql):
                v = check_statement(sql, install)
                self.assertFalse(v.allowed, "expected rejection")
                self.assertTrue(v.reasons, "a rejection must carry a reason")
                if needle:
                    self.assertIn(needle.lower(), " ".join(v.reasons).lower())


class SpecificBehaviourTests(unittest.TestCase):
    def test_verdict_is_falsy_on_reject_and_truthy_on_allow(self):
        self.assertFalse(check_statement("SELECT SLEEP(1)", "site"))
        self.assertTrue(check_statement("SELECT 1", "site"))

    def test_kinds_and_tables(self):
        v = check_statement("SHOW GRANTS FOR CURRENT_USER()", "site_ro")
        self.assertEqual(v.kind, "show_grants")
        v = check_statement("EXPLAIN SELECT name FROM wp_terms", "site")
        self.assertEqual(v.kind, "explain")
        v = check_statement("SELECT t.name FROM wp_terms t JOIN wp_term_taxonomy x "
                            "ON x.term_id = t.term_id", "site")
        self.assertEqual(v.tables, ["wp_term_taxonomy", "wp_terms"])

    def test_prefix_is_configurable(self):
        pol = sql_guard.InstallPolicy("site", prefix="xy_")
        self.assertFalse(check_statement("SELECT name FROM wp_terms", pol))
        self.assertTrue(check_statement("SELECT name FROM xy_terms", pol))
        self.assertTrue(check_statement("SELECT name FROM xy_terms", "site", prefix="xy_"))
        self.assertFalse(check_statement("SELECT * FROM xy_users", "site", prefix="xy_"))
        self.assertFalse(check_statement("SELECT 1", "site", prefix="x;y").allowed)

    def test_public_post_types_override(self):
        sql = ("SELECT post_content FROM wp_posts WHERE post_status='publish' "
               "AND post_type='glossary'")
        self.assertFalse(check_statement(sql, "site"))
        self.assertTrue(check_statement(sql, "site",
                                        public_post_types=["post", "page", "glossary"]))

    def test_admin_schema_qualifier_only_when_configured(self):
        sql = "SELECT name FROM `wpdb`.`wp_terms`"
        self.assertFalse(check_statement(sql, "site"))
        self.assertTrue(check_statement(sql, "site", schema="wpdb"))
        self.assertFalse(check_statement("SELECT * FROM wpdb.wp_users", "site", schema="wpdb"))

    def test_residue_exception(self):
        q = ("SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
             "AND post_content LIKE '%spam-two.example%'")
        self.assertFalse(check_statement(q, "docs"))
        self.assertTrue(check_statement(q, "docs", residue=True))
        self.assertFalse(check_statement(q, "site", residue=True))
        self.assertFalse(check_statement(q, "site_ro", residue=True))
        meta = ("SELECT COUNT(*) FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID "
                "WHERE p.post_type = 'revision' AND m.meta_key = '_elementor_data' "
                "AND m.meta_value LIKE '%spam-one.example%'")
        self.assertTrue(check_statement(meta, "docs", residue=True))
        self.assertFalse(check_statement(meta, "docs"))
        # Residue mode never opens forbidden tables or other columns.
        self.assertFalse(check_statement("SELECT post_password FROM wp_posts WHERE "
                                         "post_type='revision'", "docs", residue=True))
        self.assertFalse(check_statement("SELECT * FROM wp_users", "docs", residue=True))

    def test_reject_reason_names_fail_closed_rule(self):
        v = check_statement("SELECT * FROM wp_posts WHERE post_type='page'", "site")
        self.assertIn("fail closed", v.reasons[0])

    def test_every_allowlisted_function_is_accepted(self):
        two_arg = {"LEFT", "RIGHT", "LOCATE", "INSTR", "IFNULL", "NULLIF", "DATE_FORMAT",
                   "CONCAT_WS", "COALESCE", "CONCAT"}
        for f in sorted(sql_guard.FUNCTION_ALLOWLIST):
            if f in ("CURRENT_USER", "VERSION", "DATABASE"):
                sql = f"SELECT {f}()"
            elif f == "CAST":
                sql = "SELECT CAST(1 AS CHAR)"
            elif f == "CONVERT":
                sql = "SELECT CONVERT('a' USING utf8mb4)"
            elif f == "IF":
                sql = "SELECT IF(1, 'a', 'b')"
            elif f in ("REPLACE", "SUBSTRING_INDEX"):
                sql = f"SELECT {f}('a', 'b', 'c')"
            elif f == "SUBSTRING":
                sql = "SELECT SUBSTRING('abc', 1)"
            elif f in two_arg:
                sql = f"SELECT {f}('a', 'b')"
            else:
                sql = f"SELECT {f}('a')"
            with self.subTest(func=f):
                v = check_statement(sql, "site")
                self.assertTrue(v.allowed, v.reasons)

    def test_allowlist_is_exactly_the_documented_list(self):
        documented = {"COUNT", "SUM", "MIN", "MAX", "AVG", "LENGTH", "CHAR_LENGTH", "LOWER",
                    "UPPER", "SUBSTRING", "SUBSTRING_INDEX", "LEFT", "RIGHT", "CONCAT",
                    "CONCAT_WS", "GROUP_CONCAT", "COALESCE", "IFNULL", "IF", "NULLIF",
                    "REPLACE", "LOCATE", "INSTR", "TRIM", "DATE", "DATE_FORMAT", "CAST",
                    "CONVERT", "HEX", "DISTINCT", "CURRENT_USER", "VERSION", "DATABASE"}
        self.assertEqual(set(sql_guard.FUNCTION_ALLOWLIST), documented)

    def test_case_variants_of_forbidden_keywords(self):
        for kw in ("into", "Into", "iNtO"):
            with self.subTest(kw=kw):
                self.assertFalse(check_statement(f"SELECT 1 {kw} OUTFILE '/tmp/x'", "site"))
        for fn in ("sleep", "Sleep", "SLEEP", "sLeEp"):
            with self.subTest(fn=fn):
                self.assertFalse(check_statement(f"SELECT {fn}(1)", "site"))

    def test_keywords_inside_strings_and_backticks_are_inert(self):
        self.assertTrue(check_statement(
            "SELECT name FROM wp_terms WHERE name = 'INTO OUTFILE SLEEP(1) wp_users ; --'",
            "site"))
        self.assertTrue(check_statement("SELECT `update` FROM wp_terms", "site"))
        # but a backticked *table* name is still a table name
        self.assertFalse(check_statement("SELECT 1 FROM `wp_users`", "site"))


if __name__ == "__main__":
    unittest.main()
