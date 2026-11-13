/* ============================================================
   SQL Server 安全加固检测脚本（只读，不修改任何配置）
   适用：SQL Server 2012+      权限：sysadmin（否则部分项会失真）
   ------------------------------------------------------------
   结果集说明：
     1) 检测明细：按 FAIL → WARN → PASS → INFO 排序，含风险说明与修复建议
     2) 汇总统计：各等级数量
     3) 数据库明细：各业务库的加固关键指标（原值，便于复查）
   ------------------------------------------------------------
   建议流程：先跑本脚本留一份基线 → 执行 sqlserver-fix.sql → 再跑一次对比。
   ============================================================ */

SET NOCOUNT ON;

IF IS_SRVROLEMEMBER(N'sysadmin') <> 1
BEGIN
    RAISERROR(N'请以 sysadmin 账户执行，否则部分检测项会因权限不足而失真。', 16, 1);
    RETURN;
END;

IF OBJECT_ID(N'tempdb..#chk') IS NOT NULL DROP TABLE #chk;
CREATE TABLE #chk
(
    Seq      int IDENTITY(1, 1) NOT NULL PRIMARY KEY,
    Category nvarchar(20)   NOT NULL,
    Item     nvarchar(300)  NOT NULL,
    CurVal   nvarchar(max)  NULL,
    ExpVal   nvarchar(400)  NULL,
    Result   nvarchar(8)    NOT NULL,   -- FAIL / WARN / PASS / INFO
    Risk     nvarchar(1000) NULL,
    FixHint  nvarchar(1000) NULL
);

/* ------------------------------------------------------------
   一、基础信息
   ------------------------------------------------------------ */
DECLARE @ver nvarchar(128) = CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion'));
DECLARE @lvl nvarchar(128) = CONVERT(nvarchar(128), SERVERPROPERTY('ProductLevel'));
DECLARE @ed  nvarchar(128) = CONVERT(nvarchar(128), SERVERPROPERTY('Edition'));
DECLARE @inst nvarchar(256) = CONVERT(nvarchar(256), SERVERPROPERTY('ServerName'));
DECLARE @major int = TRY_CONVERT(int, LEFT(@ver, CHARINDEX(N'.', @ver) - 1));
DECLARE @integratedOnly int = CONVERT(int, SERVERPROPERTY('IsIntegratedSecurityOnly'));

INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint) VALUES
(N'基础', N'实例 / 版本 / 补丁', @inst + N' / ' + @ed + N' / ' + @ver + N' (' + @lvl + N')',
 N'受支持版本 + 最新 SP/CU',
 CASE WHEN @major <= 12 THEN N'FAIL' WHEN @major = 13 THEN N'WARN' ELSE N'PASS' END,
 N'SQL Server 2012/2014 已终止支持，不再发布安全补丁；未修补实例存在已公开的提权与远程代码执行漏洞。',
 N'升级到 SQL Server 2019/2022，最低要求安装最新 SP + CU。'),
(N'基础', N'认证模式',
 CASE WHEN @integratedOnly = 1 THEN N'仅 Windows 认证' ELSE N'混合认证（SQL 登录可用）' END,
 N'仅 Windows 认证（或混合模式下严格管控 SQL 登录）',
 CASE WHEN @integratedOnly = 1 THEN N'PASS' ELSE N'WARN' END,
 N'混合认证下，SQL 登录可被口令爆破；sa 或弱口令账号是入侵的主要入口。',
 N'无 SQL 登录需求时改为仅 Windows 认证；否则保证所有 SQL 登录强口令 + 启用密码策略，并定期审计登录来源。');

/* ------------------------------------------------------------
   二、sa 账户
   ------------------------------------------------------------ */
INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint)
SELECT N'sa', N'sa 状态（是否禁用 / 是否改名）',
       CASE WHEN s.is_disabled = 1 THEN N'已禁用' ELSE N'启用中' END + N'；当前名称：' + s.name,
       N'启用并设置强口令（推荐）或已禁用',
       CASE WHEN s.is_disabled = 1 THEN N'PASS' ELSE N'WARN' END,
       N'sa 拥有最高权限且是爆破首要目标；弱口令或长期不轮换的 sa 极易被攻破。',
       N'保留 sa 时设置 20 位以上强口令、启用密码策略（sqlserver-fix.sql 第 3 步）并定期轮换；日常运维不要使用 sa。'
FROM sys.sql_logins s
WHERE s.sid = 0x01;

INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint)
SELECT N'sa', N'sa 密码策略 / 过期策略',
       CASE s.is_policy_checked WHEN 1 THEN N'已启用' ELSE N'未启用' END + N' / ' +
       CASE s.is_expiration_checked WHEN 1 THEN N'已启用' ELSE N'未启用' END,
       N'密码策略已启用',
       CASE WHEN s.is_policy_checked = 0 THEN N'WARN' ELSE N'PASS' END,
       N'未启用密码策略时，可设置弱口令且不受锁定策略保护。',
       N'ALTER LOGIN sa WITH CHECK_POLICY = ON; 并定期轮换口令。'
FROM sys.sql_logins s
WHERE s.sid = 0x01;

/* ------------------------------------------------------------
   三、sysadmin / 高权限角色成员
   ------------------------------------------------------------ */
DECLARE @svc TABLE (acct nvarchar(256) NOT NULL PRIMARY KEY);
BEGIN TRY
    INSERT @svc (acct)
    SELECT DISTINCT service_account FROM sys.dm_server_services WHERE service_account IS NOT NULL;
END TRY
BEGIN CATCH
END CATCH

DECLARE @admin TABLE
(
    name        sysname NOT NULL PRIMARY KEY,
    principal_id int    NOT NULL,
    type        char(1) NOT NULL,
    is_disabled bit     NOT NULL,
    is_svc      bit     NOT NULL,
    is_builtin  bit     NOT NULL
);

INSERT @admin (name, principal_id, type, is_disabled, is_svc, is_builtin)
SELECT sp.name, sp.principal_id, sp.type, sp.is_disabled,
       CASE WHEN EXISTS (SELECT 1 FROM @svc v WHERE v.acct = sp.name) THEN 1 ELSE 0 END,
       CASE WHEN sp.name LIKE N'NT SERVICE\%' OR sp.name LIKE N'NT AUTHORITY\%' THEN 1 ELSE 0 END
FROM sys.server_role_members rm
JOIN sys.server_principals r  ON r.principal_id = rm.role_principal_id AND r.name = N'sysadmin'
JOIN sys.server_principals sp ON sp.principal_id = rm.member_principal_id;

DECLARE @adminList nvarchar(max) =
    ISNULL((SELECT STUFF((SELECT N', ' + name FROM @admin FOR XML PATH(''), TYPE)
                          .value(N'.', N'nvarchar(max)'), 1, 2, N'')), N'无');

DECLARE @badAdminCount int =
    (SELECT COUNT(*) FROM @admin WHERE principal_id <> 1 AND is_svc = 0 AND is_builtin = 0);

DECLARE @badAdminList nvarchar(max) =
    ISNULL((SELECT STUFF((SELECT N', ' + name FROM @admin
                           WHERE principal_id <> 1 AND is_svc = 0 AND is_builtin = 0
                            FOR XML PATH(''), TYPE).value(N'.', N'nvarchar(max)'), 1, 2, N'')), N'无');

INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint) VALUES
(N'管理员', N'sysadmin 成员清单', @adminList,
 N'sa + Windows 服务账号 + 明确白名单',
 N'INFO', N'服务账号（NT SERVICE\* 等）是 SQL Server 正常运行所必需，不能移除。', NULL);

INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint) VALUES
(N'管理员', N'非预期的 sysadmin 成员',
 CONVERT(nvarchar(10), @badAdminCount) + N' 个：' + @badAdminList,
 N'0 个（sa 之外不应有 SQL 管理员）',
 CASE WHEN @badAdminCount > 0 THEN N'FAIL' ELSE N'PASS' END,
 N'任意 sysadmin 成员都等于实例完全控制权，是后门/横向移动的常见落脚点；多一个管理员就多一份被爆破风险。',
 N'执行 sqlserver-fix.sql（@UnexpectedSysadminAction = DISABLE）：禁用或移出 sa 之外的管理员；确需保留的 DBA 账号加入配置区白名单并单独管控。');

INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint)
SELECT N'管理员', N'固定服务器角色高权限成员',
       ISNULL(NULLIF(STUFF((SELECT N', ' + sp.name + N'(' + r.name + N')'
                              FROM sys.server_role_members rm
                              JOIN sys.server_principals r  ON r.principal_id = rm.role_principal_id
                              JOIN sys.server_principals sp ON sp.principal_id = rm.member_principal_id
                             WHERE r.name IN (N'securityadmin', N'serveradmin', N'processadmin',
                                              N'setupadmin', N'bulkadmin', N'dbcreator', N'diskadmin')
                               FOR XML PATH(''), TYPE).value(N'.', N'nvarchar(max)'), 1, 2, N''), N''), N'无'),
       N'仅必要的运维账号',
       N'INFO',
       N'securityadmin 可重置口令、dbcreator 可建库，均属可被利用的次级提权路径。',
       N'按最小权限原则清理，业务/开发账号不应落在这些固定角色中。';

/* ------------------------------------------------------------
   四、登录与口令
   ------------------------------------------------------------ */
DECLARE @badPolicyCount int =
    (SELECT COUNT(*) FROM sys.sql_logins WHERE is_policy_checked = 0 AND name NOT LIKE N'##%');

DECLARE @badPolicyList nvarchar(max) =
    ISNULL((SELECT STUFF((SELECT N', ' + name FROM sys.sql_logins
                           WHERE is_policy_checked = 0 AND name NOT LIKE N'##%'
                            FOR XML PATH(''), TYPE).value(N'.', N'nvarchar(max)'), 1, 2, N'')), N'无');

DECLARE @enabledLoginList nvarchar(max) =
    ISNULL((SELECT STUFF((SELECT N', ' + name FROM sys.sql_logins
                           WHERE is_disabled = 0 AND name NOT LIKE N'##%'
                            FOR XML PATH(''), TYPE).value(N'.', N'nvarchar(max)'), 1, 2, N'')), N'无');

INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint) VALUES
(N'登录', N'关闭密码策略的 SQL 登录',
 CONVERT(nvarchar(10), @badPolicyCount) + N' 个：' + @badPolicyList,
 N'0 个',
 CASE WHEN @badPolicyCount > 0 THEN N'WARN' ELSE N'PASS' END,
 N'关闭 CHECK_POLICY 后可设置任意弱口令，且不受登录失败锁定保护，易被爆破。',
 N'ALTER LOGIN [x] WITH CHECK_POLICY = ON; 并强制使用强口令（sqlserver-fix.sql 创建的新账号已默认启用）。');

INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint) VALUES
(N'登录', N'启用中的 SQL 登录清单', @enabledLoginList,
 N'仅必要的业务/开发账号',
 N'INFO',
 N'SQL 登录越多，可爆破面越大；离职/临时账号常被遗忘。',
 N'定期核对，禁用长期未使用的登录。');

/* ------------------------------------------------------------
   五、高危配置项
   ------------------------------------------------------------ */
DECLARE @CfgCheck TABLE
(
    ConfigName  sysname        NOT NULL PRIMARY KEY,
    WantValue   int            NOT NULL,
    Severity    nvarchar(8)    NOT NULL,
    DisplayName nvarchar(80)   NOT NULL,
    Risk        nvarchar(1000) NULL,
    FixHint     nvarchar(1000) NULL
);

INSERT @CfgCheck (ConfigName, WantValue, Severity, DisplayName, Risk, FixHint) VALUES
(N'xp_cmdshell', 0, N'FAIL', N'xp_cmdshell',
 N'可通过 SQL 执行任意操作系统命令，是提权与横向移动最常用的入口。',
 N'EXEC sp_configure ''xp_cmdshell'', 0; RECONFIGURE;'),
(N'clr enabled', 0, N'FAIL', N'CLR 集成',
 N'可加载 .NET 程序集并执行任意代码，正常业务极少需要。',
 N'EXEC sp_configure ''clr enabled'', 0; RECONFIGURE;'),
(N'Ole Automation Procedures', 0, N'FAIL', N'OLE 自动化',
 N'可通过 COM 组件执行命令、读写文件，常与提权利用链配合。',
 N'EXEC sp_configure ''Ole Automation Procedures'', 0; RECONFIGURE;'),
(N'Ad Hoc Distributed Queries', 0, N'WARN', N'即席分布式查询',
 N'OPENROWSET / OPENDATASOURCE 可访问外部数据源，可用于数据外带与探测。',
 N'EXEC sp_configure ''Ad Hoc Distributed Queries'', 0; RECONFIGURE;'),
(N'cross db ownership chaining', 0, N'FAIL', N'跨库所有权链',
 N'开启后低权限用户可越权访问其他数据库对象。',
 N'EXEC sp_configure ''cross db ownership chaining'', 0; RECONFIGURE;'),
(N'contained database authentication', 0, N'WARN', N'包含数据库认证',
 N'包含数据库用户可绕过实例级登录管控，形成影子账号。',
 N'EXEC sp_configure ''contained database authentication'', 0; RECONFIGURE;'),
(N'remote admin connections', 0, N'WARN', N'远程管理员连接(DAC)',
 N'DAC 可远程连接会扩大攻击面，被利用后可绕过常规管控。',
 N'EXEC sp_configure ''remote admin connections'', 0; RECONFIGURE;'),
(N'scan for startup procs', 0, N'WARN', N'启动时扫描存储过程',
 N'实例启动会自动执行标记过的存储过程，可被用于持久化后门。',
 N'EXEC sp_configure ''scan for startup procs'', 0; RECONFIGURE;'),
(N'SQL Mail XPs', 0, N'WARN', N'SQL Mail',
 N'依赖已废弃的 MAPI 客户端，存在额外攻击面。',
 N'EXEC sp_configure ''SQL Mail XPs'', 0; RECONFIGURE;'),
(N'external scripts enabled', 0, N'FAIL', N'外部脚本（2016+）',
 N'开启后可在库内执行 Python/R 脚本，等价于在数据库进程里跑任意代码。',
 N'EXEC sp_configure ''external scripts enabled'', 0; RECONFIGURE;（需重启实例）'),
(N'clr strict security', 1, N'WARN', N'CLR 严格安全（2017+）',
 N'未开启时程序集按 UNSAFE 等价处理，放宽了 CLR 的使用边界。',
 N'EXEC sp_configure ''clr strict security'', 1; RECONFIGURE;');

INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint)
SELECT N'危险功能', v.DisplayName,
       CONVERT(nvarchar(20), c.value_in_use) + CASE WHEN c.value_in_use = v.WantValue THEN N'（符合）' ELSE N'' END,
       CONVERT(nvarchar(20), v.WantValue),
       CASE WHEN c.value_in_use = v.WantValue THEN N'PASS' ELSE v.Severity END,
       v.Risk, v.FixHint
FROM sys.configurations c
JOIN @CfgCheck v ON v.ConfigName = c.name;

/* ------------------------------------------------------------
   六、登录审核
   ------------------------------------------------------------ */
DECLARE @auditLevel nvarchar(128) = NULL;
IF OBJECT_ID(N'tempdb..#lc') IS NOT NULL DROP TABLE #lc;
CREATE TABLE #lc ([name] sysname NULL, [config_value] sysname NULL);
BEGIN TRY
    INSERT #lc ([name], [config_value]) EXEC master.dbo.xp_loginconfig N'audit level';
    SELECT TOP (1) @auditLevel = [config_value] FROM #lc;
END TRY
BEGIN CATCH
    SET @auditLevel = NULL;
END CATCH
DROP TABLE #lc;

INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint) VALUES
(N'审计', N'登录审核级别',
 ISNULL(@auditLevel, N'读取失败'),
 N'failure 或 all',
 CASE WHEN @auditLevel IS NULL THEN N'INFO'
      WHEN LOWER(@auditLevel) = N'none' THEN N'FAIL'
      WHEN LOWER(@auditLevel) = N'success' THEN N'WARN'
      ELSE N'PASS' END,
 N'不记录失败登录时，口令爆破与异常来源登录无法被发现，事后也无法追溯。',
 N'SSMS → 实例属性 → 安全性 → 登录审核，选择“失败和成功的登录”（注册表 AuditLevel=3，需重启实例生效）。');

/* ------------------------------------------------------------
   七、服务器级高权限授予
   ------------------------------------------------------------ */
DECLARE @permList nvarchar(max) =
    ISNULL((SELECT STUFF((SELECT DISTINCT N', ' + pr.name + N'/' + p.permission_name
                            FROM sys.server_permissions p
                            JOIN sys.server_principals pr ON pr.principal_id = p.grantee_principal_id
                           WHERE p.class = 100 AND p.state IN (N'G', N'W')
                             AND LOWER(p.permission_name) IN
                                 (N'control server', N'alter any login', N'alter any server role',
                                  N'unsafe assembly', N'impersonate any login', N'alter any credential',
                                  N'alter any event session', N'alter trace')
                             AND pr.principal_id <> 1
                             AND pr.type IN (N'S', N'U', N'G')
                             AND IS_SRVROLEMEMBER(N'sysadmin', pr.name) = 0
                             FOR XML PATH(''), TYPE).value(N'.', N'nvarchar(max)'), 1, 2, N'')), N'无');

INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint) VALUES
(N'权限', N'非管理员的服务器级高权限', @permList,
 N'无（或严格受控）',
 CASE WHEN @permList = N'无' THEN N'PASS' ELSE N'FAIL' END,
 N'CONTROL SERVER / ALTER ANY LOGIN / IMPERSONATE ANY LOGIN 等等价或接近 sysadmin，可被直接用于提权。',
 N'REVOKE 不需要的服务器级权限；确需授权时改用受控管理账号并定期复核授权范围。');

/* ------------------------------------------------------------
   八、链接服务器（存储的远端凭据）
   ------------------------------------------------------------ */
DECLARE @linkedCount int =
    (SELECT COUNT(*) FROM sys.linked_logins WHERE uses_self_credential = 0);

DECLARE @linkedList nvarchar(max) =
    ISNULL((SELECT STUFF((SELECT DISTINCT N', ' + s.name
                            FROM sys.linked_logins ll
                            JOIN sys.servers s ON s.server_id = ll.server_id
                           WHERE ll.uses_self_credential = 0
                             FOR XML PATH(''), TYPE).value(N'.', N'nvarchar(max)'), 1, 2, N'')), N'无');

INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint) VALUES
(N'链接服务器', N'使用显式远端凭据的链接服务器',
 CONVERT(nvarchar(10), @linkedCount) + N' 个：' + @linkedList,
 N'0 个（优先使用当前安全上下文）',
 CASE WHEN @linkedCount > 0 THEN N'WARN' ELSE N'PASS' END,
 N'链接服务器保存的远端账号口令可被高权限用户取回，常被用于横向移动。',
 N'改为“使用当前安全上下文”，或删除不再使用的链接服务器。');

/* ------------------------------------------------------------
   九、数据库级检查
   ------------------------------------------------------------ */
IF OBJECT_ID(N'tempdb..#dbchk') IS NOT NULL DROP TABLE #dbchk;
CREATE TABLE #dbchk
(
    DbName          sysname       NOT NULL PRIMARY KEY,
    Trustworthy     bit           NOT NULL,
    OwnerName       sysname       NULL,
    OwnerIsSysadmin bit           NOT NULL,
    DbOwnerCount    int           NOT NULL,
    DbOwnerList     nvarchar(max) NULL,
    GuestConnect    int           NOT NULL,
    OrphanCount     int           NOT NULL,
    OrphanList      nvarchar(max) NULL
);

DECLARE @db sysname, @sql nvarchar(max);

DECLARE curDb CURSOR LOCAL FAST_FORWARD FOR
    SELECT name FROM sys.databases
    WHERE database_id > 4
      AND state = 0
      AND source_database_id IS NULL
      AND HAS_DBACCESS(name) = 1;

OPEN curDb;
FETCH NEXT FROM curDb INTO @db;
WHILE @@FETCH_STATUS = 0
BEGIN
    SET @sql = N'
USE ' + QUOTENAME(@db) + N';
INSERT INTO #dbchk
(
    DbName, Trustworthy, OwnerName, OwnerIsSysadmin,
    DbOwnerCount, DbOwnerList, GuestConnect, OrphanCount, OrphanList
)
SELECT
    DB_NAME(),
    d.is_trustworthy_on,
    SUSER_SNAME(d.owner_sid),
    CASE WHEN IS_SRVROLEMEMBER(''sysadmin'', SUSER_SNAME(d.owner_sid)) = 1 THEN 1 ELSE 0 END,
    (SELECT COUNT(*) FROM sys.database_role_members rm
       JOIN sys.database_principals rp ON rp.principal_id = rm.role_principal_id
       JOIN sys.database_principals up ON up.principal_id = rm.member_principal_id
      WHERE rp.name = @ownerRole AND up.name <> @dboName),
    ISNULL(STUFF((SELECT N'', '' + up.name
                    FROM sys.database_role_members rm
                    JOIN sys.database_principals rp ON rp.principal_id = rm.role_principal_id
                    JOIN sys.database_principals up ON up.principal_id = rm.member_principal_id
                   WHERE rp.name = @ownerRole AND up.name <> @dboName
                   ORDER BY up.name
                     FOR XML PATH(''''), TYPE).value(''.'', ''nvarchar(max)''), 1, 2, N''''), N''''),
    (SELECT COUNT(*) FROM sys.database_permissions p
      WHERE p.grantee_principal_id = DATABASE_PRINCIPAL_ID(@guestName)
        AND p.permission_name = N''CONNECT''
        AND p.state IN (N''G'', N''W'')),
    (SELECT COUNT(*) FROM sys.database_principals dp
      WHERE dp.principal_id > 4 AND dp.sid IS NOT NULL
        AND dp.type IN (N''S'', N''U'', N''G'')
        AND NOT EXISTS (SELECT 1 FROM sys.server_principals sp WHERE sp.sid = dp.sid)),
    ISNULL(STUFF((SELECT N'', '' + dp.name
                    FROM sys.database_principals dp
                   WHERE dp.principal_id > 4 AND dp.sid IS NOT NULL
                     AND dp.type IN (N''S'', N''U'', N''G'')
                     AND NOT EXISTS (SELECT 1 FROM sys.server_principals sp WHERE sp.sid = dp.sid)
                   ORDER BY dp.name
                     FOR XML PATH(''''), TYPE).value(''.'', ''nvarchar(max)''), 1, 2, N''''), N'''')
FROM sys.databases d
WHERE d.database_id = DB_ID();';

    BEGIN TRY
        EXEC sp_executesql @sql,
             N'@ownerRole sysname, @dboName sysname, @guestName sysname',
             @ownerRole = N'db_owner', @dboName = N'dbo', @guestName = N'guest';
    END TRY
    BEGIN CATCH
        INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint)
        VALUES (N'数据库', LEFT(N'[' + @db + N'] 检测失败', 100), LEFT(ERROR_MESSAGE(), 400), NULL, N'INFO', NULL, NULL);
    END CATCH

    FETCH NEXT FROM curDb INTO @db;
END
CLOSE curDb;
DEALLOCATE curDb;

-- TRUSTWORTHY = ON
INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint)
SELECT N'数据库', N'[' + DbName + N'] TRUSTWORTHY', N'ON', N'OFF', N'FAIL',
       N'TRUSTWORTHY=ON 时，库内 db_owner 可通过 EXECUTE AS 借用服务器级权限，直接提权到 sysadmin。',
       N'ALTER DATABASE ' + QUOTENAME(DbName) + N' SET TRUSTWORTHY OFF;'
FROM #dbchk WHERE Trustworthy = 1;

-- guest 可连接
INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint)
SELECT N'数据库', N'[' + DbName + N'] guest 用户', N'已启用 CONNECT（可匿名访问）', N'已回收 CONNECT', N'FAIL',
       N'guest 可连接意味着任何能登录实例的账号都能进入该库，造成越权数据访问。',
       N'USE ' + QUOTENAME(DbName) + N'; REVOKE CONNECT FROM guest;'
FROM #dbchk WHERE GuestConnect > 0;

-- 数据库所有者不是 sysadmin
INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint)
SELECT N'数据库', N'[' + DbName + N'] 数据库所有者', ISNULL(OwnerName, N'未知'), N'sa', N'WARN',
       N'所有者不是 sysadmin 时，登录被删除会留下孤儿 dbo，且所有者可能借此保留访问能力。',
       N'ALTER AUTHORIZATION ON DATABASE::' + QUOTENAME(DbName) + N' TO [sa];'
FROM #dbchk WHERE OwnerIsSysadmin = 0;

-- db_owner 成员（信息项）
INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint)
SELECT N'数据库', N'[' + DbName + N'] db_owner 成员',
       CONVERT(nvarchar(10), DbOwnerCount) + N' 个：' + ISNULL(DbOwnerList, N''),
       N'仅必要的管理员',
       CASE WHEN DbOwnerCount > 0 THEN N'WARN' ELSE N'PASS' END,
       N'db_owner 可创建/删除对象并配合 TRUSTWORTHY 提权，业务/开发账号不应长期持有。',
       N'改为 db_datareader + db_datawriter（必要时加 db_ddladmin）。'
FROM #dbchk
WHERE DbOwnerCount > 0;

-- 孤儿用户
INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint)
SELECT N'数据库', N'[' + DbName + N'] 孤儿用户',
       CONVERT(nvarchar(10), OrphanCount) + N' 个：' + ISNULL(OrphanList, N''),
       N'0 个',
       CASE WHEN OrphanCount > 0 THEN N'WARN' ELSE N'PASS' END,
       N'孤儿用户对应的登录已不存在，若同名登录被他人创建即可直接继承其库权限。',
       N'USE ' + QUOTENAME(DbName) + N'; DROP USER [用户名]; 或重新映射到正确登录。'
FROM #dbchk
WHERE OrphanCount > 0;

-- 全部通过的库
INSERT #chk (Category, Item, CurVal, ExpVal, Result, Risk, FixHint)
SELECT N'数据库', N'[' + DbName + N'] 库级加固',
       N'TRUSTWORTHY=OFF，guest 无 CONNECT，owner=sa，db_owner 仅管理员，无孤儿用户',
       N'同上', N'PASS', NULL, NULL
FROM #dbchk
WHERE Trustworthy = 0 AND GuestConnect = 0 AND OwnerIsSysadmin = 1
  AND DbOwnerCount = 0 AND OrphanCount = 0;

/* ------------------------------------------------------------
   十、输出
   ------------------------------------------------------------ */
SELECT Category AS [类别],
       Item     AS [检查项],
       CurVal   AS [当前值],
       ExpVal   AS [期望值],
       Result   AS [结果],
       Risk     AS [风险说明],
       FixHint  AS [修复建议]
FROM #chk
ORDER BY CASE Result WHEN N'FAIL' THEN 1 WHEN N'WARN' THEN 2 WHEN N'PASS' THEN 3 ELSE 4 END,
         Category, Seq;

SELECT SUM(CASE WHEN Result = N'FAIL' THEN 1 ELSE 0 END) AS [FAIL],
       SUM(CASE WHEN Result = N'WARN' THEN 1 ELSE 0 END) AS [WARN],
       SUM(CASE WHEN Result = N'PASS' THEN 1 ELSE 0 END) AS [PASS],
       SUM(CASE WHEN Result = N'INFO' THEN 1 ELSE 0 END) AS [INFO]
FROM #chk;

SELECT DbName          AS [数据库],
       Trustworthy     AS [TRUSTWORTHY],
       OwnerName       AS [所有者],
       OwnerIsSysadmin AS [所有者是sysadmin],
       DbOwnerCount    AS [db_owner数],
       ISNULL(DbOwnerList, N'') AS [db_owner成员],
       GuestConnect    AS [guest可连接],
       OrphanCount     AS [孤儿用户数],
       ISNULL(OrphanList, N'')  AS [孤儿用户]
FROM #dbchk
ORDER BY DbName;

DECLARE @failCount int = (SELECT COUNT(*) FROM #chk WHERE Result = N'FAIL');
DECLARE @warnCount int = (SELECT COUNT(*) FROM #chk WHERE Result = N'WARN');
PRINT N'检测完成：FAIL ' + CONVERT(nvarchar(10), @failCount) + N' 项，WARN ' + CONVERT(nvarchar(10), @warnCount) + N' 项。';
PRINT N'优先处理 FAIL 项；修复后重新执行本脚本复核。';

