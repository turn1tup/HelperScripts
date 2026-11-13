/* ============================================================
   SQL Server 安全加固脚本（幂等，可重复执行）
   适用：SQL Server 2012+      权限：sysadmin
   ------------------------------------------------------------
   前置：开发账户已由 sqlserver-dev-accounts.sql 创建，应用测试已通过
   ------------------------------------------------------------
   脚本做三件事，第 4 步只做验证：
     第 1 步  sysadmin 收敛     sa 之外的管理员 → 禁用并移出角色 / 仅移出角色
     第 2 步  关闭高危组件      xp_cmdshell、CLR、OLE 自动化、外部脚本等
     第 3 步  口令策略          对全部 SQL 登录启用 CHECK_POLICY
     第 4 步  验证输出          纯查询，确认前三步结果 + 列出需人工处理的项
   脚本不做（第 4.3 步会列出待办）：
     不建账号、不改库属性（TRUSTWORTHY / guest / db_owner / 孤儿用户）、
     不回收服务器级 GRANT、不清理链接服务器凭据、
     不改登录审核级别（需改注册表并重启实例）
   ------------------------------------------------------------
   执行方式：Ctrl+A 全选后 F5（脚本共用变量，不能分段执行）
             首次建议先把 @UnexpectedSysadminAction 设为 'REPORT' 空跑，
             核对输出清单无误后再改为 'DISABLE' 正式执行
             （REPORT 只影响第 1 步，第 2~3 步仍会实际执行）
   ============================================================ */

SET NOCOUNT ON;

/* ============================================================
   ① 用户配置区 —— 只改这一段，改完直接执行
   ============================================================ */

-- 1. sysadmin 收敛策略：决定第 1 步如何处理“sa 之外的管理员”
--    REPORT  = 只打印清单，不动任何账号 —— 第一次务必先用这个核对
--    DISABLE = 禁用登录并移出 sysadmin（默认，推荐：管理员账号平时本就不该能连库）
--    REMOVE  = 只移出 sysadmin，登录仍可连接（适合要保留连接能力的账号）
DECLARE @UnexpectedSysadminAction varchar(10) = 'DISABLE';

-- 2. 明确保留 sysadmin 身份的账号（如运维 DBA）
--    sa、Windows 服务账号（NT SERVICE\*、NT AUTHORITY\*）和数据库服务的启动账号
--    由脚本自动识别保留，不需要写在这里
DECLARE @KeepSysadmin TABLE (LoginName sysname NOT NULL PRIMARY KEY);
-- INSERT @KeepSysadmin (LoginName) VALUES (N'DOMAIN\dba01');

-- 3. 只移出 sysadmin、但要保留登录可用的账号
--    用于历史遗留的业务/开发管理员账号：第 1 项的 DISABLE 会禁用它们并可能打断应用，
--    填在这里则只收回管理员身份，连接能力保留
DECLARE @RemoveFromRoleOnly TABLE (LoginName sysname NOT NULL PRIMARY KEY);
-- INSERT @RemoveFromRoleOnly (LoginName) VALUES (N'old_app_admin');

/* ============================================================
   ② 执行逻辑 —— 以下不需要修改
   ============================================================ */

-- 参数校验：写错值会让第 1 步静默落到“只移出角色”的默认分支，直接报错更安全
IF ISNULL(@UnexpectedSysadminAction, N'') NOT IN (N'REPORT', N'DISABLE', N'REMOVE')
BEGIN
    RAISERROR(N'@UnexpectedSysadminAction 只能取 REPORT / DISABLE / REMOVE。', 16, 1);
    RETURN;
END;

-- @saName：按 sid = 0x01 定位 sa（即使 sa 被改过名也能取到正确名称）
DECLARE @sql      nvarchar(max),
        @login    sysname,
        @cfgName  sysname,
        @cfgValue int,
        @saName   sysname = (SELECT name FROM sys.sql_logins WHERE sid = 0x01);

-- @Members：当前 sysadmin 成员快照（先拍快照再循环改动，避免边遍历边改）
-- @ServiceAccounts：SQL Server / Agent 等服务的启动账号（这些必须留在 sysadmin）
DECLARE @Members TABLE (LoginName sysname NOT NULL PRIMARY KEY);
DECLARE @ServiceAccounts TABLE (LoginName nvarchar(256) NOT NULL PRIMARY KEY);

-- 前置检查：必须 sysadmin，否则后面的 ALTER LOGIN、sp_configure 都会失败
IF IS_SRVROLEMEMBER(N'sysadmin') <> 1
BEGIN
    RAISERROR(N'必须以 sysadmin 身份执行本脚本。', 16, 1);
    RETURN;
END;

PRINT N'============================================================';
PRINT N'目标实例：' + CONVERT(nvarchar(256), SERVERPROPERTY('ServerName'))
               + N'（版本 ' + CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')) + N'）';
PRINT N'sysadmin 收敛策略：' + @UnexpectedSysadminAction;
PRINT N'============================================================';

/* ------------------------------------------------------------
   第 1 步：收敛 sysadmin 成员
   ------------------------------------------------------------
   逐个检查 sysadmin 成员，判定顺序如下（命中即止）：
     ① sa、@KeepSysadmin、Windows 服务账号 → 保留
     ② 当前会话使用的登录（含 Windows 组）→ 跳过（避免把自己锁死）
     ③ @RemoveFromRoleOnly                → 移出 sysadmin，登录仍可用
     ④ 其余账号                           → 按 @UnexpectedSysadminAction 处理
       DISABLE：禁用登录 + 移出 sysadmin（只禁用不移出，账号被重新启用
                就恢复完全控制，检测脚本也会继续判为不合格）
       REMOVE ：只移出 sysadmin
    注意：禁用不影响已建立的会话，账号重连时才被拒绝。
   回滚：
     ALTER LOGIN [账号] ENABLE;
     ALTER SERVER ROLE sysadmin ADD MEMBER [账号];
   ------------------------------------------------------------ */
PRINT N'';
PRINT N'===== 第 1 步：收敛 sysadmin 成员 =====';

-- 取当前 sysadmin 成员（先快照，循环里再改动不会影响遍历）
INSERT @Members (LoginName)
SELECT sp.name
FROM sys.server_role_members rm
JOIN sys.server_principals r  ON r.principal_id = rm.role_principal_id AND r.name = N'sysadmin'
JOIN sys.server_principals sp ON sp.principal_id = rm.member_principal_id;

-- 取数据库服务的启动账号；读不到（缺 VIEW SERVER STATE）不影响主流程
BEGIN TRY
    INSERT @ServiceAccounts (LoginName)
    SELECT DISTINCT service_account FROM sys.dm_server_services WHERE service_account IS NOT NULL;
END TRY
BEGIN CATCH
    PRINT N'  ! 无法读取服务账号清单，仅按 NT SERVICE\ / NT AUTHORITY\ 前缀识别。';
END CATCH

-- 本机管理员组是高危默认成员：处理前先提醒，避免连带禁掉备份/监控软件用的账号
IF EXISTS (SELECT 1 FROM @Members WHERE LoginName = N'BUILTIN\Administrators')
    PRINT N'  ! BUILTIN\Administrators 是 sysadmin 成员，将按策略处理；'
        + N'若有备份/监控软件以本机管理员身份连库，请先加入配置区第 2 项白名单。';

DECLARE curAdmin CURSOR LOCAL FAST_FORWARD FOR
    SELECT LoginName FROM @Members;

OPEN curAdmin;
FETCH NEXT FROM curAdmin INTO @login;
WHILE @@FETCH_STATUS = 0
BEGIN
    -- ① 保留：sa / 手工白名单 / 服务启动账号 / 内置账号
    IF @login = ISNULL(@saName, N'sa')
       OR EXISTS (SELECT 1 FROM @KeepSysadmin k WHERE k.LoginName = @login)
       OR EXISTS (SELECT 1 FROM @ServiceAccounts s WHERE s.LoginName = @login)
       OR @login LIKE N'NT SERVICE\%'
       OR @login LIKE N'NT AUTHORITY\%'
    BEGIN
        PRINT N'  ○ 保留 sysadmin：' + @login + N'（sa / 白名单 / 服务账号）';
    END
    -- ② 跳过当前会话使用的登录：直接匹配登录名，同时覆盖“用 Windows 组
    --    间接成为 sysadmin”的情况（ORIGINAL_LOGIN 只返回具体用户，比不到组名）
    ELSE IF @login = ORIGINAL_LOGIN()
         OR @login = SUSER_SNAME()
         OR IS_MEMBER(@login) = 1
    BEGIN
        PRINT N'  ! 跳过当前会话使用的登录：' + @login + N' —— 它是非白名单管理员，请人工确认后处理。';
    END
    -- ③ 只收回管理员身份，登录本身保留（应用仍可连接）
    ELSE IF EXISTS (SELECT 1 FROM @RemoveFromRoleOnly r WHERE r.LoginName = @login)
    BEGIN
        BEGIN TRY
            EXEC (N'ALTER SERVER ROLE sysadmin DROP MEMBER ' + QUOTENAME(@login) + N';');
            PRINT N'  ✘ 已移出 sysadmin（登录保留）：' + @login;
        END TRY
        BEGIN CATCH
            PRINT N'  ✘ 移出 sysadmin 失败：' + @login + N' → ' + ERROR_MESSAGE();
        END CATCH
    END
    -- ④ 其余账号（REPORT 模式）：只打印清单，不做任何改动
    ELSE IF @UnexpectedSysadminAction = N'REPORT'
    BEGIN
        PRINT N'  ✘ 非白名单管理员：' + @login + N'（REPORT 模式，未做处理）';
    END
    -- ④ 其余账号（正式执行）：DISABLE = 禁用 + 移出 sysadmin；REMOVE = 只移出 sysadmin
    --    两种策略都必须移出角色：只禁用的话账号仍是 sysadmin，一旦被重新
    --    ENABLE 就恢复完全控制，检测脚本也仍会判为不合格。
    ELSE
    BEGIN
        IF @UnexpectedSysadminAction = N'DISABLE'
        BEGIN
            BEGIN TRY
                EXEC (N'ALTER LOGIN ' + QUOTENAME(@login) + N' DISABLE;');
                PRINT N'  ✘ 已禁用登录：' + @login;
            END TRY
            BEGIN CATCH
                PRINT N'  ! 禁用登录失败：' + @login + N' → ' + ERROR_MESSAGE();
            END CATCH
        END

        BEGIN TRY
            EXEC (N'ALTER SERVER ROLE sysadmin DROP MEMBER ' + QUOTENAME(@login) + N';');
            PRINT N'  ✘ 已移出 sysadmin：' + @login;
        END TRY
        BEGIN CATCH
            PRINT N'  ✘ 移出 sysadmin 失败：' + @login + N' → ' + ERROR_MESSAGE();
        END CATCH
    END

    FETCH NEXT FROM curAdmin INTO @login;
END
CLOSE curAdmin;
DEALLOCATE curAdmin;

/* ------------------------------------------------------------
   第 2 步：关闭高危组件
   ------------------------------------------------------------
   下面这些扩展都能在 SQL 内执行系统命令或加载代码，是提权与横向移动的主路径。
   列出的每一项只在该功能确实被业务使用时才需要保留（把对应值改成 1 重跑即可）。
   脚本只改“当前值 ≠ 期望值”的项，可反复执行；结束后会把 show advanced options
   恢复为 0，减少被滥用的配置入口。
   ------------------------------------------------------------ */
PRINT N'';
PRINT N'===== 第 2 步：关闭高危组件 =====';

-- 这些都属于“高级选项”，必须先打开才能修改
EXEC sp_configure N'show advanced options', 1;
RECONFIGURE;

-- 配置项 → 期望值（0 = 关闭，1 = 开启）
DECLARE @Want TABLE (ConfigName sysname NOT NULL PRIMARY KEY, WantValue int NOT NULL);
INSERT @Want (ConfigName, WantValue) VALUES
    (N'xp_cmdshell',                       0),  -- 执行系统命令的入口
    (N'clr enabled',                       0),  -- 加载 .NET 程序集执行任意代码
    (N'Ole Automation Procedures',         0),  -- 通过 COM 执行命令、读写文件
    (N'Ad Hoc Distributed Queries',        0),  -- OPENROWSET 直接访问外部数据源
    (N'cross db ownership chaining',       0),  -- 跨库所有权链导致越权访问
    (N'contained database authentication', 0),  -- 包含库用户绕过实例级登录管控
    (N'remote admin connections',          0),  -- DAC 只允许本机连接
    (N'scan for startup procs',            0),  -- 启动时自动执行，可被植入后门
    (N'SQL Mail XPs',                      0),  -- 依赖已废弃的 MAPI 客户端
    (N'external scripts enabled',          0),  -- 2016+：库内 Python/R 可执行任意代码
    (N'clr strict security',               1);  -- 2017+ 才存在，不存在会自动跳过

-- 只处理“当前生效值与期望值不一致”的项
DECLARE curCfg CURSOR LOCAL FAST_FORWARD FOR
    SELECT w.ConfigName, w.WantValue
    FROM @Want w
    JOIN sys.configurations c ON c.name = w.ConfigName
    WHERE c.value_in_use <> w.WantValue;

OPEN curCfg;
FETCH NEXT FROM curCfg INTO @cfgName, @cfgValue;
WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        EXEC sp_configure @configname = @cfgName, @configvalue = @cfgValue;
        RECONFIGURE WITH OVERRIDE;   -- 部分选项必须 WITH OVERRIDE 才能生效
        PRINT N'  + 已设置 ' + @cfgName + N' = ' + CONVERT(nvarchar(10), @cfgValue);
    END TRY
    BEGIN CATCH
        PRINT N'  ✘ 设置失败：' + @cfgName + N' → ' + ERROR_MESSAGE();
    END CATCH

    FETCH NEXT FROM curCfg INTO @cfgName, @cfgValue;
END
CLOSE curCfg;
DEALLOCATE curCfg;

-- 恢复“隐藏高级选项”，减少被滥用的配置入口
EXEC sp_configure N'show advanced options', 0;
RECONFIGURE;
PRINT N'  + show advanced options 已恢复为 0。';

/* ------------------------------------------------------------
   第 2 步补充：残留在实例里的东西（只读，需人工确认）
   ------------------------------------------------------------
   关掉开关不等于清干净：启动过程的标记、xp_cmdshell 的代理凭据都还在，
   有人把开关改回来就会复活。
   ------------------------------------------------------------ */
PRINT N'';
PRINT N'--- 2.1 残留项清点 ---';

-- 已标记“启动时自动执行”的过程（本脚本只关 scan for startup procs，不删标记）
SET @sql = N'USE msdb;
SELECT o.name AS [启动时自动执行的存储过程]
FROM sys.objects o
WHERE o.type = N''P''
  AND OBJECTPROPERTY(o.object_id, N''ExecIsStartup'') = 1;';
BEGIN TRY
    EXEC sp_executesql @sql;
END TRY
BEGIN CATCH
    PRINT N'  ! 读取启动过程清单失败：' + ERROR_MESSAGE();
END CATCH

-- xp_cmdshell 代理账号、复制/备份等凭据里可能仍存有可用口令
SELECT name AS [凭据], credential_identity AS [身份]
FROM sys.credentials
ORDER BY name;

/* ------------------------------------------------------------
   第 3 步：启用 SQL 登录的口令策略
   ------------------------------------------------------------
   关闭 CHECK_POLICY 的登录不受复杂度与锁定策略保护，是口令爆破的主要入口。
   这里只打开策略：不改口令、不动过期设置，避免打断应用。
   注意：启用后该登录会受本机安全策略的“登录失败锁定”约束，口令被反复试错
   会短暂锁定账号，请确认应用侧不会用错口令重试。
   ------------------------------------------------------------ */
PRINT N'';
PRINT N'===== 第 3 步：启用 SQL 登录口令策略 =====';

DECLARE curPolicy CURSOR LOCAL FAST_FORWARD FOR
    SELECT name FROM sys.sql_logins
    WHERE is_policy_checked = 0 AND name NOT LIKE N'##%';

OPEN curPolicy;
FETCH NEXT FROM curPolicy INTO @login;
WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        EXEC (N'ALTER LOGIN ' + QUOTENAME(@login) + N' WITH CHECK_POLICY = ON;');
        PRINT N'  + 已启用密码策略：' + @login;
    END TRY
    BEGIN CATCH
        PRINT N'  ✘ 启用密码策略失败：' + @login + N' → ' + ERROR_MESSAGE();
    END CATCH

    FETCH NEXT FROM curPolicy INTO @login;
END
CLOSE curPolicy;
DEALLOCATE curPolicy;

/* ------------------------------------------------------------
   第 4 步：验证（以下全部是只读查询，不会修改任何配置）
   ------------------------------------------------------------ */
PRINT N'';
PRINT N'===== 第 4 步：验证结果 =====';

-- 应只剩 sa + 服务账号；出现“✘ 非白名单管理员”说明需要人工确认或补进白名单
PRINT N'--- 4.1 sysadmin 成员 ---';
SELECT sp.name                                                        AS [成员],
       sp.type_desc                                                   AS [类型],
       sp.is_disabled                                                 AS [已禁用],
       CASE WHEN sp.principal_id = 1 THEN N'✔ sa（唯一 SQL 管理员）'
            WHEN EXISTS (SELECT 1 FROM @ServiceAccounts s WHERE s.LoginName = sp.name)
              OR sp.name LIKE N'NT SERVICE\%' OR sp.name LIKE N'NT AUTHORITY\%'
                 THEN N'○ 服务/内置账号（必须保留）'
            WHEN EXISTS (SELECT 1 FROM @KeepSysadmin k WHERE k.LoginName = sp.name) THEN N'○ 白名单保留'
            WHEN sp.is_disabled = 1 THEN N'✘ 已禁用但仍在 sysadmin（移出角色失败）'
            ELSE N'✘ 非白名单管理员' END                              AS [判定]
FROM sys.server_role_members rm
JOIN sys.server_principals r  ON r.principal_id = rm.role_principal_id AND r.name = N'sysadmin'
JOIN sys.server_principals sp ON sp.principal_id = rm.member_principal_id
ORDER BY sp.name;

-- 全部应为“✔”；出现“✘ 未加固”说明该项设置失败，看上面的报错
PRINT N'--- 4.2 危险组件状态 ---';
SELECT name                                                        AS [配置项],
       value_in_use                                                AS [当前值],
       CASE WHEN name = N'clr strict security' AND value_in_use = 1 THEN N'✔ 符合'
            WHEN name <> N'clr strict security' AND value_in_use = 0 THEN N'✔ 已禁用'
            ELSE N'✘ 未加固' END                                   AS [状态]
FROM sys.configurations
WHERE name IN (N'xp_cmdshell', N'clr enabled', N'Ole Automation Procedures',
               N'Ad Hoc Distributed Queries', N'cross db ownership chaining',
               N'contained database authentication', N'remote admin connections',
               N'scan for startup procs', N'SQL Mail XPs',
               N'external scripts enabled', N'clr strict security')
ORDER BY name;

IF NOT EXISTS (SELECT 1 FROM sys.configurations WHERE name = N'clr strict security')
    PRINT N'  ○ 当前版本没有 clr strict security（2017 之前），该项已跳过。';

/* ------------------------------------------------------------
   4.3 未纳入本脚本的项（只读，需人工处理）
   ------------------------------------------------------------
   这些项 sqlserver-check.sql 会判 FAIL/WARN，但本脚本刻意不自动改：
   涉及库属性与跨库影响，需要逐库确认后再动。
   ------------------------------------------------------------ */
PRINT N'--- 4.3 待人工处理的项 ---';

-- 服务器级高权限授予：等价于或接近实例完全控制权
SELECT pr.name                                                      AS [主体],
       p.permission_name                                            AS [权限],
       p.state_desc                                                 AS [状态]
FROM sys.server_permissions p
JOIN sys.server_principals pr ON pr.principal_id = p.grantee_principal_id
WHERE p.class = 100
  AND p.state IN (N'G', N'W')
  AND p.permission_name IN (N'CONTROL SERVER', N'ALTER ANY LOGIN', N'ALTER ANY SERVER ROLE',
                            N'IMPERSONATE ANY LOGIN', N'UNSAFE ASSEMBLY', N'ALTER ANY CREDENTIAL',
                            N'ALTER ANY EVENT SESSION', N'ALTER TRACE')
  AND pr.principal_id <> 1
  AND pr.type IN (N'S', N'U', N'G')
  AND IS_SRVROLEMEMBER(N'sysadmin', pr.name) = 0
ORDER BY pr.name;

-- 链接服务器保存的远端凭据
SELECT DISTINCT s.name                                              AS [链接服务器（保存了显式远端凭据）]
FROM sys.linked_logins ll
JOIN sys.servers s ON s.server_id = ll.server_id
WHERE ll.uses_self_credential = 0
ORDER BY s.name;

-- 库级：TRUSTWORTHY=ON，或所有者不是 sysadmin
SELECT d.name                                                       AS [数据库],
       d.is_trustworthy_on                                          AS [TRUSTWORTHY],
       SUSER_SNAME(d.owner_sid)                                     AS [所有者],
       CASE WHEN IS_SRVROLEMEMBER(N'sysadmin', SUSER_SNAME(d.owner_sid)) = 1
            THEN N'✔' ELSE N'✘ 非 sysadmin' END                    AS [所有者判定]
FROM sys.databases d
WHERE d.database_id > 4 AND d.state = 0 AND d.source_database_id IS NULL
  AND (d.is_trustworthy_on = 1
       OR ISNULL(IS_SRVROLEMEMBER(N'sysadmin', SUSER_SNAME(d.owner_sid)), 0) = 0)
ORDER BY d.name;

PRINT N'  · guest 可连接、db_owner 成员、孤儿用户需逐库处理，请用 sqlserver-check.sql 复核。';
PRINT N'  · 登录审核级别未自动修改（需改注册表并重启实例）：';
PRINT N'    SSMS → 实例属性 → 安全性 → 登录审核 → 选择“失败和成功的登录”。';

PRINT N'';
PRINT N'建议：用 sqlserver-check.sql 复核整体加固状态。';
PRINT N'脚本执行完毕。';
