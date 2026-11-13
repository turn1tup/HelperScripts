/* ============================================================
   SQL Server 开发账户创建脚本（幂等，可重复执行）
   适用：SQL Server 2012+      权限：sysadmin
   ------------------------------------------------------------
   本脚本只做两件事：创建/修复登录、按库授权。
   不做任何禁用、加固、权限回收动作。
   ------------------------------------------------------------
   执行方式：Ctrl+A 全选后 F5（脚本共用变量，不能分段执行）
   执行顺序：
     1) 本脚本 → 把账号密码给开发，应用改配置联调
     2) 应用测试通过后，再执行 sqlserver-fix.sql 做加固
   ============================================================ */

SET NOCOUNT ON;

/* ============================================================
   ① 用户配置区 —— 只改这一段
   ============================================================ */

-- 1. 开发登录清单：Password 为 NULL 时自动生成 20 位强密码并在结果里输出
--    IsWindowsLogin = 1 表示创建 Windows 登录（此时忽略 Password）
--    可列多个账号，一个账号一行
DECLARE @DevLogins TABLE
(
    LoginName       sysname       NOT NULL PRIMARY KEY,
    Password        nvarchar(128) NULL,
    IsWindowsLogin  bit           NOT NULL,
    DefaultDatabase sysname       NULL
);
INSERT @DevLogins (LoginName, Password, IsWindowsLogin, DefaultDatabase) VALUES
    (N'Dev_App',  NULL, 0, N'YourDatabase'),
    (N'Dev_App2', NULL, 0, N'YourDatabase');

-- 2. 库 / 角色授权：格式 (登录名, 库名, 角色名)，需要几个库/角色就加几行
DECLARE @DevGrants TABLE
(
    LoginName    sysname NOT NULL,
    DatabaseName sysname NOT NULL,
    RoleName     sysname NOT NULL,
    PRIMARY KEY (LoginName, DatabaseName, RoleName)
);
INSERT @DevGrants (LoginName, DatabaseName, RoleName) VALUES
    (N'Dev_App',  N'YourDatabase', N'db_datareader'),
    (N'Dev_App',  N'YourDatabase', N'db_datawriter'),
    (N'Dev_App2', N'YourDatabase', N'db_datareader'),
    (N'Dev_App2', N'YourDatabase', N'db_datawriter');
-- 需要建表 / 改表结构：追加 db_ddladmin；确实需要完全控制再加 db_owner

/* ============================================================
   ② 执行逻辑，无需修改
   ============================================================ */
DECLARE @sql   nvarchar(max),
        @login sysname,
        @pwd   nvarchar(128),
        @isWin bit,
        @defDb sysname,
        @db    sysname,
        @role  sysname,
        @chars nvarchar(100) = N'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%*?';

DECLARE @Created TABLE (LoginName sysname NOT NULL PRIMARY KEY, Password nvarchar(128) NOT NULL);

IF IS_SRVROLEMEMBER(N'sysadmin') <> 1
BEGIN
    RAISERROR(N'必须以 sysadmin 身份执行本脚本。', 16, 1);
    RETURN;
END;

PRINT N'===== 第 1 步：创建 / 修复开发登录 =====';

DECLARE curLogin CURSOR LOCAL FAST_FORWARD FOR
    SELECT LoginName, Password, IsWindowsLogin, DefaultDatabase FROM @DevLogins;

OPEN curLogin;
FETCH NEXT FROM curLogin INTO @login, @pwd, @isWin, @defDb;
WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = @login)
        BEGIN
            IF @isWin = 1
            BEGIN
                SET @sql = N'CREATE LOGIN ' + QUOTENAME(@login) + N' FROM WINDOWS;';
                EXEC sp_executesql @sql;
                PRINT N'  + 已创建 Windows 登录：' + @login;
            END
            ELSE
            BEGIN
                IF @pwd IS NULL
                BEGIN
                    -- 固定前缀保证复杂度，后 16 位随机
                    SELECT @pwd = N'Aa9!' +
                        (SELECT TOP (16)
                                SUBSTRING(@chars,
                                          1 + ABS(CONVERT(bigint, CHECKSUM(NEWID()))) % LEN(@chars), 1)
                           FROM sys.all_objects
                            FOR XML PATH(''), TYPE).value(N'.', N'nvarchar(max)');
                END
                SET @sql = N'CREATE LOGIN ' + QUOTENAME(@login)
                         + N' WITH PASSWORD = N''' + REPLACE(@pwd, N'''', N'''''') + N''','
                         + N' CHECK_POLICY = ON, CHECK_EXPIRATION = OFF';
                IF @defDb IS NOT NULL AND DB_ID(@defDb) IS NOT NULL
                    SET @sql += N', DEFAULT_DATABASE = ' + QUOTENAME(@defDb);
                SET @sql += N';';
                EXEC sp_executesql @sql;
                INSERT @Created (LoginName, Password) VALUES (@login, @pwd);
                PRINT N'  + 已创建 SQL 登录：' + @login + N'，初始密码：' + @pwd;
            END
        END
        ELSE
        BEGIN
            -- 已存在：只纠正策略与默认库，绝不重置密码，避免打断联调
            IF @isWin = 0
            BEGIN
                SET @sql = N'ALTER LOGIN ' + QUOTENAME(@login) + N' WITH CHECK_POLICY = ON, CHECK_EXPIRATION = OFF';
                IF @defDb IS NOT NULL AND DB_ID(@defDb) IS NOT NULL
                    SET @sql += N', DEFAULT_DATABASE = ' + QUOTENAME(@defDb);
                SET @sql += N';';
                EXEC sp_executesql @sql;
            END
            PRINT N'  ○ 登录已存在（未重置密码）：' + @login;
        END
    END TRY
    BEGIN CATCH
        PRINT N'  ✘ 创建登录失败：' + @login + N' → ' + ERROR_MESSAGE();
    END CATCH

    FETCH NEXT FROM curLogin INTO @login, @pwd, @isWin, @defDb;
END
CLOSE curLogin;
DEALLOCATE curLogin;

PRINT N'';
PRINT N'===== 第 2 步：授予库访问 =====';

DECLARE curGrant CURSOR LOCAL FAST_FORWARD FOR
    SELECT LoginName, DatabaseName, RoleName FROM @DevGrants;

OPEN curGrant;
FETCH NEXT FROM curGrant INTO @login, @db, @role;
WHILE @@FETCH_STATUS = 0
BEGIN
    IF DB_ID(@db) IS NULL
    BEGIN
        PRINT N'  ✘ 数据库不存在，跳过：' + @db + N'（' + @login + N'）';
    END
    ELSE
    BEGIN
        BEGIN TRY
            SET @sql = N'
USE ' + QUOTENAME(@db) + N';
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @loginName)
    CREATE USER ' + QUOTENAME(@login) + N' FOR LOGIN ' + QUOTENAME(@login) + N';
IF NOT EXISTS (SELECT 1
                 FROM sys.database_role_members rm
                 JOIN sys.database_principals rp ON rp.principal_id = rm.role_principal_id
                 JOIN sys.database_principals up ON up.principal_id = rm.member_principal_id
                WHERE rp.name = @roleName AND up.name = @loginName)
    ALTER ROLE ' + QUOTENAME(@role) + N' ADD MEMBER ' + QUOTENAME(@login) + N';';

            EXEC sp_executesql @sql,
                 N'@loginName sysname, @roleName sysname',
                 @loginName = @login, @roleName = @role;

            PRINT N'  + ' + @db + N'：' + @login + N' → ' + @role;
        END TRY
        BEGIN CATCH
            PRINT N'  ✘ 授权失败：' + @db + N' / ' + @login + N' → ' + ERROR_MESSAGE();
        END CATCH
    END

    FETCH NEXT FROM curGrant INTO @login, @db, @role;
END
CLOSE curGrant;
DEALLOCATE curGrant;

/* ------------------------------------------------------------
   结果
   ------------------------------------------------------------ */
PRINT N'';
PRINT N'===== 结果 =====';

SELECT d.LoginName                                                 AS [登录],
       sp.is_disabled                                              AS [已禁用],
       sl.is_policy_checked                                        AS [密码策略],
       d.DefaultDatabase                                           AS [默认库],
       CASE WHEN IS_SRVROLEMEMBER(N'sysadmin', d.LoginName) = 1 THEN N'✘ 在 sysadmin，需处理' ELSE N'✔ 非管理员' END AS [权限判定]
FROM @DevLogins d
LEFT JOIN sys.server_principals sp ON sp.name = d.LoginName
LEFT JOIN sys.sql_logins        sl ON sl.name = d.LoginName
ORDER BY d.LoginName;

IF EXISTS (SELECT 1 FROM @Created)
BEGIN
    PRINT N'--- 新建登录的初始密码（请立即记录，然后清理这里的输出） ---';
    SELECT LoginName AS [登录], Password AS [初始密码] FROM @Created ORDER BY LoginName;
END

PRINT N'';
PRINT N'下一步：把账号密码交付开发联调，应用测试通过后再执行 sqlserver-fix.sql 做加固。';
