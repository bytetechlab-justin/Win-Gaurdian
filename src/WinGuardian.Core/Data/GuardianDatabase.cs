using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace WinGuardian.Core.Data;

/// <summary>
/// SQLite store for the baseline (files, processes, services, persistence), the event history,
/// trust list, quarantine index, reputation cache and runtime settings.
/// Each operation opens its own pooled connection; WAL mode lets readers run during long scans.
/// </summary>
public sealed class GuardianDatabase
{
    public const string MetaBaselineCreated = "baseline_created_utc";
    public const string MetaLastFullScan = "last_full_scan_utc";
    public const string MetaFileGeneration = "file_generation";
    public const string MetaPersistenceBaseline = "persistence_baseline_utc";
    public const string MetaHeartbeat = "heartbeat_utc";
    public const string MetaCleanStop = "clean_stop_utc";
    public const string MetaSelfManifest = "self_manifest";
    public const string MetaRuntimeSettings = "runtime_settings";
    public const string MetaTasksBaseline = "tasks_baseline_utc";
    public const string MetaAuditingEnabledByUs = "task_auditing_enabled_by_winguardian";
    public const string MetaNetworkBaseline = "network_baseline_utc";
    public const string MetaFirewallState = "firewall_state";

    private readonly string _connectionString;

    public GuardianDatabase(string path)
    {
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = true,
            DefaultTimeout = 60,
        }.ToString();
    }

    public SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    public void Initialize()
    {
        using var c = Open();
        Execute(c, null, "PRAGMA journal_mode=WAL;");
        Execute(c, null, """
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS files (
                path   TEXT PRIMARY KEY COLLATE NOCASE,
                size   INTEGER NOT NULL,
                mtime  INTEGER NOT NULL,
                sha256 TEXT,
                gen    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_files_gen ON files(gen);
            CREATE TABLE IF NOT EXISTS processes (
                key         TEXT PRIMARY KEY COLLATE NOCASE,
                name        TEXT NOT NULL,
                path        TEXT,
                sha256      TEXT,
                first_seen  TEXT NOT NULL,
                in_baseline INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS services (
                name         TEXT PRIMARY KEY COLLATE NOCASE,
                display_name TEXT,
                image_path   TEXT,
                service_dll  TEXT,
                type         INTEGER NOT NULL,
                start        INTEGER NOT NULL,
                object_name  TEXT
            );
            CREATE TABLE IF NOT EXISTS persistence (
                key         TEXT PRIMARY KEY COLLATE NOCASE,
                scope       TEXT NOT NULL COLLATE NOCASE,
                location    TEXT NOT NULL,
                name        TEXT NOT NULL,
                value       TEXT NOT NULL,
                target_path TEXT
            );
            CREATE TABLE IF NOT EXISTS persistence_scopes (
                scope TEXT PRIMARY KEY COLLATE NOCASE
            );
            CREATE TABLE IF NOT EXISTS events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                time_utc     TEXT NOT NULL,
                severity     INTEGER NOT NULL,
                category     TEXT NOT NULL,
                change       TEXT NOT NULL,
                subject      TEXT NOT NULL,
                details      TEXT,
                acknowledged INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS ix_events_ack ON events(acknowledged);
            CREATE TABLE IF NOT EXISTS trusted (
                kind      TEXT NOT NULL,
                value     TEXT NOT NULL COLLATE NOCASE,
                added_utc TEXT NOT NULL,
                note      TEXT,
                PRIMARY KEY (kind, value)
            );
            CREATE TABLE IF NOT EXISTS quarantine (
                id              TEXT PRIMARY KEY,
                original_path   TEXT NOT NULL,
                sha256          TEXT,
                size            INTEGER NOT NULL,
                quarantined_utc TEXT NOT NULL,
                reason          TEXT,
                xor_key         BLOB NOT NULL,
                pending_reboot  INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                path        TEXT PRIMARY KEY COLLATE NOCASE,
                state_json  TEXT NOT NULL,
                updated_utc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS listening_ports (
                key            TEXT PRIMARY KEY COLLATE NOCASE,
                protocol       TEXT NOT NULL,
                port           INTEGER NOT NULL,
                process        TEXT NOT NULL,
                first_seen_utc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS firewall_rules (
                key TEXT PRIMARY KEY COLLATE NOCASE,
                raw TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blocked (
                id   TEXT PRIMARY KEY,
                path TEXT NOT NULL COLLATE NOCASE,
                json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reputation (
                sha256      TEXT NOT NULL COLLATE NOCASE,
                provider    TEXT NOT NULL,
                verdict     TEXT NOT NULL,
                label       TEXT,
                detail      TEXT,
                link        TEXT,
                checked_utc TEXT NOT NULL,
                PRIMARY KEY (sha256, provider)
            );
            """);

        // Columns added after the first release.
        EnsureColumn(c, "events", "file_path", "TEXT");
        EnsureColumn(c, "events", "sha256", "TEXT");
        EnsureColumn(c, "events", "trust_key", "TEXT");
        EnsureColumn(c, "events", "signature", "TEXT");
        EnsureColumn(c, "events", "signer", "TEXT");
        EnsureColumn(c, "events", "analysis", "TEXT");

        // Scheduled tasks moved from the generic persistence monitor to ScheduledTaskMonitor.
        Execute(c, null, "DELETE FROM persistence WHERE location = 'Scheduled Task'");
    }

    private static void EnsureColumn(SqliteConnection c, string table, string column, string type)
    {
        using var cmd = Command(c, null, $"SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = $n", ("$n", column));
        if ((long)cmd.ExecuteScalar()! == 0)
            Execute(c, null, $"ALTER TABLE {table} ADD COLUMN {column} {type}");
    }

    // ---------------------------------------------------------------- meta

    public string? GetMeta(string key)
    {
        using var c = Open();
        return Scalar(c, null, "SELECT value FROM meta WHERE key = $k", ("$k", key)) as string;
    }

    public void SetMeta(string key, string? value, SqliteConnection? c = null, SqliteTransaction? tx = null)
    {
        using var owned = c is null ? Open() : null;
        Execute(c ?? owned!, tx,
            "INSERT INTO meta(key, value) VALUES($k, $v) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("$k", key), ("$v", value));
    }

    public DateTime? GetMetaDate(string key) =>
        GetMeta(key) is { } s ? DateTime.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind) : null;

    public void SetMetaDate(string key, DateTime value) => SetMeta(key, Iso(value));

    public long GetFileGeneration() => long.TryParse(GetMeta(MetaFileGeneration), out var g) ? g : 0;

    public RuntimeSettings GetRuntimeSettings() =>
        GetMeta(MetaRuntimeSettings) is { } json
            ? JsonSerializer.Deserialize<RuntimeSettings>(json) ?? new RuntimeSettings()
            : new RuntimeSettings();

    public void SetRuntimeSettings(RuntimeSettings settings) =>
        SetMeta(MetaRuntimeSettings, JsonSerializer.Serialize(settings));

    /// <summary>Wipes the baseline so it will be rebuilt. Event history, trust list and quarantine are kept.</summary>
    public void ClearBaseline()
    {
        using var c = Open();
        using var tx = c.BeginTransaction();
        Execute(c, tx, """
            DELETE FROM files; DELETE FROM processes; DELETE FROM services;
            DELETE FROM persistence; DELETE FROM persistence_scopes; DELETE FROM scheduled_tasks;
            DELETE FROM listening_ports; DELETE FROM firewall_rules;
            """);
        Execute(c, tx, "DELETE FROM meta WHERE key IN ($a, $b, $c, $d, $e, $f)",
            ("$a", MetaBaselineCreated), ("$b", MetaLastFullScan), ("$c", MetaPersistenceBaseline), ("$d", MetaTasksBaseline),
            ("$e", MetaNetworkBaseline), ("$f", MetaFirewallState));
        tx.Commit();
    }

    public (long Files, long Processes, long Services, long Persistence) GetBaselineCounts()
    {
        using var c = Open();
        return (
            (long)Scalar(c, null, "SELECT COUNT(*) FROM files")!,
            (long)Scalar(c, null, "SELECT COUNT(*) FROM processes")!,
            (long)Scalar(c, null, "SELECT COUNT(*) FROM services")!,
            (long)Scalar(c, null, "SELECT COUNT(*) FROM persistence")!);
    }

    // --------------------------------------------------------------- files

    /// <summary>Records a file as known-good in the baseline (used after a quarantine restore).</summary>
    public void UpsertFile(FileRecord f)
    {
        using var c = Open();
        using var store = new FileStore(c);
        store.Upsert(f, GetFileGeneration());
    }

    public void DeleteFile(string path)
    {
        using var c = Open();
        Execute(c, null, "DELETE FROM files WHERE path = $p", ("$p", path));
    }

    // ----------------------------------------------------------- processes

    public HashSet<string> GetProcessKeys()
    {
        using var c = Open();
        using var cmd = Command(c, null, "SELECT key FROM processes");
        using var r = cmd.ExecuteReader();
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (r.Read()) keys.Add(r.GetString(0));
        return keys;
    }

    public void InsertProcess(SqliteConnection c, SqliteTransaction? tx, ProcessSnapshot p, string? sha256, bool inBaseline) =>
        Execute(c, tx, """
            INSERT INTO processes(key, name, path, sha256, first_seen, in_baseline)
            VALUES($k, $n, $p, $h, $t, $b) ON CONFLICT(key) DO NOTHING
            """,
            ("$k", p.Key), ("$n", p.Name), ("$p", p.ImagePath), ("$h", sha256),
            ("$t", Iso(DateTime.UtcNow)), ("$b", inBaseline ? 1 : 0));

    // ------------------------------------------------------------ services

    public Dictionary<string, ServiceRecord> GetServices()
    {
        using var c = Open();
        using var cmd = Command(c, null,
            "SELECT name, display_name, image_path, service_dll, type, start, object_name FROM services");
        using var r = cmd.ExecuteReader();
        var result = new Dictionary<string, ServiceRecord>(StringComparer.OrdinalIgnoreCase);
        while (r.Read())
        {
            var s = new ServiceRecord(r.GetString(0), NullableString(r, 1), NullableString(r, 2),
                NullableString(r, 3), r.GetInt32(4), r.GetInt32(5), NullableString(r, 6));
            result[s.Name] = s;
        }
        return result;
    }

    public void ReplaceServices(SqliteConnection c, SqliteTransaction tx, IEnumerable<ServiceRecord> services)
    {
        Execute(c, tx, "DELETE FROM services");
        using var cmd = Command(c, tx, """
            INSERT INTO services(name, display_name, image_path, service_dll, type, start, object_name)
            VALUES($n, $d, $i, $s, $t, $st, $o)
            """);
        var pn = cmd.Parameters.Add("$n", SqliteType.Text);
        var pd = cmd.Parameters.Add("$d", SqliteType.Text);
        var pi = cmd.Parameters.Add("$i", SqliteType.Text);
        var ps = cmd.Parameters.Add("$s", SqliteType.Text);
        var pt = cmd.Parameters.Add("$t", SqliteType.Integer);
        var pst = cmd.Parameters.Add("$st", SqliteType.Integer);
        var po = cmd.Parameters.Add("$o", SqliteType.Text);
        foreach (var s in services)
        {
            pn.Value = s.Name;
            pd.Value = (object?)s.DisplayName ?? DBNull.Value;
            pi.Value = (object?)s.ImagePath ?? DBNull.Value;
            ps.Value = (object?)s.ServiceDll ?? DBNull.Value;
            pt.Value = s.Type;
            pst.Value = s.Start;
            po.Value = (object?)s.ObjectName ?? DBNull.Value;
            cmd.ExecuteNonQuery();
        }
    }

    // --------------------------------------------------------- persistence

    public Dictionary<string, PersistenceEntry> GetPersistence()
    {
        using var c = Open();
        using var cmd = Command(c, null, "SELECT scope, location, name, value, target_path FROM persistence");
        using var r = cmd.ExecuteReader();
        var result = new Dictionary<string, PersistenceEntry>(StringComparer.OrdinalIgnoreCase);
        while (r.Read())
        {
            var e = new PersistenceEntry(r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3), NullableString(r, 4));
            result[e.Key] = e;
        }
        return result;
    }

    public HashSet<string> GetPersistenceScopes()
    {
        using var c = Open();
        using var cmd = Command(c, null, "SELECT scope FROM persistence_scopes");
        using var r = cmd.ExecuteReader();
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (r.Read()) result.Add(r.GetString(0));
        return result;
    }

    /// <summary>Replaces the stored entries for the given scopes only; entries of other (unloaded) scopes are kept.</summary>
    public void ReplacePersistence(SqliteConnection c, SqliteTransaction tx, IReadOnlyCollection<string> scopes,
        IEnumerable<PersistenceEntry> entries)
    {
        foreach (var scope in scopes)
        {
            Execute(c, tx, "DELETE FROM persistence WHERE scope = $s", ("$s", scope));
            Execute(c, tx, "INSERT OR IGNORE INTO persistence_scopes(scope) VALUES($s)", ("$s", scope));
        }
        foreach (var e in entries)
        {
            Execute(c, tx, """
                INSERT OR REPLACE INTO persistence(key, scope, location, name, value, target_path)
                VALUES($k, $s, $l, $n, $v, $t)
                """,
                ("$k", e.Key), ("$s", e.Scope), ("$l", e.Location), ("$n", e.Name), ("$v", e.Value), ("$t", e.TargetPath));
        }
    }

    // -------------------------------------------------------------- events

    public long InsertEvent(SqliteConnection c, SqliteTransaction? tx, GuardianEvent e)
    {
        Execute(c, tx, """
            INSERT INTO events(time_utc, severity, category, change, subject, details, acknowledged, file_path, sha256, trust_key, signature, signer, analysis)
            VALUES($t, $s, $c, $ch, $sub, $d, $a, $fp, $h, $tk, $sig, $sgn, $an)
            """,
            ("$t", Iso(e.TimeUtc)), ("$s", (int)e.Severity),
            ("$c", e.Category.ToString()), ("$ch", e.Change.ToString()), ("$sub", e.Subject),
            ("$d", e.Details), ("$a", e.Acknowledged ? 1 : 0),
            ("$fp", e.FilePath), ("$h", e.Sha256), ("$tk", e.TrustKey), ("$sig", e.Signature), ("$sgn", e.Signer), ("$an", e.Analysis));
        e.Id = (long)Scalar(c, tx, "SELECT last_insert_rowid()")!;
        return e.Id;
    }

    /// <summary>
    /// With <paramref name="sinceId"/>: events newer than that id, oldest first.
    /// Without: the most recent <paramref name="limit"/> events, newest first.
    /// </summary>
    public List<GuardianEvent> GetEvents(long? sinceId, int limit, bool unacknowledgedOnly, string? extraFilter = null)
    {
        using var c = Open();
        var where = new List<string>();
        if (extraFilter is not null) where.Add(extraFilter);
        if (sinceId is not null) where.Add("id > $since");
        if (unacknowledgedOnly) where.Add("acknowledged = 0");
        var sql = "SELECT id, time_utc, severity, category, change, subject, details, acknowledged, file_path, sha256, trust_key, signature, signer FROM events"
                  + (where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : "")
                  + (sinceId is not null ? " ORDER BY id ASC" : " ORDER BY id DESC")
                  + " LIMIT $limit";
        using var cmd = Command(c, null, sql, ("$since", sinceId), ("$limit", limit));
        using var r = cmd.ExecuteReader();
        var list = new List<GuardianEvent>();
        while (r.Read())
        {
            list.Add(new GuardianEvent
            {
                Id = r.GetInt64(0),
                TimeUtc = ParseIso(r.GetString(1)),
                Severity = (Severity)r.GetInt32(2),
                Category = Enum.TryParse<EventCategory>(r.GetString(3), out var cat) ? cat : EventCategory.System,
                Change = Enum.TryParse<ChangeKind>(r.GetString(4), out var ch) ? ch : ChangeKind.Info,
                Subject = r.GetString(5),
                Details = NullableString(r, 6),
                Acknowledged = r.GetInt64(7) != 0,
                FilePath = NullableString(r, 8),
                Sha256 = NullableString(r, 9),
                TrustKey = NullableString(r, 10),
                Signature = NullableString(r, 11),
                Signer = NullableString(r, 12),
            });
        }
        return list;
    }

    /// <summary>One event including its analysis JSON (which list queries leave out to stay small).</summary>
    public GuardianEvent? GetEvent(long id)
    {
        using var c = Open();
        var e = GetEvents(null, int.MaxValue, false, $"id = {id}").FirstOrDefault();
        if (e is not null) e.Analysis = Scalar(c, null, "SELECT analysis FROM events WHERE id = $id", ("$id", id)) as string;
        return e;
    }

    // ------------------------------------------------------------- blocked

    public List<string> GetBlocked()
    {
        using var c = Open();
        using var cmd = Command(c, null, "SELECT json FROM blocked ORDER BY path");
        using var r = cmd.ExecuteReader();
        var result = new List<string>();
        while (r.Read()) result.Add(r.GetString(0));
        return result;
    }

    public void InsertBlocked(string id, string path, string json)
    {
        using var c = Open();
        Execute(c, null, "INSERT INTO blocked(id, path, json) VALUES($i, $p, $j)", ("$i", id), ("$p", path), ("$j", json));
    }

    public void DeleteBlocked(string id)
    {
        using var c = Open();
        Execute(c, null, "DELETE FROM blocked WHERE id = $i", ("$i", id));
    }

    // ------------------------------------------------------------- network

    public Dictionary<string, DateTime> GetListenerFirstSeen()
    {
        using var c = Open();
        using var cmd = Command(c, null, "SELECT key, first_seen_utc FROM listening_ports");
        using var r = cmd.ExecuteReader();
        var result = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        while (r.Read()) result[r.GetString(0)] = ParseIso(r.GetString(1));
        return result;
    }

    public void InsertListener(string key, string protocol, int port, string process)
    {
        using var c = Open();
        Execute(c, null, "INSERT OR IGNORE INTO listening_ports(key, protocol, port, process, first_seen_utc) VALUES($k, $pr, $po, $p, $t)",
            ("$k", key), ("$pr", protocol), ("$po", port), ("$p", process), ("$t", Iso(DateTime.UtcNow)));
    }

    public Dictionary<string, string> GetFirewallRules()
    {
        using var c = Open();
        using var cmd = Command(c, null, "SELECT key, raw FROM firewall_rules");
        using var r = cmd.ExecuteReader();
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (r.Read()) result[r.GetString(0)] = r.GetString(1);
        return result;
    }

    public void ReplaceFirewallRules(IReadOnlyDictionary<string, string> rules)
    {
        using var c = Open();
        using var tx = c.BeginTransaction();
        Execute(c, tx, "DELETE FROM firewall_rules");
        foreach (var (key, raw) in rules)
            Execute(c, tx, "INSERT OR REPLACE INTO firewall_rules(key, raw) VALUES($k, $r)", ("$k", key), ("$r", raw));
        tx.Commit();
    }

    // ----------------------------------------------------- scheduled tasks

    public Dictionary<string, string> GetTaskStatesJson()
    {
        using var c = Open();
        using var cmd = Command(c, null, "SELECT path, state_json FROM scheduled_tasks");
        using var r = cmd.ExecuteReader();
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (r.Read()) result[r.GetString(0)] = r.GetString(1);
        return result;
    }

    public string? GetTaskStateJson(string path)
    {
        using var c = Open();
        return Scalar(c, null, "SELECT state_json FROM scheduled_tasks WHERE path = $p", ("$p", path)) as string;
    }

    public void UpsertTaskState(string path, string json)
    {
        using var c = Open();
        Execute(c, null, "INSERT OR REPLACE INTO scheduled_tasks(path, state_json, updated_utc) VALUES($p, $j, $t)",
            ("$p", path), ("$j", json), ("$t", Iso(DateTime.UtcNow)));
    }

    public void DeleteTaskState(string path)
    {
        using var c = Open();
        Execute(c, null, "DELETE FROM scheduled_tasks WHERE path = $p", ("$p", path));
    }

    public long CountTaskStates()
    {
        using var c = Open();
        return (long)Scalar(c, null, "SELECT COUNT(*) FROM scheduled_tasks")!;
    }

    /// <summary>Acknowledges the given events, or all of them when <paramref name="ids"/> is null or empty.</summary>
    public int Acknowledge(IReadOnlyCollection<long>? ids = null)
    {
        using var c = Open();
        if (ids is null || ids.Count == 0)
            return Execute(c, null, "UPDATE events SET acknowledged = 1 WHERE acknowledged = 0");

        using var tx = c.BeginTransaction();
        var count = ids.Sum(id => Execute(c, tx, "UPDATE events SET acknowledged = 1 WHERE id = $id AND acknowledged = 0", ("$id", id)));
        tx.Commit();
        return count;
    }

    public (long Count, Severity? Highest, long LatestId) GetEventSummary()
    {
        using var c = Open();
        using var cmd = Command(c, null, """
            SELECT (SELECT COUNT(*) FROM events WHERE acknowledged = 0),
                   (SELECT MAX(severity) FROM events WHERE acknowledged = 0),
                   (SELECT IFNULL(MAX(id), 0) FROM events)
            """);
        using var r = cmd.ExecuteReader();
        r.Read();
        return (r.GetInt64(0), r.IsDBNull(1) ? null : (Severity)r.GetInt32(1), r.GetInt64(2));
    }

    /// <summary>
    /// Deletes acknowledged events older than <paramref name="retentionDays"/>, and any event older than
    /// <paramref name="hardLimitDays"/> regardless of state.
    /// </summary>
    public int PruneEvents(int retentionDays, int hardLimitDays)
    {
        using var c = Open();
        var removed = Execute(c, null, "DELETE FROM events WHERE acknowledged = 1 AND time_utc < $t",
            ("$t", Iso(DateTime.UtcNow.AddDays(-retentionDays))));
        removed += Execute(c, null, "DELETE FROM events WHERE time_utc < $t",
            ("$t", Iso(DateTime.UtcNow.AddDays(-hardLimitDays))));
        return removed;
    }

    // ------------------------------------------------------------- trusted

    public List<TrustEntry> GetTrusted()
    {
        using var c = Open();
        using var cmd = Command(c, null, "SELECT kind, value, added_utc, note FROM trusted ORDER BY added_utc DESC");
        using var r = cmd.ExecuteReader();
        var list = new List<TrustEntry>();
        while (r.Read())
        {
            if (!Enum.TryParse<TrustKind>(r.GetString(0), out var kind)) continue;
            list.Add(new TrustEntry { Kind = kind, Value = r.GetString(1), AddedUtc = ParseIso(r.GetString(2)), Note = NullableString(r, 3) });
        }
        return list;
    }

    public void AddTrusted(TrustKind kind, string value, string? note)
    {
        using var c = Open();
        Execute(c, null, "INSERT OR REPLACE INTO trusted(kind, value, added_utc, note) VALUES($k, $v, $t, $n)",
            ("$k", kind.ToString()), ("$v", value), ("$t", Iso(DateTime.UtcNow)), ("$n", note));
    }

    public bool RemoveTrusted(TrustKind kind, string value)
    {
        using var c = Open();
        return Execute(c, null, "DELETE FROM trusted WHERE kind = $k AND value = $v", ("$k", kind.ToString()), ("$v", value)) > 0;
    }

    // ---------------------------------------------------------- quarantine

    public void InsertQuarantine(QuarantineItem q, byte[] xorKey)
    {
        using var c = Open();
        Execute(c, null, """
            INSERT INTO quarantine(id, original_path, sha256, size, quarantined_utc, reason, xor_key, pending_reboot)
            VALUES($id, $p, $h, $s, $t, $r, $k, $pr)
            """,
            ("$id", q.Id), ("$p", q.OriginalPath), ("$h", q.Sha256), ("$s", q.Size),
            ("$t", Iso(q.QuarantinedUtc)), ("$r", q.Reason), ("$k", xorKey), ("$pr", q.PendingReboot ? 1 : 0));
    }

    public List<QuarantineItem> GetQuarantine()
    {
        using var c = Open();
        using var cmd = Command(c, null,
            "SELECT id, original_path, sha256, size, quarantined_utc, reason, pending_reboot FROM quarantine ORDER BY quarantined_utc DESC");
        using var r = cmd.ExecuteReader();
        var list = new List<QuarantineItem>();
        while (r.Read())
        {
            list.Add(new QuarantineItem
            {
                Id = r.GetString(0),
                OriginalPath = r.GetString(1),
                Sha256 = NullableString(r, 2),
                Size = r.GetInt64(3),
                QuarantinedUtc = ParseIso(r.GetString(4)),
                Reason = NullableString(r, 5),
                PendingReboot = r.GetInt64(6) != 0,
            });
        }
        return list;
    }

    public (QuarantineItem Item, byte[] XorKey)? GetQuarantineItem(string id)
    {
        using var c = Open();
        using var cmd = Command(c, null,
            "SELECT original_path, sha256, size, quarantined_utc, reason, pending_reboot, xor_key FROM quarantine WHERE id = $id",
            ("$id", id));
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        var item = new QuarantineItem
        {
            Id = id,
            OriginalPath = r.GetString(0),
            Sha256 = NullableString(r, 1),
            Size = r.GetInt64(2),
            QuarantinedUtc = ParseIso(r.GetString(3)),
            Reason = NullableString(r, 4),
            PendingReboot = r.GetInt64(5) != 0,
        };
        return (item, (byte[])r.GetValue(6));
    }

    public void DeleteQuarantine(string id)
    {
        using var c = Open();
        Execute(c, null, "DELETE FROM quarantine WHERE id = $id", ("$id", id));
    }

    // ---------------------------------------------------------- reputation

    public ReputationResult? GetCachedReputation(string sha256, string provider, TimeSpan maxAge)
    {
        using var c = Open();
        using var cmd = Command(c, null,
            "SELECT verdict, label, detail, link, checked_utc FROM reputation WHERE sha256 = $h AND provider = $p",
            ("$h", sha256), ("$p", provider));
        using var r = cmd.ExecuteReader();
        if (!r.Read() || DateTime.UtcNow - ParseIso(r.GetString(4)) > maxAge) return null;
        return new ReputationResult(provider, Enum.Parse<ReputationVerdict>(r.GetString(0)),
            NullableString(r, 1), NullableString(r, 2), NullableString(r, 3));
    }

    public void CacheReputation(string sha256, ReputationResult result)
    {
        using var c = Open();
        Execute(c, null, """
            INSERT OR REPLACE INTO reputation(sha256, provider, verdict, label, detail, link, checked_utc)
            VALUES($h, $p, $v, $l, $d, $u, $t)
            """,
            ("$h", sha256), ("$p", result.Provider), ("$v", result.Verdict.ToString()), ("$l", result.Label),
            ("$d", result.Detail), ("$u", result.Link), ("$t", Iso(DateTime.UtcNow)));
    }

    // ------------------------------------------------------------- helpers

    public static string Iso(DateTime utc) => utc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static DateTime ParseIso(string s) => DateTime.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    public static SqliteCommand Command(SqliteConnection c, SqliteTransaction? tx, string sql,
        params (string Name, object? Value)[] args)
    {
        var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var (name, value) in args)
            cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return cmd;
    }

    public static int Execute(SqliteConnection c, SqliteTransaction? tx, string sql,
        params (string Name, object? Value)[] args)
    {
        using var cmd = Command(c, tx, sql, args);
        return cmd.ExecuteNonQuery();
    }

    public static object? Scalar(SqliteConnection c, SqliteTransaction? tx, string sql,
        params (string Name, object? Value)[] args)
    {
        using var cmd = Command(c, tx, sql, args);
        var value = cmd.ExecuteScalar();
        return value is DBNull ? null : value;
    }

    private static string? NullableString(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : r.GetString(i);
}
