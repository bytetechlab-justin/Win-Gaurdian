using Microsoft.Data.Sqlite;

namespace WinGuardian.Core.Data;

/// <summary>
/// Prepared statements for the files table, reused across hundreds of thousands of rows during a scan.
/// </summary>
public sealed class FileStore : IDisposable
{
    private readonly SqliteCommand _get;
    private readonly SqliteCommand _upsert;
    private readonly SqliteCommand _touch;
    private readonly SqliteCommand _delete;

    public FileStore(SqliteConnection connection)
    {
        _get = Create(connection, "SELECT size, mtime, sha256 FROM files WHERE path = $p", "$p");
        _upsert = Create(connection, """
            INSERT INTO files(path, size, mtime, sha256, gen) VALUES($p, $s, $m, $h, $g)
            ON CONFLICT(path) DO UPDATE SET size = excluded.size, mtime = excluded.mtime,
                                            sha256 = excluded.sha256, gen = excluded.gen
            """, "$p", "$s", "$m", "$h", "$g");
        _touch = Create(connection, "UPDATE files SET gen = $g WHERE path = $p", "$p", "$g");
        _delete = Create(connection, "DELETE FROM files WHERE path = $p", "$p");
    }

    public SqliteTransaction? Transaction
    {
        set => _get.Transaction = _upsert.Transaction = _touch.Transaction = _delete.Transaction = value;
    }

    public FileRecord? Get(string path)
    {
        _get.Parameters["$p"].Value = path;
        using var r = _get.ExecuteReader();
        if (!r.Read()) return null;
        return new FileRecord(path, r.GetInt64(0), r.GetInt64(1), r.IsDBNull(2) ? null : r.GetString(2));
    }

    public void Upsert(FileRecord f, long generation)
    {
        _upsert.Parameters["$p"].Value = f.Path;
        _upsert.Parameters["$s"].Value = f.Size;
        _upsert.Parameters["$m"].Value = f.LastWriteTicksUtc;
        _upsert.Parameters["$h"].Value = (object?)f.Sha256 ?? DBNull.Value;
        _upsert.Parameters["$g"].Value = generation;
        _upsert.ExecuteNonQuery();
    }

    public void Touch(string path, long generation)
    {
        _touch.Parameters["$p"].Value = path;
        _touch.Parameters["$g"].Value = generation;
        _touch.ExecuteNonQuery();
    }

    public void Delete(string path)
    {
        _delete.Parameters["$p"].Value = path;
        _delete.ExecuteNonQuery();
    }

    public void Dispose()
    {
        _get.Dispose();
        _upsert.Dispose();
        _touch.Dispose();
        _delete.Dispose();
    }

    private static SqliteCommand Create(SqliteConnection c, string sql, params string[] parameters)
    {
        var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var p in parameters) cmd.Parameters.Add(new SqliteParameter { ParameterName = p });
        return cmd;
    }
}
