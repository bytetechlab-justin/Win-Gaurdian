using System.Security.Principal;
using System.Xml;
using System.Xml.Linq;

namespace WinGuardian.Core.Tasks;

public sealed class TaskParseException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Parses Task Scheduler XML (the extension-less files under System32\Tasks). The bytes parsed are the
/// same bytes that were hashed, so the analysis always describes exactly the version that was hashed.
/// DTDs and external entities are rejected; nothing in the task is executed.
/// </summary>
public static class TaskDefinitionParser
{
    private const long MaxDocumentChars = 4_000_000;

    private static readonly XmlReaderSettings SafeSettings = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersFromEntities = 0,
        MaxCharactersInDocument = MaxDocumentChars,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
    };

    public static TaskDefinition Parse(byte[] content, string taskPath)
    {
        XDocument doc;
        try
        {
            using var stream = new MemoryStream(content);
            using var reader = XmlReader.Create(stream, SafeSettings);
            doc = XDocument.Load(reader);
        }
        catch (Exception ex) when (ex is XmlException or InvalidOperationException or ArgumentException)
        {
            throw new TaskParseException($"Malformed task definition: {ex.Message}", ex);
        }

        var root = doc.Root;
        if (root is null || root.Name.LocalName != "Task")
            throw new TaskParseException("Not a Task Scheduler definition (no <Task> root element).");

        var def = new TaskDefinition { Path = taskPath };

        var reg = Child(root, "RegistrationInfo");
        def.Description = Text(reg, "Description");
        def.Author = Text(reg, "Author");
        def.RegistrationDate = Text(reg, "Date");
        def.Source = Text(reg, "Source");

        var settings = Child(root, "Settings");
        def.Enabled = Bool(Text(settings, "Enabled"), defaultValue: true);
        def.Hidden = Bool(Text(settings, "Hidden"), defaultValue: false);

        ParsePrincipal(root, def);
        ParseTriggers(root, def);
        ParseActions(root, def);
        return def;
    }

    private static void ParsePrincipal(XElement root, TaskDefinition def)
    {
        var actions = Child(root, "Actions");
        var context = actions?.Attribute("Context")?.Value;
        var principals = Child(root, "Principals")?.Elements().Where(e => e.Name.LocalName == "Principal").ToList() ?? [];
        var principal = principals.FirstOrDefault(p => p.Attribute("id")?.Value == context) ?? principals.FirstOrDefault();

        def.UserId = Text(principal, "UserId");
        def.GroupId = Text(principal, "GroupId");
        def.LogonType = Text(principal, "LogonType");
        def.RunLevel = Text(principal, "RunLevel");

        var sid = ToSid(def.UserId);
        var groupSid = ToSid(def.GroupId);
        def.RunsAsSystem = sid == "S-1-5-18";
        def.RunsPrivileged = sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20" || groupSid == "S-1-5-32-544" ||
                             string.Equals(def.RunLevel, "HighestAvailable", StringComparison.OrdinalIgnoreCase);

        var account = sid switch
        {
            "S-1-5-18" => "LocalSystem",
            "S-1-5-19" => "LocalService",
            "S-1-5-20" => "NetworkService",
            null when def.GroupId is not null => $"Group: {AccountName(def.GroupId)}",
            null when def.UserId is not null => def.UserId,
            null => "(account that registered the task)",
            _ => AccountName(sid),
        };
        if (string.Equals(def.RunLevel, "HighestAvailable", StringComparison.OrdinalIgnoreCase))
            account += " (highest privileges)";
        def.ExecutionAccount = account;
    }

    private static void ParseTriggers(XElement root, TaskDefinition def)
    {
        foreach (var trigger in Child(root, "Triggers")?.Elements() ?? [])
        {
            var name = trigger.Name.LocalName;
            var parts = new List<string> { name };
            var schedule = trigger.Elements().FirstOrDefault(e => e.Name.LocalName.StartsWith("ScheduleBy", StringComparison.Ordinal));
            if (schedule is not null) parts.Add(schedule.Name.LocalName);
            if (Text(trigger, "UserId") is { } user) parts.Add($"user {user}");
            if (Text(trigger, "StateChange") is { } state) parts.Add(state);
            if (Text(trigger, "StateName") is { } wnf) parts.Add($"WNF {wnf}");
            if (Text(trigger, "Delay") is { } delay) parts.Add($"delay {delay}");
            if (Text(Child(trigger, "Repetition"), "Interval") is { } interval) parts.Add($"every {interval}");
            if (Text(trigger, "Subscription") is { } sub) parts.Add($"event {Truncate(sub, 200)}");
            if (!Bool(Text(trigger, "Enabled"), defaultValue: true)) parts.Add("(disabled)");
            def.Triggers.Add(string.Join(", ", parts));

            var start = Text(trigger, "StartBoundary");
            var end = Text(trigger, "EndBoundary");
            if (start is not null || end is not null)
                def.TriggerBoundaries.Add($"{name}: {start ?? "-"} .. {end ?? "-"}");
        }
    }

    private static void ParseActions(XElement root, TaskDefinition def)
    {
        foreach (var action in Child(root, "Actions")?.Elements() ?? [])
        {
            def.Actions.Add(action.Name.LocalName switch
            {
                "Exec" => new TaskAction
                {
                    Type = "Exec",
                    Command = Text(action, "Command"),
                    Arguments = Text(action, "Arguments"),
                    WorkingDirectory = Text(action, "WorkingDirectory"),
                },
                "ComHandler" => new TaskAction
                {
                    Type = "ComHandler",
                    ClassId = NormalizeClsid(Text(action, "ClassId")),
                    Data = Text(action, "Data"),
                },
                var other => new TaskAction { Type = other },
            });
        }
    }

    public static string? NormalizeClsid(string? value)
    {
        if (value is null) return null;
        return Guid.TryParse(value.Trim(), out var g) ? g.ToString("B").ToUpperInvariant() : value.Trim();
    }

    private static string? ToSid(string? account)
    {
        if (string.IsNullOrWhiteSpace(account)) return null;
        if (account.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) return account.ToUpperInvariant();
        if (account.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
            account.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase)) return "S-1-5-18";
        try
        {
            return ((SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier))).Value;
        }
        catch
        {
            return null;
        }
    }

    private static string AccountName(string sidOrName)
    {
        try
        {
            return sidOrName.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
                ? new SecurityIdentifier(sidOrName).Translate(typeof(NTAccount)).Value
                : sidOrName;
        }
        catch
        {
            return sidOrName;
        }
    }

    private static XElement? Child(XElement? parent, string name) =>
        parent?.Elements().FirstOrDefault(e => e.Name.LocalName == name);

    private static string? Text(XElement? parent, string name)
    {
        var value = Child(parent, name)?.Value.Trim();
        return string.IsNullOrEmpty(value) ? null : value;
    }

    private static bool Bool(string? value, bool defaultValue) =>
        value is null ? defaultValue : value.Equals("true", StringComparison.OrdinalIgnoreCase) || value == "1";

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
