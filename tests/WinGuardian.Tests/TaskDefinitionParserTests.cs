using System.Text;
using WinGuardian.Core.Tasks;

namespace WinGuardian.Tests;

public class TaskDefinitionParserTests
{
    [Fact]
    public void Parses_exec_action_principal_and_triggers()
    {
        var def = TaskDefinitionParser.Parse(TaskXml.Bytes(TaskXml.Exec(@"C:\Tools\app.exe", "--run now")), @"\Test\Exec");

        var action = Assert.Single(def.Actions);
        Assert.Equal("Exec", action.Type);
        Assert.Equal(@"C:\Tools\app.exe", action.Command);
        Assert.Equal("--run now", action.Arguments);
        Assert.True(def.RunsAsSystem);
        Assert.True(def.RunsPrivileged);
        Assert.Equal("LocalSystem", def.ExecutionAccount);
        Assert.Contains(def.Triggers, t => t.StartsWith("TimeTrigger") && t.Contains("every PT4H"));
        Assert.Single(def.TriggerBoundaries);
        Assert.Equal("WinGuardian tests", def.Author);
    }

    [Fact]
    public void Parses_com_handler_and_normalizes_class_id()
    {
        var def = TaskDefinitionParser.Parse(TaskXml.Bytes(TaskXml.Com("{e07647f7-aed2-48d9-9720-939bc24a8a3c}")), @"\Test\Com");
        var action = Assert.Single(def.Actions);
        Assert.Equal("ComHandler", action.Type);
        Assert.Equal("{E07647F7-AED2-48D9-9720-939BC24A8A3C}", action.ClassId);
    }

    [Fact]
    public void Group_principal_is_not_privileged()
    {
        var def = TaskDefinitionParser.Parse(TaskXml.Bytes(TaskXml.Exec("notepad.exe", principal: TaskXml.UsersGroupPrincipal)), @"\T");
        Assert.False(def.RunsPrivileged);
        Assert.StartsWith("Group:", def.ExecutionAccount);
    }

    [Fact]
    public void Highest_run_level_counts_as_privileged()
    {
        var xml = TaskXml.Exec("notepad.exe", principal: "<GroupId>S-1-5-32-545</GroupId><RunLevel>HighestAvailable</RunLevel>");
        Assert.True(TaskDefinitionParser.Parse(TaskXml.Bytes(xml), @"\T").RunsPrivileged);
    }

    [Fact]
    public void Malformed_definition_throws_parse_exception()
    {
        Assert.Throws<TaskParseException>(() =>
            TaskDefinitionParser.Parse(Encoding.UTF8.GetBytes("<Task><Actions><Exec>"), @"\Broken"));
    }

    [Fact]
    public void Non_task_xml_is_rejected()
    {
        Assert.Throws<TaskParseException>(() =>
            TaskDefinitionParser.Parse(Encoding.UTF8.GetBytes("<Something/>"), @"\Other"));
    }

    [Fact]
    public void External_entities_are_never_resolved()
    {
        var xxe = """
            <?xml version="1.0"?>
            <!DOCTYPE Task [<!ENTITY secret SYSTEM "file:///C:/Windows/win.ini">]>
            <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo><Description>&secret;</Description></RegistrationInfo>
            </Task>
            """;
        Assert.Throws<TaskParseException>(() => TaskDefinitionParser.Parse(Encoding.UTF8.GetBytes(xxe), @"\Xxe"));
    }

    [Fact]
    public void Real_windows_task_RefreshCache_is_a_com_handler()
    {
        var file = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            @"System32\Tasks\Microsoft\Windows\Flighting\OneSettings\RefreshCache");
        if (!File.Exists(file)) Assert.Skip("RefreshCache task not present on this machine.");
        byte[] bytes;
        try { bytes = File.ReadAllBytes(file); }
        catch (UnauthorizedAccessException) { Assert.Skip("Task file not readable without elevation."); return; }

        var def = TaskDefinitionParser.Parse(bytes, @"\Microsoft\Windows\Flighting\OneSettings\RefreshCache");
        var action = Assert.Single(def.Actions);
        Assert.Equal("ComHandler", action.Type);
        Assert.Equal("{E07647F7-AED2-48D9-9720-939BC24A8A3C}", action.ClassId);
        Assert.True(def.RunsAsSystem);
    }
}
