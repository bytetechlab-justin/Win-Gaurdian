namespace WinGuardian.Tray;

/// <summary>Shared ListView helpers for the dashboard's data views.</summary>
internal static class ListViews
{
    /// <summary>A details-view list whose columns sort when clicked (numerically when both values are numbers).</summary>
    public static ListView MakeSortable(params (string Title, int Width)[] columns)
    {
        var list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false };
        foreach (var (title, width) in columns) list.Columns.Add(title, width);
        var sorter = new ColumnSorter();
        list.ListViewItemSorter = sorter;
        list.ColumnClick += (_, e) =>
        {
            sorter.Descending = sorter.Column == e.Column && !sorter.Descending;
            sorter.Column = e.Column;
            list.Sort();
        };
        return list;
    }

    /// <summary>Refills a list while keeping the user's selection and scroll position.</summary>
    public static void Fill<T>(ListView list, IEnumerable<T> rows, Func<T, ListViewItem> toItem, Func<T, string> keyOf)
    {
        var selected = list.SelectedItems.Cast<ListViewItem>().Select(i => i.Tag).OfType<T>().Select(keyOf).ToHashSet();
        var topIndex = list.TopItem?.Index ?? 0;

        list.BeginUpdate();
        list.Items.Clear();
        foreach (var row in rows)
        {
            var item = toItem(row);
            item.Selected = selected.Contains(keyOf(row));
            list.Items.Add(item);
        }
        list.Sort();
        if (list.Items.Count > 0) list.TopItem = list.Items[Math.Min(topIndex, list.Items.Count - 1)];
        list.EndUpdate();
    }

    /// <summary>Tab-separated text of the selected rows.</summary>
    public static void CopySelected(ListView list)
    {
        var lines = list.SelectedItems.Cast<ListViewItem>()
            .Select(i => string.Join("\t", i.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text)));
        var text = string.Join(Environment.NewLine, lines);
        if (text.Length > 0) Clipboard.SetText(text);
    }

    private sealed class ColumnSorter : System.Collections.IComparer
    {
        public int Column { get; set; } = -1;
        public bool Descending { get; set; }

        public int Compare(object? x, object? y)
        {
            if (Column < 0 || x is not ListViewItem a || y is not ListViewItem b) return 0;
            var sa = Column < a.SubItems.Count ? a.SubItems[Column].Text : "";
            var sb = Column < b.SubItems.Count ? b.SubItems[Column].Text : "";
            var result = long.TryParse(sa, out var na) && long.TryParse(sb, out var nb)
                ? na.CompareTo(nb)
                : string.Compare(sa, sb, StringComparison.OrdinalIgnoreCase);
            return Descending ? -result : result;
        }
    }
}
