// PrivateOwnerApp.cs - owner side. never ship this or the .key files
// first run makes the keys, then paste machine code, pick expiry, generate
// license layout is in the README
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

static class Issuer
{
    static readonly string Dir = AppDomain.CurrentDomain.BaseDirectory;
    public static string P(string name) { return Path.Combine(Dir, name); }
    public const string Tag = "CALC";   // same as kTag in the cpp
    static readonly string[] Ids = { "MachineGuid", "SMBIOS UUID", "Baseboard serial", "Disk serial" };   // slot order

    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.Run(new Gui());
    }

    public static long Unix(DateTime utc)
    {
        return (long)(utc - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
    }

    // issuer.key signs, if it's lost use spare.key
    static string SignKeyPath() { return File.Exists(P("issuer.key")) ? P("issuer.key") : P("spare.key"); }

    public static bool HasKey() { return File.Exists(P("issuer.key")) || File.Exists(P("spare.key")); }

    static byte[] Sha(byte[] data) { using (var h = SHA256.Create()) return h.ComputeHash(data); }

    static void Pair(string privFile, StringBuilder rows)
    {
        var p = new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.AllowPlaintextExport };
        using (var k = CngKey.Create(CngAlgorithm.ECDsaP256, null, p))
        {
            byte[] pub = k.Export(CngKeyBlobFormat.EccPublicBlob);   // 8b header then X, Y
            File.WriteAllText(privFile, Convert.ToBase64String(k.Export(CngKeyBlobFormat.EccPrivateBlob)));
            rows.Append("{");
            for (int i = 8; i < 72; i++) rows.Append("0x" + pub[i].ToString("x2") + (i < 71 ? "," : ""));
            rows.Append("},\r\n");
        }
    }

    // one-time setup: 2 signing keys, app key, public.txt
    public static string NewKey()
    {
        foreach (string f in new[] { "issuer.key", "spare.key", "asset.key" })
            if (File.Exists(P(f))) throw new Exception(f + " already exists, refusing to overwrite");
        var rows = new StringBuilder();
        Pair(P("issuer.key"), rows);
        Pair(P("spare.key"), rows);
        File.WriteAllText(P("public.txt"),
            "Paste these rows into kPub in ExampleShippedApp.cpp (replacing what's there) and rebuild.\r\n" +
            "First row is the primary key, second is the spare.\r\n\r\n" + rows);

        var K = new byte[16];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(K);
        File.WriteAllText(P("asset.key"), Convert.ToBase64String(K));
        return "Made issuer.key, spare.key, asset.key and public.txt in " + Dir +
               "\r\nTake spare.key off this PC now and back up asset.key. If either one is lost you can never issue another license.";
    }

    public static string PublicText()
    {
        return File.Exists(P("public.txt")) ? File.ReadAllText(P("public.txt")) : "No public.txt here, it gets written on first run.";
    }

    // only the {0x..} rows
    public static string PublicRows()
    {
        var rows = new List<string>();
        foreach (string line in PublicText().Split('\n')) if (line.StartsWith("{")) rows.Add(line.TrimEnd());
        return string.Join("\r\n", rows.ToArray());
    }

    // 0 good, 1 weak, 2 bad, -1 empty
    public static int Inspect(string machineCode, out string msg)
    {
        string t = Regex.Replace(machineCode, @"\s", "");
        if (t.Length == 0) { msg = "Waiting for the machine code..."; return -1; }
        byte[] c;
        try { c = Convert.FromBase64String(t); } catch (FormatException) { c = null; }
        if (c == null || c.Length != 96)
        {
            msg = "That is not a machine code. It should be the 128 characters ExampleShippedApp or MachineCodeTool shows.";
            return 2;
        }
        var have = new List<string>();
        var miss = new List<string>();
        for (int i = 0; i < 4; i++) (BitConverter.ToInt64(c, i * 8) != 0 ? have : miss).Add(Ids[i]);
        msg = have.Count + " of 4 IDs usable. Found: " + string.Join(", ", have.ToArray()) +
              (miss.Count > 0 ? ". Missing: " + string.Join(", ", miss.ToArray()) : "") +
              (have.Count >= 3 ? ". Strong, 3 of 4 have to match on their PC."
               : have.Count > 0 ? ". WEAK. Usually a VM or a PC that hides its hardware IDs. Try a real PC, or tick 'Issue anyway' and set an expiry."
               : ". Can't issue this one.");
        return have.Count >= 3 ? 0 : have.Count > 0 ? 1 : 2;
    }

    // <3 ids = weak, needs allowWeak + an expiry
    public static string Issue(string machineCode, long expires, bool allowWeak, out string note)
    {
        string why;
        if (Inspect(machineCode, out why) == 2) throw new Exception(why);
        byte[] code = Convert.FromBase64String(Regex.Replace(machineCode, @"\s", ""));
        if (!HasKey() || !File.Exists(P("asset.key"))) throw new Exception("signing key or asset.key missing");
        byte[] K = Convert.FromBase64String(File.ReadAllText(P("asset.key")));

        var payload = new byte[120];
        BitConverter.GetBytes(expires).CopyTo(payload, 0);
        Encoding.ASCII.GetBytes(Tag).CopyTo(payload, 8);
        Array.Copy(code, 0, payload, 16, 32);                        // 4 public hashes
        int slots = 0;
        for (int i = 0; i < 4; i++)
        {
            if (BitConverter.ToInt64(code, i * 8) == 0) continue;    // id unreadable, slot stays empty
            slots++;
            for (int j = 0; j < 16; j++) payload[48 + i * 16 + j] = (byte)(K[j] ^ code[32 + i * 16 + j]);
        }
        if (slots < 3)
        {
            if (!allowWeak) throw new Exception("Only " + slots + " of 4 IDs usable. Tick 'Issue anyway' to accept a weak binding.");
            if (expires == 0) throw new Exception("A weak binding needs an expiry date, not 'Never expires'.");
        }
        note = slots < 3 ? "Weak key issued: only " + slots + " of 4 IDs, so it is easier to fake and stops working if one of them changes." : null;
        Array.Copy(Sha(K), 0, payload, 112, 8);                      // lets the app check its key

        string key = Sign(payload);
        File.AppendAllText(P("issued.csv"), string.Format("{0:u},{1},{2},{3},{4}\r\n", DateTime.UtcNow, Tag, expires, slots, machineCode.Trim()));
        return key;
    }

    // test key: no pc binding, must expire, no app key
    public static string IssueTest(long expires)
    {
        if (expires == 0) throw new Exception("A test key needs an expiry date: untick 'Never expires'.");
        if (!HasKey()) throw new Exception("signing key missing");
        var payload = new byte[120];                                 // slots/wrapped/check stay empty
        BitConverter.GetBytes(expires).CopyTo(payload, 0);
        Encoding.ASCII.GetBytes(Tag).CopyTo(payload, 8);
        string key = Sign(payload);
        File.AppendAllText(P("issued.csv"), string.Format("{0:u},{1},{2},0,-\r\n", DateTime.UtcNow, Tag, expires));
        return key;
    }

    static string Sign(byte[] payload)
    {
        byte[] sig;
        using (var k = CngKey.Import(Convert.FromBase64String(File.ReadAllText(SignKeyPath())), CngKeyBlobFormat.EccPrivateBlob))
        using (var ec = new ECDsaCng(k) { HashAlgorithm = CngAlgorithm.Sha256 })
            sig = ec.SignData(payload);
        if (sig.Length != 64) throw new Exception("unexpected signature size");
        var all = new byte[184];
        payload.CopyTo(all, 0);
        sig.CopyTo(all, 120);
        return Convert.ToBase64String(all);
    }

    // last n log lines, newest 1st
    public static string Recent(int n)
    {
        if (!File.Exists(P("issued.csv"))) return "No licenses issued yet.";
        string[] lines = File.ReadAllLines(P("issued.csv"));
        var sb = new StringBuilder("Issued so far: " + lines.Length + "\r\n");
        for (int i = lines.Length - 1; i >= 0 && i >= lines.Length - n; i--)
        {
            try
            {
                string[] f = lines[i].Split(new[] { ',' }, 5);       // time,tag,expiry,ids,code
                long e = long.Parse(f[2]);
                string until = e == 0 ? "never expires" : "valid through " +
                    new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(e - 1).ToLocalTime().ToString("yyyy-MM-dd");
                string what = f[3] == "0" ? "TEST KEY, any PC"
                    : f[3] + "/4 IDs" + (int.Parse(f[3]) < 3 ? " WEAK" : "") + "  code " + f[4].Substring(0, Math.Min(10, f[4].Length)) + "...";
                sb.AppendLine(f[0] + "  " + f[1] + "  " + until + "  " + what);
            }
            catch (Exception) { sb.AppendLine("(unreadable line)"); }
        }
        return sb.ToString();
    }
}

// shows the public.txt rows
class PublicKeys : Form
{
    public PublicKeys()
    {
        Text = "Public keys for ExampleShippedApp.cpp";
        ClientSize = new Size(560, 300);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        var box = new TextBox
        {
            Left = 12, Top = 12, Width = 536, Height = 240, Multiline = true, ReadOnly = true,
            ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 8.5f), Text = Issuer.PublicText()
        };
        var copy = new Button { Text = "Copy rows", Left = 12, Top = 262, Width = 100 };
        copy.Click += (s, e) => { string r = Issuer.PublicRows(); if (r.Length > 0) Clipboard.SetText(r); };
        var close = new Button { Text = "Close", Left = 448, Top = 262, Width = 100, DialogResult = DialogResult.OK };
        AcceptButton = close;
        Controls.AddRange(new Control[] { box, copy, close });
        Shown += (s, e) => box.Select(0, 0);
    }
}

class Gui : Form
{
    static readonly Color[] Lvl = { Color.ForestGreen, Color.DarkOrange, Color.Firebrick };
    TextBox code, outp, recent;
    Label info, status;
    CheckBox never, weak;
    DateTimePicker date;

    public Gui()
    {
        Text = "PrivateOwnerApp - License Issuer";
        ClientSize = new Size(560, 604);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;

        var how = new Label
        {
            Left = 12, Top = 10, Width = 536, Height = 64, AutoSize = false,
            Text = "How it works\r\n1. The buyer runs ExampleShippedApp (or MachineCodeTool) and sends you the machine code.\r\n" +
                   "2. Paste it below, pick an expiry, hit Generate.\r\n3. Send them the key, or save it as license.key."
        };
        var l1 = new Label { Text = "Machine code from the buyer:", Left = 12, Top = 80, Width = 400 };
        code = new TextBox { Left = 12, Top = 100, Width = 536, Height = 62, Multiline = true };
        info = new Label { Left = 12, Top = 168, Width = 536, Height = 36, AutoSize = false, ForeColor = Color.Gray, Text = "Waiting for the machine code..." };
        code.TextChanged += (s, e) =>
        {
            string m;
            int lv = Issuer.Inspect(code.Text, out m);
            info.Text = m;
            info.ForeColor = lv < 0 ? Color.Gray : Lvl[lv];
            weak.Visible = lv == 1;                      // override only for weak
            weak.Checked = false;
        };
        var prod = new Label { Text = "Product: " + Issuer.Tag + " (ExampleShippedApp)", Left = 12, Top = 210, Width = 400 };
        never = new CheckBox { Text = "Never expires", Left = 12, Top = 234, Width = 110, Checked = true };
        date = new DateTimePicker { Left = 130, Top = 232, Width = 130, Format = DateTimePickerFormat.Short, Value = DateTime.Today.AddYears(1), Enabled = false };
        never.CheckedChanged += (s, e) => date.Enabled = !never.Checked;
        var lbl = new Label { Text = "(valid through the end of that day)", Left = 270, Top = 236, Width = 240 };
        var go = new Button { Text = "Generate key", Left = 12, Top = 266, Width = 120 };
        go.Click += Generate;
        weak = new CheckBox { Text = "Issue anyway (weak, needs expiry)", Left = 142, Top = 268, Width = 250, Visible = false, ForeColor = Color.DarkOrange };
        var test = new Button { Text = "Test key (any PC)", Left = 398, Top = 266, Width = 150 };
        test.Click += GenerateTest;
        outp =new TextBox { Left = 12, Top = 302, Width = 536, Height = 90, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical };
        var copy = new Button { Text = "Copy key", Left = 12, Top = 400, Width = 100 };
        copy.Click += (s, e) => { if (outp.Text.Length > 0) Clipboard.SetText(outp.Text); };
        var save = new Button { Text = "Save license.key...", Left = 120, Top = 400, Width = 130 };
        save.Click += Save;
        var log = new Button { Text = "Open issued.csv", Left = 258, Top = 400, Width = 110 };
        log.Click += (s, e) => { if (File.Exists(Issuer.P("issued.csv"))) Process.Start("notepad.exe", Issuer.P("issued.csv")); };
        var pub = new Button { Text = "Public keys...", Left = 376, Top = 400, Width = 110 };
        pub.Click += (s, e) => new PublicKeys().ShowDialog(this);
        status = new Label { Left = 12, Top = 434, Width = 536, Height = 34, AutoSize = false };
        var l2 = new Label { Text = "Recent licenses", Left = 12, Top = 474, Width = 300 };
        recent = new TextBox { Left = 12, Top = 494, Width = 536, Height = 100, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 8.5f) };
        Controls.AddRange(new Control[] { how, l1, code, info, prod, never, date, lbl, go, weak, test, outp, copy, save, log, pub, status, l2, recent });

        recent.Text = Issuer.Recent(8);
        Shown += (s, e) => EnsureKey();
    }

    void EnsureKey()
    {
        if (Issuer.HasKey()) return;
        var r = MessageBox.Show(
            "No signing keys here yet. Run the first-time setup (signing key, spare key, app key)?\n\nBack up everything it makes and keep the spare off this PC. If the keys get lost you can't issue licenses anymore.",
            "First run", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (r != DialogResult.Yes) { Close(); return; }
        try
        {
            status.Text = Issuer.NewKey();
            new PublicKeys().ShowDialog(this);
        }
        catch (Exception ex) { status.Text = "Error: " + ex.Message; }
    }

    void Generate(object s, EventArgs e)
    {
        try
        {
            long exp = never.Checked ? 0 : Issuer.Unix(date.Value.Date.AddDays(1).ToUniversalTime());
            string note;
            outp.Text = Issuer.Issue(code.Text, exp, weak.Checked, out note);
            status.Text = note ?? ("Key generated: " + Issuer.Tag + ", " + (never.Checked ? "never expires" : "expires " + date.Value.ToString("yyyy-MM-dd")) + ". Logged to issued.csv.");
            recent.Text = Issuer.Recent(8);
        }
        catch (Exception ex) { outp.Text = ""; status.Text = "Error: " + ex.Message; }
    }

    // no code needed, just expiry
    void GenerateTest(object s, EventArgs e)
    {
        try
        {
            long exp = never.Checked ? 0 : Issuer.Unix(date.Value.Date.AddDays(1).ToUniversalTime());
            outp.Text = Issuer.IssueTest(exp);
            status.Text = "Test key generated: works on any PC until " + date.Value.ToString("yyyy-MM-dd") + ". Logged to issued.csv.";
            recent.Text = Issuer.Recent(8);
        }
        catch (Exception ex) { outp.Text = ""; status.Text = "Error: " + ex.Message; }
    }

    void Save(object s, EventArgs e)
    {
        if (outp.Text.Length == 0) return;
        using (var d = new SaveFileDialog { FileName = "license.key", Filter = "License key|*.key" })
            if (d.ShowDialog() == DialogResult.OK) File.WriteAllText(d.FileName, outp.Text);
    }
}
