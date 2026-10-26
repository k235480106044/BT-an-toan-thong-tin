using System.Numerics;
using System.Text;

namespace Bai2_RSA;

public static class Asn1Dumper
{
    private record Node(int Start, int HeaderLen, int ContentStart, int Len, byte Tag);

    private static readonly string[] PrivNames =
    {
        "version (0)", "n  (modulus)", "e  (publicExponent)", "d  (privateExponent)",
        "p  (prime1)", "q  (prime2)", "dP = d mod (p-1)", "dQ = d mod (q-1)", "qInv = q^-1 mod p"
    };

    public static byte[] PemToDer(string pem, out string label)
    {
        label = "";
        var b64 = new StringBuilder();
        foreach (string raw in pem.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith("-----BEGIN")) { label = line.Trim('-').Replace("BEGIN ", "").Trim(); continue; }
            if (line.StartsWith("-----")) continue;
            b64.Append(line);
        }
        return Convert.FromBase64String(b64.ToString());
    }

    public static string Dump(string pem)
    {
        var sb = new StringBuilder();
        try
        {
            byte[] der = PemToDer(pem, out string label);
            sb.AppendLine($"Nhãn PEM          : {label}");
            sb.AppendLine($"Số ký tự Base64    : {pem.Count(char.IsLetterOrDigit)} (xấp xỉ), sau giải mã: {der.Length} byte DER");
            sb.AppendLine("Quy ước dòng       : @offset [byte Tag + byte Length] kiểu = ý nghĩa\n");
            Walk(der, 0, der.Length, 0, sb);
        }
        catch (Exception ex) { sb.AppendLine("Không phân tích được PEM: " + ex.Message); }
        return sb.ToString();
    }

    private static List<Node> ReadChildren(byte[] d, int pos, int end)
    {
        var list = new List<Node>();
        while (pos < end)
        {
            int start = pos;
            byte tag = d[pos++];
            int len = d[pos++];
            if ((len & 0x80) != 0)
            {
                int n = len & 0x7F;
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | d[pos++];
            }
            list.Add(new Node(start, pos - start, pos, len, tag));
            pos += len;
        }
        return list;
    }

    private static void Walk(byte[] d, int pos, int end, int depth, StringBuilder sb)
    {
        var kids = ReadChildren(d, pos, end);
        int intCount = kids.Count(k => k.Tag == 0x02);
        string[]? names = intCount == 9 ? PrivNames
                        : intCount == 2 ? new[] { "n  (modulus)", "e  (publicExponent)" }
                        : null;
        int intIdx = 0;
        string ind = new string(' ', depth * 2);

        foreach (var k in kids)
        {
            string hdr = BitConverter.ToString(d, k.Start, k.HeaderLen).Replace('-', ' ');
            string label = "";
            if (k.Tag == 0x02 && names != null && intIdx < names.Length) label = " = " + names[intIdx++];
            sb.AppendLine($"{ind}@{k.Start,-4} [{hdr}] {TagName(k.Tag)}{label}, nội dung {k.Len} byte");

            if ((k.Tag & 0x20) != 0)
            {
                Walk(d, k.ContentStart, k.ContentStart + k.Len, depth + 1, sb);
            }
            else if (k.Tag == 0x02)
            {
                sb.AppendLine($"{ind}    giá trị: {Preview(d, k.ContentStart, k.Len)}");
            }
            else if (k.Tag == 0x06)
            {
                sb.AppendLine($"{ind}    OID: {DecodeOid(d, k.ContentStart, k.Len)}");
            }
            else if (k.Tag == 0x03 || k.Tag == 0x04)
            {
                int off = k.Tag == 0x03 ? 1 : 0; // BIT STRING: byte đầu là số bit đệm
                if (k.Len > off && d[k.ContentStart + off] == 0x30)
                {
                    sb.AppendLine($"{ind}    (bên trong là một SEQUENCE DER lồng nhau)");
                    Walk(d, k.ContentStart + off, k.ContentStart + k.Len, depth + 1, sb);
                }
            }
        }
    }

    private static string TagName(byte t) => t switch
    {
        0x02 => "INTEGER",
        0x03 => "BIT STRING",
        0x04 => "OCTET STRING",
        0x05 => "NULL",
        0x06 => "OBJECT IDENTIFIER",
        0x30 => "SEQUENCE",
        0x31 => "SET",
        _ => $"TAG 0x{t:X2}"
    };

    private static string Preview(byte[] d, int s, int n)
    {
        string hex = Convert.ToHexString(d, s, Math.Min(n, 12));
        string more = n > 12 ? $"... (tổng {n} byte)" : "";
        string dec = n <= 4 ? "  = " + new BigInteger(d.AsSpan(s, n), true, true) : "";
        string lead = n > 1 && d[s] == 0x00 ? "  [byte 00 đầu: giữ cho số nguyên dương]" : "";
        return hex + more + dec + lead;
    }

    private static string DecodeOid(byte[] d, int s, int n)
    {
        var parts = new List<string> { (d[s] / 40).ToString(), (d[s] % 40).ToString() };
        long v = 0;
        for (int i = 1; i < n; i++)
        {
            v = (v << 7) | (long)(d[s + i] & 0x7F);
            if ((d[s + i] & 0x80) == 0) { parts.Add(v.ToString()); v = 0; }
        }
        string oid = string.Join('.', parts);
        return oid == "1.2.840.113549.1.1.1" ? oid + " (rsaEncryption)" : oid;
    }
}