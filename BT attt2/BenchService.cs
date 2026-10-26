using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Bai2_RSA;

public static class BenchService
{
    private static BigInteger B(byte[]? v)
        => new BigInteger(v!, isUnsigned: true, isBigEndian: true);

    // A. RSA của .NET: OAEP-SHA256, giải mã dùng CRT
    public static string RunLibrary(int[] keySizes, int iterations)
    {
        var sb = new StringBuilder();
        sb.AppendLine("A. RSA của .NET (OAEP-SHA256, bản rõ 32 byte, giải mã dùng CRT)");
        sb.AppendLine($"Số lần lặp: {iterations}\n");
        sb.AppendLine("| Khoá (bit) | Sinh khoá (ms) | Mã hoá / lần (ms) | Giải mã / lần (ms) | Giải mã chậm hơn |");
        sb.AppendLine("|---|---|---|---|---|");
        byte[] data = RandomNumberGenerator.GetBytes(32);

        foreach (int bits in keySizes)
        {
            var sw = Stopwatch.StartNew();
            using var rsa = RSA.Create(bits);
            rsa.ExportParameters(true);                 // ép sinh khoá ngay để đo
            double tGen = sw.Elapsed.TotalMilliseconds;

            byte[] c = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            rsa.Decrypt(c, RSAEncryptionPadding.OaepSHA256);   // khởi động (warm-up)

            sw.Restart();
            for (int i = 0; i < iterations; i++) c = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            double tEnc = sw.Elapsed.TotalMilliseconds / iterations;

            sw.Restart();
            for (int i = 0; i < iterations; i++) rsa.Decrypt(c, RSAEncryptionPadding.OaepSHA256);
            double tDec = sw.Elapsed.TotalMilliseconds / iterations;

            sb.AppendLine($"| {bits} | {tGen:F1} | {tEnc:F4} | {tDec:F4} | {tDec / tEnc:F1} lần |");
        }
        return sb.ToString();
    }

    // B. Phép toán thô bằng BigInteger: tách riêng ảnh hưởng của số mũ e và d
    public static string RunRaw(int bits, int iterations)
    {
        using var rsa = RSA.Create(bits);
        RSAParameters p = rsa.ExportParameters(true);
        BigInteger n = B(p.Modulus), e = B(p.Exponent), d = B(p.D);
        BigInteger P = B(p.P), Q = B(p.Q), dP = B(p.DP), dQ = B(p.DQ), qInv = B(p.InverseQ);
        BigInteger m = new BigInteger(RandomNumberGenerator.GetBytes(bits / 8 - 2), true, true); // m < n
        int itPriv = Math.Max(3, iterations / 20);

        BigInteger c = BigInteger.ModPow(m, e, n);   // warm-up
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++) c = BigInteger.ModPow(m, e, n);
        double tPub = sw.Elapsed.TotalMilliseconds / iterations;

        sw.Restart();
        BigInteger back = 0;
        for (int i = 0; i < itPriv; i++) back = BigInteger.ModPow(c, d, n);
        double tPriv = sw.Elapsed.TotalMilliseconds / itPriv;

        sw.Restart();
        BigInteger back2 = 0;
        for (int i = 0; i < itPriv; i++)
        {
            BigInteger m1 = BigInteger.ModPow(c % P, dP, P);
            BigInteger m2 = BigInteger.ModPow(c % Q, dQ, Q);
            BigInteger h = ((qInv * (m1 - m2)) % P + P) % P;
            back2 = m2 + h * Q;
        }
        double tCrt = sw.Elapsed.TotalMilliseconds / itPriv;

        var sb = new StringBuilder();
        sb.AppendLine($"B. BigInteger.ModPow thô, modulus {bits} bit");
        sb.AppendLine($"Kiểm tra đúng đắn: m^e^d == m ? {back == m}; CRT == m ? {back2 == m}\n");
        sb.AppendLine("| Phép toán | Độ dài số mũ (bit) | Số lần lặp | Thời gian / lần (ms) | So với mã hoá |");
        sb.AppendLine("|---|---|---|---|---|");
        sb.AppendLine($"| Khoá công khai: m^e mod n | {e.GetBitLength()} | {iterations} | {tPub:F4} | 1,0 |");
        sb.AppendLine($"| Khoá bí mật: c^d mod n | {d.GetBitLength()} | {itPriv} | {tPriv:F4} | {tPriv / tPub:F1} lần |");
        sb.AppendLine($"| Khoá bí mật có CRT | {dP.GetBitLength()} (x2) | {itPriv} | {tCrt:F4} | {tCrt / tPub:F1} lần |");
        return sb.ToString();
    }

    // C. Thời gian luỹ thừa phụ thuộc độ dài số mũ (không cần số mũ là khoá hợp lệ)
    public static string RunExponentSweep(int bits, int iterations)
    {
        using var rsa = RSA.Create(bits);
        BigInteger n = B(rsa.ExportParameters(false).Modulus);
        BigInteger m = new BigInteger(RandomNumberGenerator.GetBytes(bits / 8 - 2), true, true);

        var sb = new StringBuilder();
        sb.AppendLine($"C. Ảnh hưởng độ dài số mũ, modulus {bits} bit\n");
        sb.AppendLine("| Độ dài số mũ (bit) | Thời gian / lần (ms) | Tỉ lệ so với số mũ 17 bit |");
        sb.AppendLine("|---|---|---|");
        double? baseT = null;
        foreach (int expBits in new[] { 2, 17, 64, 256, 1024, bits })
        {
            byte[] eb = RandomNumberGenerator.GetBytes((expBits + 7) / 8);
            BigInteger x = (new BigInteger(eb, true, true) & ((BigInteger.One << expBits) - 1)) | (BigInteger.One << (expBits - 1));   // ép đủ expBits bit
            if (expBits > 1) x |= 1;
            int it = expBits <= 64 ? iterations : Math.Max(3, iterations / 20);
            BigInteger.ModPow(m, x, n);
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < it; i++) BigInteger.ModPow(m, x, n);
            double t = sw.Elapsed.TotalMilliseconds / it;
            if (expBits == 17) baseT = t;
            sb.AppendLine($"| {expBits} | {t:F4} | {(baseT.HasValue ? (t / baseT.Value).ToString("F1") + " lần" : "-")} |");
        }
        return sb.ToString();
    }
}