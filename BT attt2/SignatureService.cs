using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Bai2_RSA;

public static class SignatureService
{
    public static byte[] SignPkcs1(RSA rsa, byte[] data)
        => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    public static byte[] SignPss(RSA rsa, byte[] data)
        => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

    public static bool Verify(RSA rsa, byte[] data, byte[] sig, RSASignaturePadding pad)
        => rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, pad);

    // Phương pháp 2: băm ngẫu nhiên
    public static (byte[] Nonce, byte[] Signature) SignRandomizedHash(RSA rsa, byte[] data)
    {
        byte[] r = RandomNumberGenerator.GetBytes(32);
        return (r, SignPkcs1(rsa, Concat(r, data)));
    }

    public static bool VerifyRandomizedHash(RSA rsa, byte[] data, byte[] nonce, byte[] sig)
        => Verify(rsa, Concat(nonce, data), sig, RSASignaturePadding.Pkcs1);

    private static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0);
        b.CopyTo(r, a.Length);
        return r;
    }

    // Minh hoạ "chữ ký = RSA bằng khoá bí mật trên giá trị băm": tự tính S^e mod n rồi đối chiếu
    public static string ManualVerifyPkcs1(RSA rsa, byte[] data, byte[] sig)
    {
        RSAParameters p = rsa.ExportParameters(false);
        BigInteger n = new(p.Modulus!, true, true), e = new(p.Exponent!, true, true), s = new(sig, true, true);
        byte[] em = BigInteger.ModPow(s, e, n).ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] full = new byte[p.Modulus!.Length];
        em.CopyTo(full, full.Length - em.Length);                 // bù lại byte 00 đầu
        byte[] hash = SHA256.HashData(data);
        bool tail = full.AsSpan(full.Length - 32).SequenceEqual(hash);
        return $"S^e mod n (EM) = {Convert.ToHexString(full)[..40]}...\n" +
               $"  2 byte đầu = {Convert.ToHexString(full, 0, 2)} (00 01), 32 byte cuối == SHA256(dữ liệu): {tail}";
    }

    private static string Short(byte[] s)
    {
        string h = Convert.ToHexString(s);
        return $"{h[..24]}...{h[^8..]} ({s.Length} byte)";
    }

    // Thử nghiệm so sánh các phương pháp
    public static string Demo(RSA rsa, byte[] data, int times = 5)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Dữ liệu {data.Length} byte, SHA-256 = {HashService.Hex(SHA256.HashData(data))}\n");

        sb.AppendLine("--- (A) PKCS#1 v1.5: tất định ---");
        var setA = new HashSet<string>();
        byte[] lastA = Array.Empty<byte>();
        for (int i = 1; i <= times; i++)
        {
            lastA = SignPkcs1(rsa, data);
            setA.Add(Convert.ToBase64String(lastA));
            sb.AppendLine($"Lần {i}: {Short(lastA)}  verify={Verify(rsa, data, lastA, RSASignaturePadding.Pkcs1)}");
        }
        sb.AppendLine($"=> {setA.Count} chữ ký khác nhau / {times} lần ký");
        sb.AppendLine(ManualVerifyPkcs1(rsa, data, lastA) + "\n");

        sb.AppendLine("--- (B) RSASSA-PSS: ngẫu nhiên hoá bằng salt ---");
        var setB = new HashSet<string>();
        byte[] lastB = Array.Empty<byte>();
        for (int i = 1; i <= times; i++)
        {
            lastB = SignPss(rsa, data);
            setB.Add(Convert.ToBase64String(lastB));
            sb.AppendLine($"Lần {i}: {Short(lastB)}  verify={Verify(rsa, data, lastB, RSASignaturePadding.Pss)}");
        }
        sb.AppendLine($"=> {setB.Count} chữ ký khác nhau / {times} lần ký\n");

        sb.AppendLine("--- (C) Băm ngẫu nhiên: ký SHA256(r || M), gửi kèm r ---");
        var setC = new HashSet<string>();
        for (int i = 1; i <= times; i++)
        {
            var (r, sig) = SignRandomizedHash(rsa, data);
            setC.Add(Convert.ToBase64String(sig));
            sb.AppendLine($"Lần {i}: {Short(sig)}  verify={VerifyRandomizedHash(rsa, data, r, sig)}");
        }
        sb.AppendLine($"=> {setC.Count} chữ ký khác nhau / {times} lần ký\n");

        sb.AppendLine("--- (D) Kiểm tra phát hiện sửa đổi ---");
        byte[] tampered = (byte[])data.Clone();
        tampered[0] ^= 0x01;
        sb.AppendLine($"Sửa 1 bit dữ liệu, kiểm tra chữ ký PSS cũ: {Verify(rsa, tampered, lastB, RSASignaturePadding.Pss)} (kỳ vọng False)");
        sb.AppendLine($"Kiểm tra chữ ký PSS bằng padding PKCS#1: {Verify(rsa, data, lastB, RSASignaturePadding.Pkcs1)} (kỳ vọng False)");
        return sb.ToString();
    }
}