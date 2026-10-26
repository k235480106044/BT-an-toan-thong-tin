using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Bai2_RSA;

public static class RsaService
{
    // 1. Sinh cặp khoá
    public static RSA GenerateKeyPair(int bits = 2048) => RSA.Create(bits);

    // 2. Xuất PEM. pkcs1 = true: "RSA PUBLIC/PRIVATE KEY"; false: "PUBLIC KEY" (SPKI) / "PRIVATE KEY" (PKCS#8)
    public static string ExportPublicPem(RSA rsa, bool pkcs1)
        => pkcs1 ? rsa.ExportRSAPublicKeyPem() : rsa.ExportSubjectPublicKeyInfoPem();

    public static string ExportPrivatePem(RSA rsa, bool pkcs1)
        => pkcs1 ? rsa.ExportRSAPrivateKeyPem() : rsa.ExportPkcs8PrivateKeyPem();

    // 4. Nhập PEM (tự nhận diện 4 loại nhãn)
    public static RSA ImportPem(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    public static bool HasPrivateKey(RSA rsa)
    {
        try { rsa.ExportParameters(true); return true; }
        catch (CryptographicException) { return false; }
    }

    private static BigInteger Big(byte[]? b)
        => b == null ? BigInteger.Zero : new BigInteger(b, isUnsigned: true, isBigEndian: true);

    // 4. Hiển thị các thành phần của khoá: n, e (public); thêm d, p, q, dP, dQ, qInv (private)
    public static string Describe(RSA rsa)
    {
        bool priv = HasPrivateKey(rsa);
        RSAParameters p = rsa.ExportParameters(priv);
        var sb = new StringBuilder();
        sb.AppendLine(priv ? "=== KHOÁ BÍ MẬT (private key) ===" : "=== KHOÁ CÔNG KHAI (public key) ===");
        Line(sb, "n  (modulus)", p.Modulus);
        Line(sb, "e  (publicExponent)", p.Exponent);
        if (priv)
        {
            Line(sb, "d  (privateExponent)", p.D);
            Line(sb, "p  (prime1)", p.P);
            Line(sb, "q  (prime2)", p.Q);
            Line(sb, "dP = d mod (p-1)", p.DP);
            Line(sb, "dQ = d mod (q-1)", p.DQ);
            Line(sb, "qInv = q^-1 mod p", p.InverseQ);

            BigInteger n = Big(p.Modulus), e = Big(p.Exponent), d = Big(p.D), pp = Big(p.P), qq = Big(p.Q);
            BigInteger lambda = BigInteger.Abs((pp - 1) * (qq - 1)) / BigInteger.GreatestCommonDivisor(pp - 1, qq - 1);
            sb.AppendLine();
            sb.AppendLine("Kiểm tra toán học:");
            sb.AppendLine($"  p * q == n               : {pp * qq == n}");
            sb.AppendLine($"  e * d mod lcm(p-1,q-1)==1: {BigInteger.Remainder(e * d, lambda) == 1}");
        }
        return sb.ToString();
    }

    private static void Line(StringBuilder sb, string name, byte[]? v)
    {
        sb.AppendLine($"{name}: {v!.Length} byte, {Big(v).GetBitLength()} bit");
        sb.AppendLine("  hex: " + Convert.ToHexString(v));
        sb.AppendLine("  dec: " + Big(v));
    }

    // 5. Mã hoá bằng khoá công khai (OAEP-SHA256). Tối đa k - 2*32 - 2 byte (2048 bit => 190 byte)
    public static int MaxOaepBytes(RSA rsa) => rsa.KeySize / 8 - 2 * 32 - 2;

    public static byte[] Encrypt(RSA rsa, byte[] data)
    {
        int max = MaxOaepBytes(rsa);
        if (data.Length > max)
            throw new ArgumentException($"Dữ liệu {data.Length} byte vượt quá giới hạn {max} byte của OAEP-SHA256 với khoá {rsa.KeySize} bit.");
        return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    // 6. Giải mã bằng khoá bí mật
    public static byte[] Decrypt(RSA rsa, byte[] cipher)
        => rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);

    public static void SaveCipherBase64(string path, byte[] cipher) => File.WriteAllText(path, Convert.ToBase64String(cipher));
    public static byte[] LoadCipherBase64(string path) => Convert.FromBase64String(File.ReadAllText(path).Trim());
}