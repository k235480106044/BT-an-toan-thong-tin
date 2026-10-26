using System.Security.Cryptography;
using System.Text;

namespace Bai1_AES;

public static class AesService
{
    private const int BufferSize = 1024 * 1024; // 1 MB
    private const int IvSize = 16;

    // 1. Sinh khoá
    public static byte[] GenerateKey(int keyBits = 256)
    {
        if (keyBits is not (128 or 192 or 256))
            throw new ArgumentException("Độ dài khoá AES phải là 128, 192 hoặc 256 bit.");
        return RandomNumberGenerator.GetBytes(keyBits / 8);
    }

    // 2. Lưu khoá (Base64)
    public static void SaveKey(string path, byte[] key)
        => File.WriteAllText(path, Convert.ToBase64String(key));

    // 3. Nạp khoá
    public static byte[] LoadKey(string path)
    {
        byte[] key = Convert.FromBase64String(File.ReadAllText(path).Trim());
        if (key.Length is not (16 or 24 or 32))
            throw new InvalidDataException($"Khoá không hợp lệ: {key.Length} byte (cần 16/24/32).");
        return key;
    }

    // 4. Mã hoá / giải mã văn bản
    public static string EncryptText(string plainText, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        byte[] cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(plainText), aes.IV, PaddingMode.PKCS7);
        byte[] all = new byte[IvSize + cipher.Length];
        aes.IV.CopyTo(all, 0);
        cipher.CopyTo(all, IvSize);
        return Convert.ToBase64String(all);
    }

    public static string DecryptText(string base64, byte[] key)
    {
        byte[] all = Convert.FromBase64String(base64.Trim());
        if (all.Length < IvSize + 16) throw new InvalidDataException("Dữ liệu mã hoá quá ngắn.");
        using var aes = Aes.Create();
        aes.Key = key;
        byte[] plain = aes.DecryptCbc(all.AsSpan(IvSize), all.AsSpan(0, IvSize), PaddingMode.PKCS7);
        return Encoding.UTF8.GetString(plain);
    }

    // 5. Mã hoá / giải mã file theo luồng (hỗ trợ file hàng GB)
    public static void EncryptFile(string src, string dst, byte[] key, Action<int>? progress = null)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();

        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan);
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize, FileOptions.SequentialScan);
        fout.Write(aes.IV, 0, IvSize);
        using var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write);
        Copy(fin, cs, fin.Length, progress);
        cs.FlushFinalBlock();
    }

    public static void DecryptFile(string src, string dst, byte[] key, Action<int>? progress = null)
    {
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan);
        byte[] iv = new byte[IvSize];
        fin.ReadExactly(iv);

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize, FileOptions.SequentialScan);
        using var cs = new CryptoStream(fin, aes.CreateDecryptor(), CryptoStreamMode.Read);
        Copy(cs, fout, fin.Length, progress);
    }

    private static void Copy(Stream input, Stream output, long total, Action<int>? progress)
    {
        byte[] buffer = new byte[BufferSize];
        long done = 0;
        int read, last = -1;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            output.Write(buffer, 0, read);
            done += read;
            if (progress != null && total > 0)
            {
                int pct = (int)Math.Min(100, done * 100 / total);
                if (pct != last) { last = pct; progress(pct); }
            }
        }
    }

    // 6. So sánh từng byte hai file. Trả về (giống nhau?, vị trí byte khác đầu tiên hoặc -1)
    public static (bool Equal, long FirstDiff) CompareFiles(string a, string b)
    {
        using var fa = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan);
        using var fb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan);
        if (fa.Length != fb.Length) return (false, Math.Min(fa.Length, fb.Length));

        byte[] ba = new byte[BufferSize], bb = new byte[BufferSize];
        long pos = 0;
        while (true)
        {
            int ra = fa.ReadAtLeast(ba, ba.Length, throwOnEndOfStream: false);
            int rb = fb.ReadAtLeast(bb, bb.Length, throwOnEndOfStream: false);
            if (ra != rb) return (false, pos);
            if (ra == 0) return (true, -1);
            var sa = ba.AsSpan(0, ra);
            var sb = bb.AsSpan(0, ra);
            if (!sa.SequenceEqual(sb)) return (false, pos + sa.CommonPrefixLength(sb));
            pos += ra;
        }
    }

    // Tạo file ngẫu nhiên kích thước tuỳ ý để thử nghiệm
    public static void CreateTestFile(string path, long sizeBytes)
    {
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize, FileOptions.SequentialScan);
        byte[] buf = new byte[BufferSize];
        long left = sizeBytes;
        while (left > 0)
        {
            Random.Shared.NextBytes(buf);
            int n = (int)Math.Min(buf.Length, left);
            fs.Write(buf, 0, n);
            left -= n;
        }
    }
}