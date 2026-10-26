using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Bai2_RSA;

public static class HashService
{
    public static byte[] Sha256(string text) => SHA256.HashData(Encoding.UTF8.GetBytes(text));
    public static string Hex(byte[] h) => Convert.ToHexString(h).ToLowerInvariant();

    // Số bit khác nhau (khoảng cách Hamming) giữa hai giá trị băm
    public static int DiffBits(byte[] a, byte[] b)
    {
        int c = 0;
        for (int i = 0; i < a.Length; i++) c += BitOperations.PopCount((uint)(a[i] ^ b[i]));
        return c;
    }

    // Dòng đánh dấu những ký tự hex khác nhau
    public static string DiffMarks(string h1, string h2)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < h1.Length; i++) sb.Append(h1[i] == h2[i] ? ' ' : '^');
        return sb.ToString();
    }

    // Thí nghiệm: lật ngẫu nhiên 1 bit của thông điệp 64 byte, lặp 'trials' lần
    public static string Avalanche(int trials)
    {
        var diffs = new List<int>(trials);
        for (int t = 0; t < trials; t++)
        {
            byte[] msg = RandomNumberGenerator.GetBytes(64);
            byte[] h1 = SHA256.HashData(msg);
            int bit = RandomNumberGenerator.GetInt32(msg.Length * 8);
            msg[bit / 8] ^= (byte)(1 << (bit % 8));
            diffs.Add(DiffBits(h1, SHA256.HashData(msg)));
        }
        double mean = diffs.Average();
        double sd = Math.Sqrt(diffs.Sum(x => (x - mean) * (x - mean)) / diffs.Count);
        return $"Thí nghiệm {trials} lần, mỗi lần đổi đúng 1 bit đầu vào:\n" +
               $"  Số bit đầu ra thay đổi: trung bình {mean:F2}/256 ({mean / 2.56:F2}%), " +
               $"độ lệch chuẩn {sd:F2}, nhỏ nhất {diffs.Min()}, lớn nhất {diffs.Max()}\n" +
               $"  Lý thuyết (mỗi bit đầu ra đổi với xác suất 1/2): trung bình 128, độ lệch chuẩn 8.";
    }
}