using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Bai1_AES;
using Bai2_RSA;

internal static class Program
{
    static byte[]? aesKey;
    static RSA? keyPair, pub, priv;
    static byte[]? lastPlain;

    static string Ask(string prompt)
    {
        Console.Write(prompt);
        return (Console.ReadLine() ?? "").Trim().Trim('"');
    }

    static string AskDef(string prompt, string def)
    {
        string s = Ask(prompt);
        return s.Length == 0 ? def : s;
    }

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;

        while (true)
        {
            Console.WriteLine("\n================ CHƯƠNG TRÌNH BÀI TẬP AN TOÀN VÀ BẢO MẬT THÔNG TIN ================");
            Console.WriteLine("1. Bài 1: Mã hoá AES (sinh khoá, mã hoá văn bản/file, đo tốc độ file lớn)");
            Console.WriteLine("2. Bài 2: Mã hoá RSA, PEM, SHA-256 và chữ ký số");
            Console.WriteLine("0. Thoát");
            switch (Ask("Lựa chọn của bạn (1/2/0): "))
            {
                case "1": Bai1(); break;
                case "2": Bai2(); break;
                case "0": return;
            }
        }
    }

    // =====================================================================
    // BÀI 1: AES
    // =====================================================================
    static byte[] RequireKey() => aesKey ?? throw new InvalidOperationException("Chưa có khoá. Hãy chọn 1 hoặc 3 trước.");

    static void Bai1()
    {
        while (true)
        {
            Console.WriteLine("\n===== BÀI 1: AES =====");
            Console.WriteLine("1. Sinh khoá AES        2. Lưu khoá ra file     3. Nạp khoá từ file");
            Console.WriteLine("4. Mã hoá văn bản       5. Giải mã văn bản");
            Console.WriteLine("6. Mã hoá file          7. Giải mã file");
            Console.WriteLine("8. Benchmark file lớn   0. Quay lại");
            string choice = Ask("Chọn: ");
            try
            {
                switch (choice)
                {
                    case "1":
                        {
                            int bits = int.TryParse(Ask("Độ dài khoá (128/192/256) [256]: "), out var b) ? b : 256;
                            aesKey = AesService.GenerateKey(bits);
                            Console.WriteLine($"Đã sinh khoá {bits} bit. Base64: {Convert.ToBase64String(aesKey)}");
                            break;
                        }
                    case "2":
                        AesService.SaveKey(Ask("Đường dẫn file khoá (vd: aes.key): "), RequireKey());
                        Console.WriteLine("Đã lưu khoá.");
                        break;
                    case "3":
                        aesKey = AesService.LoadKey(Ask("Đường dẫn file khoá: "));
                        Console.WriteLine($"Đã nạp khoá {aesKey.Length * 8} bit.");
                        break;
                    case "4":
                        Console.WriteLine("Bản mã (Base64):\n" + AesService.EncryptText(Ask("Nhập văn bản: "), RequireKey()));
                        break;
                    case "5":
                        Console.WriteLine("Bản rõ:\n" + AesService.DecryptText(Ask("Dán chuỗi Base64: "), RequireKey()));
                        break;
                    case "6": RunFile(true); break;
                    case "7": RunFile(false); break;
                    case "8": Benchmark(); break;
                    case "0": return;
                }
            }
            catch (Exception ex) { Console.WriteLine("Lỗi: " + ex.Message); }
        }
    }

    static void RunFile(bool encrypt)
    {
        string src = Ask("File nguồn: ");
        string dst = Ask("File đích: ");
        var sw = Stopwatch.StartNew();
        Action<int> p = pct => Console.Write($"\r  Tiến độ: {pct}%   ");
        if (encrypt) AesService.EncryptFile(src, dst, RequireKey(), p);
        else AesService.DecryptFile(src, dst, RequireKey(), p);
        sw.Stop();
        Console.WriteLine($"\nHoàn tất sau {sw.Elapsed.TotalSeconds:F2} giây.");
    }

    static void Benchmark()
    {
        var k = RequireKey();
        string dir = Ask("Thư mục chứa file thử nghiệm (cần đủ chỗ trống ~3 lần file lớn nhất): ");
        Directory.CreateDirectory(dir);
        string list = Ask("Các kích thước thử, đơn vị MB, cách nhau dấu phẩy [100,500,1024,2048,4096]: ");
        var sizes = (string.IsNullOrWhiteSpace(list) ? "100,500,1024,2048,4096" : list)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(long.Parse).ToArray();

        Console.WriteLine($"\nKhoá AES-{k.Length * 8}, CBC/PKCS7, bộ đệm 1 MB, CPU: {Environment.ProcessorCount} luồng");
        Console.WriteLine("| Kích thước (MB) | T mã hoá (s) | MB/s MH | T giải mã (s) | MB/s GM | Kích thước .enc (byte) | So sánh byte | Byte lệch đầu tiên |");
        Console.WriteLine("|---|---|---|---|---|---|---|---|");

        foreach (long mb in sizes)
        {
            string src = Path.Combine(dir, $"src_{mb}MB.bin");
            string enc = Path.Combine(dir, $"src_{mb}MB.enc");
            string dec = Path.Combine(dir, $"src_{mb}MB.dec");
            AesService.CreateTestFile(src, mb * 1024 * 1024);

            var sw = Stopwatch.StartNew();
            AesService.EncryptFile(src, enc, k);
            double tEnc = sw.Elapsed.TotalSeconds;

            sw.Restart();
            AesService.DecryptFile(enc, dec, k);
            double tDec = sw.Elapsed.TotalSeconds;

            var (equal, diff) = AesService.CompareFiles(src, dec);
            long encSize = new FileInfo(enc).Length;
            Console.WriteLine($"| {mb} | {tEnc:F2} | {mb / tEnc:F1} | {tDec:F2} | {mb / tDec:F1} | {encSize:N0} | {(equal ? "GIỐNG HỆT" : "KHÁC")} | {diff} |");

            foreach (var f in new[] { src, enc, dec }) File.Delete(f);
        }
        Console.WriteLine("\nCopy bảng trên vào báo cáo (mục 1.5).");
    }
