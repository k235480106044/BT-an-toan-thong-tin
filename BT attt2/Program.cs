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

    // =====================================================================
    // BÀI 2: RSA / SHA-256 / CHỮ KÝ SỐ
    // =====================================================================
    static void Bai2()
    {
        while (true)
        {
            Console.WriteLine("\n===== BÀI 2: RSA / SHA-256 / CHỮ KÝ SỐ =====");
            Console.WriteLine("1. Sinh cặp khoá + xuất public.pem, private.pem");
            Console.WriteLine("2. Xem cấu trúc byte của file PEM (ASN.1 DER)");
            Console.WriteLine("3. Nhập public.pem  (hiện n, e)");
            Console.WriteLine("4. Nhập private.pem (hiện n, e, d, p, q, ...)");
            Console.WriteLine("5. Mã hoá khoá AES 32 byte bằng public key đã nhập, lưu file Base64");
            Console.WriteLine("6. Giải mã: private.pem + file Base64, so sánh với nguồn");
            Console.WriteLine("7. Đo tốc độ khoá công khai / khoá bí mật");
            Console.WriteLine("8. SHA-256 và hiệu ứng thác đổ");
            Console.WriteLine("9. Chữ ký số: PKCS#1 / PSS / băm ngẫu nhiên");
            Console.WriteLine("0. Quay lại");
            string choice = Ask("Chọn: ");
            try
            {
                switch (choice)
                {
                    case "1":
                        {
                            int bits = int.TryParse(AskDef("Độ dài khoá (1024/2048/3072/4096) [2048]: ", "2048"), out var b) ? b : 2048;
                            bool pkcs1 = Ask("Dùng định dạng PKCS#1 (RSA PUBLIC/PRIVATE KEY)? (y/N): ").ToLower() == "y";
                            var sw = Stopwatch.StartNew();
                            keyPair = RsaService.GenerateKeyPair(bits);
                            keyPair.ExportParameters(true);
                            sw.Stop();
                            string pubPem = RsaService.ExportPublicPem(keyPair, pkcs1);
                            string privPem = RsaService.ExportPrivatePem(keyPair, pkcs1);
                            Console.WriteLine($"Đã sinh khoá {bits} bit trong {sw.ElapsedMilliseconds} ms\n");
                            Console.WriteLine(pubPem + "\n");
                            Console.WriteLine(privPem);
                            File.WriteAllText(AskDef("\nLưu public PEM tại [public.pem]: ", "public.pem"), pubPem + "\n");
                            File.WriteAllText(AskDef("Lưu private PEM tại [private.pem]: ", "private.pem"), privPem + "\n");
                            Console.WriteLine("Đã lưu 2 file PEM.");
                            break;
                        }
                    case "2":
                        {
                            string pem = File.ReadAllText(Ask("Đường dẫn file PEM: "));
                            Console.WriteLine(pem);
                            Console.WriteLine("=== PHÂN TÍCH TỪNG BYTE (ASN.1 DER) ===");
                            Console.WriteLine(Asn1Dumper.Dump(pem));
                            break;
                        }
                    case "3":
                        {
                            pub = RsaService.ImportPem(File.ReadAllText(Ask("Đường dẫn public.pem: ")));
                            Console.WriteLine(RsaService.Describe(pub));
                            break;
                        }
                    case "4":
                        {
                            priv = RsaService.ImportPem(File.ReadAllText(Ask("Đường dẫn private.pem: ")));
                            Console.WriteLine(RsaService.Describe(priv));
                            break;
                        }
                    case "5":
                        {
                            if (pub == null) throw new InvalidOperationException("Chưa nhập public.pem (chọn mục 3).");
                            string b64 = Ask("Dữ liệu Base64 (Enter = sinh khoá AES-256 ngẫu nhiên 32 byte): ");
                            byte[] data = b64.Length == 0 ? RandomNumberGenerator.GetBytes(32) : Convert.FromBase64String(b64);
                            lastPlain = data;
                            byte[] cipher = RsaService.Encrypt(pub, data);
                            Console.WriteLine($"Dữ liệu vào: {data.Length} byte (tối đa {RsaService.MaxOaepBytes(pub)} byte)");
                            Console.WriteLine($"Base64 dữ liệu: {Convert.ToBase64String(data)}");
                            Console.WriteLine($"Bản mã: {cipher.Length} byte\nBase64 bản mã:\n{Convert.ToBase64String(cipher)}");
                            RsaService.SaveCipherBase64(AskDef("Lưu bản mã tại [cipher.b64.txt]: ", "cipher.b64.txt"), cipher);
                            Console.WriteLine("Đã lưu.");
                            break;
                        }
                    case "6":
                        {
                            using RSA rsa = RsaService.ImportPem(File.ReadAllText(Ask("Đường dẫn private.pem: ")));
                            byte[] cipher = RsaService.LoadCipherBase64(AskDef("File bản mã Base64 [cipher.b64.txt]: ", "cipher.b64.txt"));
                            byte[] plain = RsaService.Decrypt(rsa, cipher);
                            Console.WriteLine($"Giải mã được {plain.Length} byte\nBase64: {Convert.ToBase64String(plain)}");
                            string src = Ask("Base64 dữ liệu nguồn để so sánh (Enter = dùng dữ liệu vừa mã hoá ở mục 5): ");
                            byte[]? source = src.Length > 0 ? Convert.FromBase64String(src) : lastPlain;
                            if (source == null) Console.WriteLine("Không có dữ liệu nguồn để so sánh.");
                            else Console.WriteLine("So sánh với nguồn: " + (plain.AsSpan().SequenceEqual(source) ? "GIỐNG HỆT" : "KHÁC NHAU"));
                            break;
                        }
                    case "7":
                        {
                            int it = int.TryParse(AskDef("Số lần lặp [200]: ", "200"), out var n) ? n : 200;
                            Console.WriteLine("Đang đo, khoá 4096 bit sinh khá lâu, vui lòng chờ...\n");
                            Console.WriteLine(BenchService.RunLibrary(new[] { 1024, 2048, 3072, 4096 }, it));
                            Console.WriteLine(BenchService.RunRaw(2048, it));
                            Console.WriteLine(BenchService.RunExponentSweep(2048, it));
                            break;
                        }
                    case "8":
                        {
                            Console.WriteLine("Nhập từng dòng văn bản, mỗi dòng được băm và so với dòng trước.");
                            Console.WriteLine("Gõ 'avalanche' để chạy thí nghiệm 1000 lần, để trống để quay lại.");
                            byte[]? prev = null;
                            while (true)
                            {
                                string text = Console.ReadLine() ?? "";
                                if (text.Length == 0) break;
                                if (text == "avalanche") { Console.WriteLine(HashService.Avalanche(1000)); continue; }
                                byte[] h = HashService.Sha256(text);
                                string hex = HashService.Hex(h);
                                Console.WriteLine($"SHA-256 mới : {hex}");
                                if (prev != null)
                                {
                                    string ph = HashService.Hex(prev);
                                    int d = HashService.DiffBits(prev, h);
                                    Console.WriteLine($"SHA-256 cũ  : {ph}");
                                    Console.WriteLine($"Khác nhau   : {HashService.DiffMarks(ph, hex)}");
                                    Console.WriteLine($"Số bit khác : {d}/256 ({d / 2.56:F1}%)");
                                }
                                prev = h;
                            }
                            break;
                        }
                    case "9":
                        {
                            RSA rsa = priv ?? keyPair ?? throw new InvalidOperationException("Chưa có khoá bí mật. Chọn mục 1 hoặc 4.");
                            string text = AskDef("Dữ liệu cần ký [Hop dong so 01/2026]: ", "Hop dong so 01/2026");
                            Console.WriteLine(SignatureService.Demo(rsa, Encoding.UTF8.GetBytes(text), 5));
                            break;
                        }
                    case "0":
                        return;
                }
            }
            catch (Exception ex) { Console.WriteLine("Lỗi: " + ex.Message); }
        }
    }
}