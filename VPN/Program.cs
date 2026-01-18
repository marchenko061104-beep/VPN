using System;
using System.Data;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using SharpPcap;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace VPN
{
    class Program
    {
        static TcpListener server = null;
        static TcpClient client = null;
        static bool isRunning = false;
        static string secretPassword = "VaPN123";



        static byte[] EncryptData(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] key = Encoding.UTF8.GetBytes(secretPassword);

            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return result;
        }//шифрирование


        static byte[] DecryptData(byte[] data)
        {
            return EncryptData(data);

        }//дешифрирование


        static void SetupVpnRouting(string vpnServerIp)
        {
            try
            {
                Console.WriteLine("\n🔧 Настраиваю маршрутизацию и DNS...");
                Console.WriteLine("🇩🇪 Устанавливаю DNS 9.9.9.9 (Франкфурт)...");

                Process.Start(new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "interface ip set dns name=\"Ethernet\" source=static addr=9.9.9.9",
                    Verb = "runas",
                    UseShellExecute = true,
                    CreateNoWindow = true
                });

                // МАРШРУТИЗАЦИЯ (оставляем как было)
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c route add 0.0.0.0 mask 0.0.0.0 {vpnServerIp}",
                    Verb = "runas",
                    UseShellExecute = true,
                    CreateNoWindow = true
                });

                Console.WriteLine("✅ DNS 9.9.9.9 установлен! Маршрутизация настроена!");
            }
            catch
            {
                Console.WriteLine("⚠️ Запусти программу от имени Администратора!");
            }
        }


        static async Task Main(string[] args)
        {
            string localIp = "127.0.0.1"; //франкфурт

            while (true)
            {
                Console.WriteLine("=== VPN (ТЕСТ на одном компьютере) ===");
                Console.WriteLine("1. Подключиться");
                Console.WriteLine("2. Отключиться");
                Console.Write("Выбор: ");
                var choice = Console.ReadLine();

                if (choice == "1" && !isRunning)
                {
                    //Л МАРШРУТИЗАЦИЮ 
                    SetupVpnRouting(localIp);

                    _ = Task.Run(async () => await RunServer());
                    _ = Task.Run(async () => await RunClient(localIp));

                    isRunning = true;

                    while (isRunning)
                    {
                        var disconnectChoice = Console.ReadLine();

                        if (disconnectChoice == "2")
                        {
                            Disconnect();
                            break;
                        }
                    }
                }
                else if (choice == "2" && isRunning)
                {
                    Disconnect();
                }
                else if (choice == "2" && !isRunning)
                {
                    Console.WriteLine("VPN не запущен");
                }
            }
        }

        static async Task RunServer()
        {
            server = new TcpListener(IPAddress.Any, 2222);
            server.Start();
            Console.WriteLine("Сервер: жду подключения...");

            TcpClient serverClient = await server.AcceptTcpClientAsync();
            Console.WriteLine("Сервер: клиент подключился!");

            NetworkStream stream = serverClient.GetStream();
            byte[] buffer = new byte[4096];

            while (isRunning)
            {
                try
                {
                    // Ждем данные от клиента
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0) break;

                    // Берем только полученные байты
                    byte[] receivedData = new byte[bytesRead];
                    Array.Copy(buffer, receivedData, bytesRead);

                    // ДЕШИФРУЕМ
                    byte[] decryptedData = DecryptData(receivedData);
                    string message = Encoding.UTF8.GetString(decryptedData);

                    Console.WriteLine($"Сервер получил: '{message}'");
                }
                catch
                {
                    break;
                }
            }
        }

        // 🔥 ПРОСТО ПОДКЛЮЧАЕМСЯ К localhost
        static async Task RunClient(string vpnServerIp)
        {
            client = new TcpClient();
            await client.ConnectAsync(vpnServerIp, 2222);
            Console.WriteLine("Клиент: подключился к серверу");

            NetworkStream stream = client.GetStream();
            byte[] buffer = new byte[4096];


            string[] testTraffic = {
                "Привет!",                    // 1. Просто текст
                "GET / HTTP/1.1",             // 2. HTTP запрос (как браузер)
                "user@mail.com:pass123",      // 3. Логин/пароль
                "8.8.8.8",                    // 4. DNS запрос
                "🎥 Видео поток"              // 5. Юникод (как медиа)
            };

            foreach (var data in testTraffic)
            {
                Console.WriteLine($"\nКлиент отправляет: '{data}'");

                //  ШИФРУЕМ данные
                byte[] encrypted = EncryptData(Encoding.UTF8.GetBytes(data));

                //  ОТПРАВЛЯЕМ зашифрованные данные
                await stream.WriteAsync(encrypted, 0, encrypted.Length);

                // ЖДЕМ ОТВЕТ от сервера

                if (stream.DataAvailable)
                {
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead > 0)
                    {
                        byte[] receivedData = new byte[bytesRead];
                        Array.Copy(buffer, receivedData, bytesRead);

                        // ДЕШИФРУЕМ ответ
                        byte[] decryptedData = DecryptData(receivedData);
                        string response = Encoding.UTF8.GetString(decryptedData);

                        Console.WriteLine($"Ответ сервера: '{response}'");
                    }
                }
                await Task.Delay(1000);
            }

            while (isRunning)
            {
                try
                {
                    // Клиент тоже может получать сообщения
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0) break;

                    byte[] receivedData = new byte[bytesRead];
                    Array.Copy(buffer, receivedData, bytesRead);

                    Console.WriteLine($"\nКлиент получил: {BitConverter.ToString(receivedData)}");

                    // Дешифруем
                    byte[] decryptedData = DecryptData(receivedData);
                    string message = Encoding.UTF8.GetString(decryptedData);

                    Console.WriteLine($"Сообщение: '{message}'");
                }
                catch
                {
                    break;
                }
            }
        }

        static void Disconnect()
        {
            isRunning = false;

            if (client != null)
            {
                client.Close();
                client = null;
            }

            if (server != null)
            {
                server.Stop();
                server = null;
            }

            Console.WriteLine("\n=== вы отключились ===");
        }
    }
}
