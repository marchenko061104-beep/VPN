using H.OpenVpn;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Data;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using TapTunHelperCsharp;

namespace VPN_s
{
    class Program
    {
        static TcpListener server = null;
        static TcpClient client = null;
        static bool isRunning = false;
        static string secretPassword = "VaPN123";
        static IntPtr tunHandle = IntPtr.Zero;

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
                Console.WriteLine("🇩🇪 Устанавливаю DNS 9.9.9.9 (Франкфурт)...");

                Process.Start(new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "interface ip set dns name=\"Ethernet\" source=static addr=9.9.9.9",
                    Verb = "runas",
                    UseShellExecute = true,
                    CreateNoWindow = true
                });

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
        }//маршрутизация

     
        static bool ConfigureTunAdapter()
        {
            try
            {
                Console.WriteLine("🔧 Настраиваю TUN адаптер...");
                Process.Start(new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "interface ip set address name=\"Ethernet\" static 10.8.0.1 255.255.255.0",
                    Verb = "runas",
                    UseShellExecute = true,
                    CreateNoWindow = true
                });

                Console.WriteLine("✅ TUN адаптер настроен с IP 10.8.0.1");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Ошибка настройки TUN: {ex.Message}");
                return false;
            }
        }//настройка адаптера



        static string AnalyzePacket(byte[] packet)
        {
            if (packet.Length < 20)
                return $"Маленький пакет: {packet.Length} байт";

            try
            {
                byte version = (byte)(packet[0] >> 4);
                byte ihl = (byte)(packet[0] & 0x0F);
                byte protocol = packet[9];

                string srcIp = $"{packet[12]}.{packet[13]}.{packet[14]}.{packet[15]}";
                string dstIp = $"{packet[16]}.{packet[17]}.{packet[18]}.{packet[19]}";

                string protocolName = protocol switch
                {
                    6 => "TCP",
                    17 => "UDP",
                    1 => "ICMP",
                    58 => "ICMPv6",
                    _ => $"Протокол {protocol}"
                };

                return $"{srcIp} → {dstIp} ({protocolName}): {packet.Length} байт";
            }
            catch
            {
                return $"Неизвестный пакет: {packet.Length} байт";
            }
        }//анализ пакета

        static async Task CaptureRealTraffic(NetworkStream vpnStream)
        {
            byte[] buffer = new byte[65535];
            Console.WriteLine("📡 Начинаю перехват трафика через TUN...");

            while (isRunning && tunHandle != IntPtr.Zero && client?.Connected == true)
            {
                try
                {
                    if (tunHandle == IntPtr.Zero || tunHandle.ToInt32() == -1)
                    {
                        Console.WriteLine("⚠️ TUN адаптер закрыт, останавливаю захват...");
                        break;
                    }
                    uint bytesRead = 0;
                    if (ReadFile(tunHandle, buffer, (uint)buffer.Length, out bytesRead, IntPtr.Zero))
                    {
                        if (bytesRead > 0)
                        {
                            byte[] packet = new byte[bytesRead];
                            Array.Copy(buffer, packet, bytesRead);
                            string packetInfo = AnalyzePacket(packet);
                            Console.WriteLine($"📦 {packetInfo}");
                            await SendToVpnServer(packet, vpnStream);
                        }
                        else
                        {
                            await Task.Delay(50);
                        }
                    }
                    else
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == 997) 
                        {
                            await Task.Delay(50);
                        }
                        else if (error != 0)
                        {
                            Console.WriteLine($" Ошибка чтения TUN (код {error})");
                            await Task.Delay(100);
                        }
                    }

                    await Task.Delay(10);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($" Ошибка захвата трафика: {ex.Message}");
                    await Task.Delay(100);
                }
            }

            Console.WriteLine("Захват трафика остановлен");
        }//перехват трафика

        static async Task SendToVpnServer(byte[] packet, NetworkStream stream)
        {
            try
            {
                byte[] encrypted = EncryptData(packet);
                await stream.WriteAsync(encrypted, 0, encrypted.Length);
            }
            catch { }
        }//отправка пакетов

        static async Task SendToTun(byte[] packet)
        {
            if (tunHandle == IntPtr.Zero || packet == null || packet.Length == 0)
                return;

            try
            {
                if (tunHandle.ToInt32() == -1)
                {
                    Console.WriteLine("TUN адаптер закрыт, не могу отправить пакет");
                    return;
                }
                uint bytesWritten = 0;
                if (WriteFile(tunHandle, packet, (uint)packet.Length, out bytesWritten, IntPtr.Zero))
                {
                    if (bytesWritten > 0)
                    {
                        if (packet.Length >= 20)
                        {
                            byte protocol = packet[9];
                            string protocolName = protocol switch
                            {
                                6 => "TCP",
                                17 => "UDP",
                                1 => "ICMP",
                                _ => $"Протокол {protocol}"
                            };
                            Console.WriteLine($"Получен {protocolName} пакет: {bytesWritten} байт");
                        }
                        else
                        {
                            Console.WriteLine($" Получено данных: {bytesWritten} байт");
                        }
                    }
                }
                else
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != 0)
                    {
                        Console.WriteLine($"Не удалось записать в TUN (ошибка {error})");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Ошибка отправки в TUN: {ex.Message}");
            }
        }//отправка в tun

        static async Task Main(string[] args)
        {
            string localIp = "127.0.0.1"; //франкфурт

            while (true)
            {
                Console.WriteLine("=== VPN (ТЕСТ на одном компьютере)ав120020 ===");
                Console.WriteLine("1. Подключиться выаываы");
                Console.WriteLine("2. Отключиться");
                Console.Write("Выбор: ");
                var choice = Console.ReadLine();

                if (choice == "1" && !isRunning)
                {
                    SetupVpnRouting(localIp); //маршрутизация
                    _ = Task.Run(async () => await RunServer());
                    await Task.Delay(1000);
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
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0) break;
                    byte[] receivedData = new byte[bytesRead];
                    Array.Copy(buffer, receivedData, bytesRead);
                    byte[] decryptedData = DecryptData(receivedData);
                    if (bytesRead > 100)
                    {
                        string packetInfo = AnalyzePacket(decryptedData);
                        Console.WriteLine($"Сервер получил: {packetInfo}");
                        await stream.WriteAsync(receivedData, 0, receivedData.Length);
                    }
                    else
                    {
                        string message = Encoding.UTF8.GetString(decryptedData);
                        Console.WriteLine($"Сервер получил: '{message}'");
                    }
                }
                catch
                {
                    break;
                }
            }
        }

        static async Task RunClient(string vpnServerIp)
        {
            client = new TcpClient();
            await client.ConnectAsync(vpnServerIp, 2222);
            Console.WriteLine("Успешное подключение к VPN");

            NetworkStream vpnStream = client.GetStream();
            byte[] buffer = new byte[65535];
            Task tunCaptureTask = Task.Run(() => CaptureRealTraffic(vpnStream));

            while (isRunning && client.Connected)
            {
                try
                {
                    if (vpnStream.DataAvailable)
                    {
                        int bytesRead = await vpnStream.ReadAsync(buffer, 0, buffer.Length);
                        if (bytesRead > 0)
                        {
                            byte[] receivedData = new byte[bytesRead];
                            Array.Copy(buffer, receivedData, bytesRead);
                            byte[] decryptedResponse = DecryptData(receivedData);
                            await SendToTun(decryptedResponse);
                        }
                    }
                    await Task.Delay(10);
                }
                catch (Exception ex)
                {
                    if (isRunning)
                    {
                        Console.WriteLine($" Ошибка приема: {ex.Message}");
                        break;
                    }
                }
            }
            await tunCaptureTask;
        }

        static void Disconnect()
        {
            isRunning = false;

            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "interface ip set dns name=\"Ethernet\" dhcp",
                    Verb = "runas",
                    UseShellExecute = true,
                    CreateNoWindow = true
                });
                Console.WriteLine(" DNS восстановлен на автоматический");
            }
            catch { }

            // Закрываем TUN если открыт
            if (tunHandle != IntPtr.Zero)
            {
                CloseHandle(tunHandle);
                tunHandle = IntPtr.Zero;
                Console.WriteLine(" TUN закрыт");
            }

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
            Console.WriteLine("fdgdfg");
            Console.WriteLine("\n=== вы отключились ===");
        }

        // =========== WINAPI ФУНКЦИИ ДЛЯ TUN ===========
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess,
            uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer,
            uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer,
            uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);
    }
}
