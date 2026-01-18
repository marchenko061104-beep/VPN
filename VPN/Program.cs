using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace VPN
{
    class Program
    {
        static TcpListener server = null;
        static TcpClient client = null;
        static bool isRunning = false;

        static async Task Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine("=== VPN ===");
                Console.WriteLine("1. Подключиться");
                Console.WriteLine("2. Отключиться");
                Console.Write("Выбор: ");
                var choice = Console.ReadLine();

                if (choice == "1" && !isRunning)
                {
                    _ = Task.Run(async () => await RunServer());
                    _ = Task.Run(async () => await RunClient());

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
            server = new TcpListener(IPAddress.Any, 5555);
            server.Start();  
            Console.WriteLine("Сервер: запущен, порт 5555");

            //  ЖДЕМ подключения клиента 
            TcpClient serverClient = await server.AcceptTcpClientAsync();
            Console.WriteLine("Сервер: клиент подключился");

            //  Открываем поток для обмена данными
            NetworkStream stream = serverClient.GetStream();
            byte[] buffer = new byte[1024];

            while (isRunning)
            {
                try
                {
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0) break;  
                }
                catch
                {
                    break;
                }
            }

            serverClient.Close();
            server.Stop();
        }

        static async Task RunClient()
        {
            client = new TcpClient();
            await client.ConnectAsync("127.0.0.1", 5555);
            Console.WriteLine("Клиент: подключился к серверу");

            // поток для обмена данными
            NetworkStream stream = client.GetStream();
            byte[] buffer = new byte[1024];

            // ждем данные от сервера
            while (isRunning)  
            {
                try
                {
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0) break;
                }
                catch
                {
                    break;
                }
            }
            client.Close();
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