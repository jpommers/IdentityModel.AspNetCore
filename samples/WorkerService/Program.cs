using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using System;
using IdentityModel.Client;
using Serilog.Sinks.SystemConsole.Themes;

namespace WorkerService
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                                .MinimumLevel.Debug()
                                .WriteTo.Console(theme: AnsiConsoleTheme.Code)
                                .CreateLogger();

            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args)
        {
            var host = Host.CreateDefaultBuilder(args)
                .UseSerilog()
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddAccessTokenManagement(options =>
                    {
                        options.Client.Clients.Add("identityserver", new PasswordTokenRequest
                        {
                            Address = "https://demo.identityserver.io/connect/token",
                            ClientId = "m2m.short",
                            ClientSecret = "secret",
                            Scope = "api",
                            UserName = "",
                            Password = ""
                        });
                    });

                    services.AddClientAccessTokenClient("client", configureClient: client =>
                    {
                        client.BaseAddress = new Uri("https://demo.identityserver.io/api/");
                    });

                    services.AddHostedService<Worker>();
                });

            return host;
        }
            
    }
}
