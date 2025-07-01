var builder = Host.CreateDefaultBuilder(args)
    .ConfigureServices(services =>
    {
        services.AddHttpClient();
        services.AddHostedService<Worker>();
    });

builder.Build().Run();
