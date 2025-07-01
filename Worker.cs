using System.Net.Http;

public class Worker : BackgroundService
{
    private readonly IHttpClientFactory _clientFactory;

    public Worker(IHttpClientFactory clientFactory)
    {
        _clientFactory = clientFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var client = _clientFactory.CreateClient();
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var response = await client.GetStringAsync("http://localhost:3500/v1.0/invoke/webapi/method/hello");
                Console.WriteLine($"Got from WebAPI: {response}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error calling WebAPI: {ex.Message}");
            }

            await Task.Delay(5000, stoppingToken);
        }
    }
}
