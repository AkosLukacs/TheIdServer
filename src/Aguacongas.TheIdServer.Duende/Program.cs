﻿// Project: Aguafrommars/TheIdServer
// Copyright (c) 2022 @Olivier Lefebvre
using Aguacongas.TheIdServer;
using Aguacongas.TheIdServer.BlazorApp.Models;
using Aguacongas.TheIdServer.Options.OpenTelemetry;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using System.Diagnostics;
using System.Linq;
using MutualTlsOptions = Aguacongas.TheIdServer.BlazorApp.Models.MutualTlsOptions;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((hostingContext, configuration) =>
                        configuration.ReadFrom.Configuration(hostingContext.Configuration));

var configuration = builder.Configuration;

var services = builder.Services;

services.AddTheIdServer(configuration);

var seed = args.Any(x => x == "/seed");
if (seed)
{
    args = args.Except(new[] { "/seed" }).ToArray();
}

services.AddOpenTelemetry(configuration.GetSection(nameof(OpenTelemetryOptions)));

var mutualTlsOptions = configuration.GetSection("IdentityServerOptions:MutualTls").Get<MutualTlsOptions>();
if (mutualTlsOptions?.Enabled == true && !seed)
{
    // when mutual TLS is enable the web host must receive client certificate
    builder.WebHost.ConfigureKestrel(kestrel =>
    {
        kestrel.ConfigureHttpsDefaults(https => https.ClientCertificateMode = ClientCertificateMode.DelayCertificate);
    });
}

var app = builder.Build();

if (seed)
{
    var config = app.Services.GetRequiredService<IConfiguration>();
    SeedData.EnsureSeedData(config, app.Services);
    return;
}

var activitySource = new ActivitySource("TheIdServer");

app.Use(async (context, next) =>
{
    using var activity = activitySource.StartActivity("Request");
    await next().ConfigureAwait(false);
});
app.UseTheIdServer(app.Environment, configuration);

app.Run();
