﻿using Aguacongas.IdentityServer.Store;
using Aguacongas.TheIdServer.BlazorApp.Services;
using Aguacongas.TheIdServer.IntegrationTest.BlazorApp;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;
using SettingsPage = Aguacongas.TheIdServer.BlazorApp.Pages.Settings.Settings;

namespace Aguacongas.TheIdServer.Duende.IntegrationTest.BlazorApp.Pages
{
    [Collection(BlazorAppCollection.Name)]
    public class SettingsTest : TestContext
    {
        public TheIdServerFactory Factory { get; }

        public SettingsTest(TheIdServerFactory factory)
        {
            Factory = factory;
        }

        [Fact]
        public async Task SaveButonClick_should_notify()
        {
            var component = CreateComponent("Alice Smith",
                SharedConstants.WRITERPOLICY);

            var form = component.WaitForElement("form");

            var notifier = Services.GetRequiredService<Notifier>();
            notifier.Show = n =>
            {
                Assert.NotNull(n);
                return Task.CompletedTask;
            };

            await form.SubmitAsync().ConfigureAwait(false);
        }

        private IRenderedComponent<SettingsPage> CreateComponent(string userName,
            string role)
        {
            Factory.ConfigureTestContext(userName,
               new Claim[]
               {
                    new Claim("scope", SharedConstants.ADMINSCOPE),
                    new Claim("role", SharedConstants.READERPOLICY),
                    new Claim("role", role),
                    new Claim("sub", Guid.NewGuid().ToString())
               },
               this);

            var component = RenderComponent<SettingsPage>();
            component.WaitForState(() => !component.Markup.Contains("Loading..."), TimeSpan.FromMinutes(1));
            return component;
        }
    }
}
